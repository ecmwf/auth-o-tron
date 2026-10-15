-- Atomic refresh-token family operations on one primary. KEYS[1] is the presented or
-- issued token key, except where an operation names another key; family, per-user
-- index and other token keys derive from the fixed prefix. A token key expires at the family idle deadline when it was issued or
-- rotated, and a family keeps at most ARGV[10] rotated hashes ("history", oldest first).
-- A coupled family also holds a sealed upstream grant ("upstream") and its generation
-- ("upstream_gen"). The latest rotation keeps the token it replaced ("previous"), its
-- time ("rotated"), the current token sealed by that one ("successor") and how often it
-- was answered again for it ("retries"); "streak" counts consecutive rotations, up to the
-- latest, that were answered again.
-- Replies that end families append each one's id, grant and sealed upstream grant (empty
-- unless coupled), for the audit log and upstream revocation; families removed after
-- expiry are not reported.
-- A run resent after a lost reply never applies twice: rotate finds its own rotation and
-- answers it again ('repeated'), issue finds the token key present, set_upstream
-- recognises its own replacement, and revocation is idempotent.
local token = KEYS[1]
local op, prefix, now, window_max = ARGV[1], ARGV[2], tonumber(ARGV[3]), tonumber(ARGV[4])
local function integer(n) return n and n > 0 and n <= 253402300799999 and n % 1 == 0 end
local function count(n) return n == 0 or integer(n) end
local function decimal(n) return string.format('%.0f', n) end
if not integer(now) or not integer(window_max) then return {'unavailable'} end
local function family_key(id) return prefix .. 'family:' .. id end
local function index_key(user) return prefix .. 'user:' .. user end
local function token_key(hash) return prefix .. 'token:' .. hash end
local function history(key)
    local hashes = {}
    for hash in string.gmatch(redis.call('HGET', key, 'history') or '', '%S+') do hashes[#hashes + 1] = hash end
    return hashes
end
-- Returns {id, grant, sealed upstream grant or ''} for a stored family, otherwise {}.
local function revoke(id)
    local key = family_key(id)
    local ended = {}
    if redis.call('TYPE', key).ok == 'hash' then
        local current = redis.call('HGET', key, 'current')
        if current then redis.call('DEL', token_key(current)) end
        for _, hash in ipairs(history(key)) do redis.call('DEL', token_key(hash)) end
        local grant = redis.call('HGET', key, 'grant')
        if grant then ended = {id, grant, redis.call('HGET', key, 'upstream') or ''} end
    end
    local user = redis.call('HGET', key, 'user')
    redis.call('DEL', key)
    if user then redis.call('ZREM', index_key(user), id) end
    return ended
end
local function append(reply, values)
    for _, value in ipairs(values) do reply[#reply + 1] = value end
    return reply
end
local function live(key)
    if redis.call('TYPE', key).ok ~= 'hash' then return nil end
    local idle, absolute = tonumber(redis.call('HGET', key, 'idle')), tonumber(redis.call('HGET', key, 'absolute'))
    if not integer(idle) or not integer(absolute) then return nil end
    return now < idle and now < absolute
end
-- Removes the families of a per-user index that are no longer live. A family whose key
-- expired took its "user" field along, so revoke() cannot find its index entry.
local function prune_index(index)
    for _, member in ipairs(redis.call('ZRANGE', index, 0, -1)) do
        if not live(family_key(member)) then
            revoke(member)
            redis.call('ZREM', index, member)
        end
    end
end

if op == 'issue' then
    local id, user, hash, grant = ARGV[5], ARGV[6], ARGV[7], ARGV[8]
    local absolute, idle, cap, client, upstream = tonumber(ARGV[9]), tonumber(ARGV[10]), tonumber(ARGV[11]), ARGV[12], ARGV[13]
    if not integer(absolute) or not integer(idle) or not integer(cap) or idle > absolute then return {'unavailable'} end
    if redis.call('EXISTS', token) == 1 then return {'unavailable'} end
    local index = index_key(user)
    prune_index(index)
    local excess = redis.call('ZCARD', index) + 1 - cap
    local reply = {'ok'}
    if excess > 0 then
        for _, member in ipairs(redis.call('ZRANGE', index, 0, excess - 1)) do append(reply, revoke(member)) end
    end
    local key = family_key(id)
    redis.call('HSET', key, 'grant', grant, 'client', client, 'user', user, 'created', decimal(now), 'absolute', decimal(absolute),
        'idle', decimal(idle), 'current', hash, 'previous', '', 'rotated', '0', 'successor', '', 'retries', '0',
        'streak', '0', 'history', '')
    if upstream ~= '' then redis.call('HSET', key, 'upstream', upstream, 'upstream_gen', '0') end
    redis.call('PEXPIREAT', key, decimal(idle))
    redis.call('SET', token, id, 'PXAT', decimal(idle))
    redis.call('ZADD', index, now, id)
    if redis.call('PEXPIRETIME', index) < absolute then redis.call('PEXPIREAT', index, decimal(absolute)) end
    return reply
end

-- Upstream replacement: KEYS[1] is the family key, ARGV[5] the expected generation.
if op == 'set_upstream' then
    if not live(token) then return {'stale'} end
    local expected, sealed = tonumber(ARGV[5]), ARGV[6]
    local stored, generation = redis.call('HGET', token, 'upstream'), tonumber(redis.call('HGET', token, 'upstream_gen'))
    if not stored or not generation or not expected or expected < 0 or expected % 1 ~= 0 then return {'stale'} end
    if generation == expected + 1 and stored == sealed then return {'stored'} end
    if generation ~= expected then return {'stale'} end
    redis.call('HSET', token, 'upstream', sealed, 'upstream_gen', decimal(generation + 1))
    return {'stored'}
end

-- Upstream refresh lock: KEYS[1] is the family's lock key, ARGV[5] the holder.
if op == 'lock' then
    local holder, expires = ARGV[5], tonumber(ARGV[6])
    if not integer(expires) or expires <= now then return {'unavailable'} end
    local current = redis.call('GET', token)
    if current and current ~= holder then return {'busy'} end
    redis.call('SET', token, holder, 'PXAT', decimal(expires))
    return {'ok'}
end
if op == 'unlock' then
    if redis.call('GET', token) == ARGV[5] then redis.call('DEL', token) end
    return {'ok'}
end

-- A user's families: KEYS[1] is the per-user index. 'list' replies with the summaries
-- {id, grant, created, last used, idle, absolute} of at most ARGV[5] live families,
-- newest first; the last use is the latest rotation, or the start. 'revoke_user' ends
-- every live family of the user.
if op == 'list' then
    local limit = tonumber(ARGV[5])
    if not integer(limit) then return {'unavailable'} end
    prune_index(token)
    local reply = {'ok'}
    for _, member in ipairs(redis.call('ZRANGE', token, 0, limit - 1, 'REV')) do
        local key = family_key(member)
        local created, rotated = redis.call('HGET', key, 'created'), tonumber(redis.call('HGET', key, 'rotated')) or 0
        append(reply, {member, redis.call('HGET', key, 'grant'), created, rotated > 0 and decimal(rotated) or created,
            redis.call('HGET', key, 'idle'), redis.call('HGET', key, 'absolute')})
    end
    return reply
end
if op == 'revoke_user' then
    prune_index(token)
    local reply = {'ok'}
    for _, member in ipairs(redis.call('ZRANGE', token, 0, -1)) do append(reply, revoke(member)) end
    redis.call('DEL', token)
    return reply
end

local id = redis.call('GET', token)
if op == 'revoke' then
    if not id then return {'missing'} end
    local key = family_key(id)
    if redis.call('TYPE', key).ok ~= 'hash' then return {'missing'} end
    if redis.call('HGET', key, 'client') ~= ARGV[5] then return {'missing'} end
    return append({'ok'}, revoke(id))
end
if op == 'revoke_family' then
    return append({'ok'}, revoke(ARGV[5]))
end
if not id then return {'missing'} end
local key = family_key(id)
local state = live(key)
if state == nil then return {'missing'} end
if not state then revoke(id) return {'missing'} end
local hash = ARGV[5]
local current = redis.call('HGET', key, 'current')

local previous, rotated = redis.call('HGET', key, 'previous'), tonumber(redis.call('HGET', key, 'rotated'))
-- Answers the latest rotation again for its previous token, within `window` ms of it and
-- at most `cap` times: {'repeated', current hash, sealed successor, retries, streak}.
local function repeated(window, cap)
    local retries, streak = tonumber(redis.call('HGET', key, 'retries')), tonumber(redis.call('HGET', key, 'streak'))
    if previous ~= hash or not rotated or not retries or not streak or now >= rotated + window or retries >= cap then
        return {'stale'}
    end
    if retries == 0 then streak = streak + 1 end
    redis.call('HSET', key, 'retries', decimal(retries + 1), 'streak', decimal(streak))
    return {'repeated', current, redis.call('HGET', key, 'successor'), decimal(retries + 1), decimal(streak)}
end

-- A family view is {id, grant, created, absolute, sealed upstream grant or '', its generation};
-- the previous token within the longest retry window adds the time of its rotation.
if op == 'lookup' then
    local view = {id, redis.call('HGET', key, 'grant'), redis.call('HGET', key, 'created'), redis.call('HGET', key, 'absolute'),
        redis.call('HGET', key, 'upstream') or '', redis.call('HGET', key, 'upstream_gen') or '0'}
    if current == hash then return append({'current'}, view) end
    if previous == hash and rotated and now < rotated + window_max then
        return append(append({'previous'}, view), {decimal(rotated)})
    end
    return append({'reused'}, revoke(id))
end
-- Repetition: ARGV[6] is the retry window in ms and ARGV[7] the cap.
if op == 'repeat' then
    local window, cap = tonumber(ARGV[6]), tonumber(ARGV[7])
    if not count(window) or not count(cap) then return {'unavailable'} end
    return repeated(window, cap)
end
-- Rotation: ARGV[9] is the grant the next token carries, replacing the family's, ARGV[11]
-- the next token sealed by the presented one, ARGV[12] the retry window and ARGV[13] the
-- cap that apply if the presented token turns out to be the previous one.
if op == 'rotate' then
    local next_hash, next_token, idle, ceiling = ARGV[6], KEYS[2], tonumber(ARGV[7]), tonumber(ARGV[8])
    local grant, keep, sealed = ARGV[9], tonumber(ARGV[10]), ARGV[11]
    local window, cap = tonumber(ARGV[12]), tonumber(ARGV[13])
    if not integer(idle) or not integer(ceiling) or idle > ceiling or not integer(keep) or not count(window) or not count(cap) then
        return {'unavailable'}
    end
    if previous == hash then return repeated(window, cap) end
    if current ~= hash or now >= ceiling then return {'stale'} end
    if redis.call('EXISTS', next_token) == 1 then return {'unavailable'} end
    local absolute = math.min(tonumber(redis.call('HGET', key, 'absolute')), ceiling)
    local hashes = history(key)
    hashes[#hashes + 1] = hash
    while #hashes > keep do redis.call('DEL', token_key(table.remove(hashes, 1))) end
    -- The streak goes on only if the rotation that ends now was answered again.
    local streak = tonumber(redis.call('HGET', key, 'streak')) or 0
    if (tonumber(redis.call('HGET', key, 'retries')) or 0) == 0 then streak = 0 end
    redis.call('HSET', key, 'grant', grant, 'current', next_hash, 'previous', hash, 'rotated', decimal(now),
        'successor', sealed, 'retries', '0', 'streak', decimal(streak),
        'idle', decimal(idle), 'absolute', decimal(absolute), 'history', table.concat(hashes, ' '))
    redis.call('PEXPIREAT', key, decimal(idle))
    redis.call('PEXPIREAT', token, decimal(idle))
    redis.call('SET', next_token, id, 'PXAT', decimal(idle))
    return {'rotated'}
end
return {'unavailable'}
