-- Atomic refresh-token family operations on one primary. KEYS[1] is the presented or
-- issued token key, except where an operation names another key; family, per-user
-- index and other token keys derive from the fixed prefix. A token key expires at the family idle deadline when it was issued or
-- rotated, and a family keeps at most ARGV[10] rotated hashes ("history", oldest first).
-- A coupled family also holds a sealed upstream grant ("upstream") and its generation
-- ("upstream_gen").
-- Replies that end families append each one's id, grant and sealed upstream grant (empty
-- unless coupled), for the audit log and upstream revocation; families removed after
-- expiry are not reported.
-- A run resent after a lost reply never applies twice: rotate finds the hash no longer
-- current ('stale'), issue finds the token key present, set_upstream recognises its own
-- replacement, and revocation is idempotent.
local token = KEYS[1]
local op, prefix, now, grace = ARGV[1], ARGV[2], tonumber(ARGV[3]), tonumber(ARGV[4])
local function integer(n) return n and n > 0 and n <= 253402300799999 and n % 1 == 0 end
local function decimal(n) return string.format('%.0f', n) end
if not integer(now) or not integer(grace) then return {'unavailable'} end
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

if op == 'issue' then
    local id, user, hash, grant = ARGV[5], ARGV[6], ARGV[7], ARGV[8]
    local absolute, idle, cap, client, upstream = tonumber(ARGV[9]), tonumber(ARGV[10]), tonumber(ARGV[11]), ARGV[12], ARGV[13]
    if not integer(absolute) or not integer(idle) or not integer(cap) or idle > absolute then return {'unavailable'} end
    if redis.call('EXISTS', token) == 1 then return {'unavailable'} end
    local index = index_key(user)
    for _, member in ipairs(redis.call('ZRANGE', index, 0, -1)) do
        if not live(family_key(member)) then revoke(member) end
    end
    local excess = redis.call('ZCARD', index) + 1 - cap
    local reply = {'ok'}
    if excess > 0 then
        for _, member in ipairs(redis.call('ZRANGE', index, 0, excess - 1)) do append(reply, revoke(member)) end
    end
    local key = family_key(id)
    redis.call('HSET', key, 'grant', grant, 'client', client, 'user', user, 'created', decimal(now), 'absolute', decimal(absolute),
        'idle', decimal(idle), 'current', hash, 'previous', '', 'rotated', '0', 'history', '')
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

if op == 'lookup' then
    if current == hash then
        return {'current', id, redis.call('HGET', key, 'grant'), redis.call('HGET', key, 'created'), redis.call('HGET', key, 'absolute'),
            redis.call('HGET', key, 'upstream') or '', redis.call('HGET', key, 'upstream_gen') or '0'}
    end
    local rotated = tonumber(redis.call('HGET', key, 'rotated'))
    if redis.call('HGET', key, 'previous') == hash and rotated and now < rotated + grace then return {'grace'} end
    return append({'reused'}, revoke(id))
end
-- Rotation: ARGV[9] is the grant the next token carries, replacing the family's.
if op == 'rotate' then
    local next_hash, next_token, idle, ceiling = ARGV[6], KEYS[2], tonumber(ARGV[7]), tonumber(ARGV[8])
    local grant, keep = ARGV[9], tonumber(ARGV[10])
    if not integer(idle) or not integer(ceiling) or idle > ceiling or not integer(keep) then return {'unavailable'} end
    if current ~= hash or now >= ceiling then return {'stale'} end
    if redis.call('EXISTS', next_token) == 1 then return {'unavailable'} end
    local absolute = math.min(tonumber(redis.call('HGET', key, 'absolute')), ceiling)
    local hashes = history(key)
    hashes[#hashes + 1] = hash
    while #hashes > keep do redis.call('DEL', token_key(table.remove(hashes, 1))) end
    redis.call('HSET', key, 'grant', grant, 'current', next_hash, 'previous', hash, 'rotated', decimal(now),
        'idle', decimal(idle), 'absolute', decimal(absolute), 'history', table.concat(hashes, ' '))
    redis.call('PEXPIREAT', key, decimal(idle))
    redis.call('PEXPIREAT', token, decimal(idle))
    redis.call('SET', next_token, id, 'PXAT', decimal(idle))
    return {'rotated'}
end
return {'unavailable'}
