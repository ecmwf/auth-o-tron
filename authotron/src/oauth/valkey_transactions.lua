-- Atomic execution does not imply rollback after an unexpected write failure.
local index, key = KEYS[1], KEYS[2]
local op, pending_limit, auth_limit, consent_limit = ARGV[1], tonumber(ARGV[2]), tonumber(ARGV[8]), tonumber(ARGV[11])
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local function integer(n) return n and n > 0 and n <= 253402300799999 and n % 1 == 0 end
local function decimal(n) return string.format('%.0f', n) end
local function kind(k) return redis.call('TYPE', k).ok end
local function writable(state, expiry, payload)
    return redis.acl_check_cmd('HSET', key, 'kind', state, 'expiry', decimal(expiry), 'payload', payload)
        and redis.acl_check_cmd('PEXPIREAT', key, decimal(expiry))
        and redis.acl_check_cmd('ZADD', index, decimal(expiry), key)
end
local function write(state, expiry, payload)
    redis.call('HSET', key, 'kind', state, 'expiry', decimal(expiry), 'payload', payload)
    redis.call('PEXPIREAT', key, decimal(expiry))
    redis.call('ZADD', index, decimal(expiry), key)
end
if not integer(now) or not pending_limit or not auth_limit or not consent_limit then return {'unavailable'} end
local it, kt = kind(index), kind(key)
if (it ~= 'none' and it ~= 'zset') or (kt ~= 'none' and kt ~= 'hash') then return {'unavailable'} end
if redis.call('ZCARD', index) > 100000 then return {'unavailable'} end
local score = tonumber(redis.call('ZSCORE', index, key))
if op == 'create' then
    local client_index, budget = KEYS[3], tonumber(ARGV[12])
    if not client_index or not budget or budget < 1 or budget > 100000 or budget % 1 ~= 0 then return {'unavailable'} end
    local ct = kind(client_index)
    if ct ~= 'none' and ct ~= 'zset' then return {'unavailable'} end
    if redis.call('ZCARD', client_index) > 100000 then return {'unavailable'} end
    local ttl, cap, expiry, payload = tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[5]), ARGV[6]
    if not ttl or ttl < 30000 or ttl > 900000 or ttl % 1 ~= 0 or not cap or cap < 1 or cap > 100000 or cap % 1 ~= 0
        or not integer(expiry) or expiry <= now or expiry > now + ttl or #payload < 1 or #payload > pending_limit then return {'unavailable'} end
    if kt ~= 'none' or score then return {'collision'} end
    -- Client indexes disappear without another request, including after a client
    -- is removed from policy. Original member deadlines bound retention; a new
    -- shorter-lived reservation must not expire another member's budget early.
    local index_expiry = expiry
    local latest = redis.call('ZRANGE', client_index, -1, -1, 'WITHSCORES')
    if #latest > 0 then
        local latest_expiry = tonumber(latest[2])
        if not integer(latest_expiry) or latest_expiry > now + 900000 then return {'unavailable'} end
        index_expiry = math.max(index_expiry, latest_expiry)
    end
    if not writable('pending', expiry, payload) or not redis.acl_check_cmd('ZREMRANGEBYSCORE', index, '-inf', decimal(now)) then return {'unavailable'} end
    if not redis.acl_check_cmd('ZADD', client_index, decimal(expiry), key)
        or not redis.acl_check_cmd('ZREM', client_index, key)
        or not redis.acl_check_cmd('PEXPIREAT', client_index, decimal(index_expiry)) then return {'unavailable'} end
    redis.call('ZREMRANGEBYSCORE', index, '-inf', decimal(now))
    -- Global membership is authoritative after consume/issue; promotions can shorten
    -- expiry. Prune this bounded client partition before reserving its next slot.
    for _, member in ipairs(redis.call('ZRANGE', client_index, 0, -1)) do
        local deadline = tonumber(redis.call('ZSCORE', index, member))
        if not deadline or deadline <= now then redis.call('ZREM', client_index, member) end
    end
    if redis.call('ZCARD', client_index) >= budget then return {'limited'} end
    if redis.call('ZCARD', index) >= cap then return {'limited'} end
    redis.call('ZADD', client_index, decimal(expiry), key)
    redis.call('PEXPIREAT', client_index, decimal(index_expiry))
    write('pending', expiry, payload)
    return {'ok'}
end
if kt == 'none' then return {'missing'} end
if not integer(score) then return {'unavailable'} end
if score <= now then return {'missing'} end
if redis.call('HLEN', key) ~= 3 or redis.call('HSTRLEN', key, 'kind') > 13 or redis.call('HSTRLEN', key, 'expiry') > 15 then return {'unavailable'} end
local state = redis.call('HGET', key, 'kind')
local expiry = tonumber(redis.call('HGET', key, 'expiry'))
if (state ~= 'pending' and state ~= 'authenticated' and state ~= 'consent') or not integer(expiry) or expiry ~= score then return {'unavailable'} end
if ARGV[7] == 'prepare' then
    if state ~= 'authenticated' and state ~= 'consent' then return {'missing'} end
elseif state ~= ARGV[7] then return {'missing'} end
local limit = state == 'pending' and pending_limit or (state == 'authenticated' and auth_limit or consent_limit)
local size = redis.call('HSTRLEN', key, 'payload')
if size < 1 or size > limit then return {'unavailable'} end
local payload = redis.call('HGET', key, 'payload')
if op == 'read' then return {'ok', decimal(now), decimal(expiry), payload, state} end
if op == 'prepare' then
    local next_expiry, next_payload = tonumber(ARGV[5]), ARGV[6]
    if expiry ~= tonumber(ARGV[9]) or payload ~= ARGV[10] then return {'missing'} end
    if not integer(next_expiry) or next_expiry <= now or next_expiry > expiry or #next_payload < 1 or #next_payload > consent_limit then return {'unavailable'} end
    if not writable('consent', next_expiry, next_payload) then return {'unavailable'} end
    write('consent', next_expiry, next_payload)
    return {'ok'}
end
if op == 'promote' then
    local next_expiry, next_payload = tonumber(ARGV[5]), ARGV[6]
    if expiry ~= tonumber(ARGV[9]) or payload ~= ARGV[10] then return {'missing'} end
    if state ~= 'pending' or not integer(next_expiry) or next_expiry <= now or next_expiry > expiry
        or #next_payload < 1 or #next_payload > auth_limit then return {'unavailable'} end
    if not writable('authenticated', next_expiry, next_payload) then return {'unavailable'} end
    write('authenticated', next_expiry, next_payload)
    return {'ok'}
end
if op == 'consume' then
    if expiry ~= tonumber(ARGV[5]) or payload ~= ARGV[6] then return {'missing'} end
    if (state == 'authenticated' or state == 'consent') and (not integer(tonumber(ARGV[9])) or tonumber(ARGV[9]) <= now or tonumber(ARGV[9]) > expiry) then return {'missing'} end
    if not redis.acl_check_cmd('DEL', key) or not redis.acl_check_cmd('ZREM', index, key) then return {'unavailable'} end
    redis.call('DEL', key)
    redis.call('ZREM', index, key)
    return {'ok'}
end
return {'unavailable'}
