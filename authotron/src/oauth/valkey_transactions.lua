-- Atomic execution does not imply rollback after an unexpected write failure.
local index, key = KEYS[1], KEYS[2]
local op, max_bytes = ARGV[1], tonumber(ARGV[2])
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local function integer(n) return n and n > 0 and n <= 253402300799999 and n % 1 == 0 end
local function decimal(n) return string.format('%.0f', n) end
local function kind(k) return redis.call('TYPE', k).ok end
if not integer(now) or not max_bytes or max_bytes < 1 then return {'unavailable'} end
local it, kt = kind(index), kind(key)
if (it ~= 'none' and it ~= 'zset') or (kt ~= 'none' and kt ~= 'string') then return {'unavailable'} end
if redis.call('ZCARD', index) > 100000 then return {'unavailable'} end
local score = tonumber(redis.call('ZSCORE', index, key))
if op == 'create' then
    local ttl, cap, expiry, payload = tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[5]), ARGV[6]
    if not ttl or ttl < 30000 or ttl > 900000 or ttl % 1 ~= 0 or not cap or cap < 1 or cap > 100000 or cap % 1 ~= 0
        or not integer(expiry) or expiry <= now or expiry > now + ttl or #payload < 1 or #payload > max_bytes then return {'unavailable'} end
    if kt ~= 'none' or score then return {'collision'} end
    if not redis.acl_check_cmd('ZREMRANGEBYSCORE', index, '-inf', decimal(now))
        or not redis.acl_check_cmd('SET', key, payload, 'PXAT', decimal(expiry), 'NX')
        or not redis.acl_check_cmd('ZADD', index, decimal(expiry), key) then return {'unavailable'} end
    redis.call('ZREMRANGEBYSCORE', index, '-inf', decimal(now))
    if redis.call('ZCARD', index) >= cap then return {'limited'} end
    if not redis.call('SET', key, payload, 'PXAT', decimal(expiry), 'NX') then return {'collision'} end
    redis.call('ZADD', index, decimal(expiry), key)
    return {'ok'}
end
if kt == 'none' then return {'missing'} end
if not integer(score) then return {'unavailable'} end
if score <= now then return {'missing'} end
if redis.call('STRLEN', key) > max_bytes then return {'unavailable'} end
local payload = redis.call('GET', key)
if op == 'read' then return {'ok', decimal(now), decimal(score), payload} end
if op == 'consume' then
    if score ~= tonumber(ARGV[5]) or payload ~= ARGV[6] then return {'missing'} end
    if not redis.acl_check_cmd('DEL', key) or not redis.acl_check_cmd('ZREM', index, key) then return {'unavailable'} end
    redis.call('DEL', key)
    redis.call('ZREM', index, key)
    return {'ok'}
end
return {'unavailable'}
