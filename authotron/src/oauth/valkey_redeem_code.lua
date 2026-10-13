-- Bounded read or exact-snapshot consume on one primary; no rollback. A consume resent
-- after a lost reply finds the code gone and returns 'missing'.
local index, key = KEYS[1], KEYS[2]
local op, limit = ARGV[1], tonumber(ARGV[2])
local function integer(n) return n and n > 0 and n <= 253402300799999 and n % 1 == 0 end
local function decimal(n) return string.format('%.0f', n) end
local function kind(k) return redis.call('TYPE', k).ok end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
if not integer(now) or not limit then return {'unavailable'} end
local it, kt = kind(index), kind(key)
if (it ~= 'none' and it ~= 'zset') or (kt ~= 'none' and kt ~= 'hash') then return {'unavailable'} end
if redis.call('ZCARD', index) > 100000 then return {'unavailable'} end
if kt == 'none' then return {'missing'} end
local score = tonumber(redis.call('ZSCORE', index, key))
if not integer(score) then return {'unavailable'} end
if score <= now then return {'missing'} end
if redis.call('HLEN', key) ~= 4 or redis.call('HSTRLEN', key, 'code_hash') ~= 43
    or redis.call('HSTRLEN', key, 'issuer') < 1 or redis.call('HSTRLEN', key, 'issuer') > 2048
    or redis.call('HSTRLEN', key, 'expiry') < 1 or redis.call('HSTRLEN', key, 'expiry') > 15
    or redis.call('HSTRLEN', key, 'payload') < 1 or redis.call('HSTRLEN', key, 'payload') > limit then return {'unavailable'} end
local expiry_text = redis.call('HGET', key, 'expiry')
local expiry = tonumber(expiry_text)
if not integer(expiry) or expiry ~= score or expiry_text ~= decimal(expiry) then return {'unavailable'} end
local hash, issuer, payload = redis.call('HGET', key, 'code_hash'), redis.call('HGET', key, 'issuer'), redis.call('HGET', key, 'payload')
if op == 'read' then return {'ok', decimal(now), expiry_text, hash, issuer, payload} end
if op ~= 'consume' then return {'unavailable'} end
if expiry_text ~= ARGV[3] or hash ~= ARGV[4] or issuer ~= ARGV[5] or payload ~= ARGV[6] then return {'missing'} end
local effective = tonumber(ARGV[7])
if not integer(effective) or effective <= now or effective > expiry then return {'missing'} end
if not redis.acl_check_cmd('DEL', key) or not redis.acl_check_cmd('ZREM', index, key) then return {'unavailable'} end
redis.call('DEL', key)
redis.call('ZREM', index, key)
return {'ok'}
