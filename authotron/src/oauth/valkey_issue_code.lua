-- Four explicit keys on one primary; atomic execution is not rollback on unexpected errors.
local si, source, ci, code = KEYS[1], KEYS[2], KEYS[3], KEYS[4]
local old_exp, old_payload, effective = tonumber(ARGV[1]), ARGV[2], tonumber(ARGV[3])
local cap, expiry, hash, issuer, payload = tonumber(ARGV[4]), tonumber(ARGV[5]), ARGV[6], ARGV[7], ARGV[8]
local code_limit, consent_limit, ttl = tonumber(ARGV[9]), tonumber(ARGV[10]), tonumber(ARGV[11])
local function integer(n) return n and n > 0 and n <= 253402300799999 and n % 1 == 0 end
local function decimal(n) return string.format('%.0f', n) end
local function kind(key) return redis.call('TYPE', key).ok end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
if not integer(now) or not code_limit or not consent_limit or not cap or cap < 1 or cap > 100000 or cap % 1 ~= 0
    or not ttl or ttl < 30000 or ttl > 300000 or ttl % 1 ~= 0 then return {'unavailable'} end
local sit, st, cit, ct = kind(si), kind(source), kind(ci), kind(code)
if (sit ~= 'none' and sit ~= 'zset') or (st ~= 'none' and st ~= 'hash')
    or (cit ~= 'none' and cit ~= 'zset') or (ct ~= 'none' and ct ~= 'hash') then return {'unavailable'} end
if redis.call('ZCARD', si) > 100000 or redis.call('ZCARD', ci) > 100000 then return {'unavailable'} end
if st == 'none' then return {'missing'} end
local score = tonumber(redis.call('ZSCORE', si, source))
if not integer(score) then return {'unavailable'} end
if score <= now then return {'missing'} end
if redis.call('HLEN', source) ~= 3 or redis.call('HSTRLEN', source, 'kind') > 13
    or redis.call('HSTRLEN', source, 'expiry') > 15 then return {'unavailable'} end
local state = redis.call('HGET', source, 'kind')
local source_exp = tonumber(redis.call('HGET', source, 'expiry'))
if not integer(source_exp) or source_exp ~= score
    or (state ~= 'consent' and state ~= 'authenticated' and state ~= 'pending') then return {'unavailable'} end
if state ~= 'consent' then return {'missing'} end
local size = redis.call('HSTRLEN', source, 'payload')
if size < 1 or size > consent_limit then return {'unavailable'} end
if source_exp ~= old_exp or redis.call('HGET', source, 'payload') ~= old_payload then return {'missing'} end
if not integer(effective) or effective <= now or effective > source_exp then return {'missing'} end
-- Hash examples: 43 'A' characters are valid; appended '=' or a final 'B' is invalid.
if not integer(expiry) or expiry <= now or expiry > effective or expiry > now + ttl
    or #hash ~= 43 or not string.match(hash, '^[A-Za-z0-9_-]+$') or not string.match(string.sub(hash, -1), '^[AEIMQUYcgkosw048]$')
    or #issuer < 1 or #issuer > 2048 or #payload < 1 or #payload > code_limit then return {'unavailable'} end
if ct ~= 'none' or redis.call('ZSCORE', ci, code) then return {'collision'} end
if not redis.acl_check_cmd('HSET', code, 'code_hash', hash, 'issuer', issuer, 'expiry', decimal(expiry), 'payload', payload)
    or not redis.acl_check_cmd('PEXPIREAT', code, decimal(expiry))
    or not redis.acl_check_cmd('ZADD', ci, decimal(expiry), code)
    or not redis.acl_check_cmd('ZREMRANGEBYSCORE', ci, '-inf', decimal(now))
    or not redis.acl_check_cmd('DEL', source) or not redis.acl_check_cmd('ZREM', si, source) then return {'unavailable'} end
redis.call('ZREMRANGEBYSCORE', ci, '-inf', decimal(now))
if redis.call('ZCARD', ci) >= cap then return {'limited'} end
redis.call('HSET', code, 'code_hash', hash, 'issuer', issuer, 'expiry', decimal(expiry), 'payload', payload)
redis.call('PEXPIREAT', code, decimal(expiry))
redis.call('ZADD', ci, decimal(expiry), code)
redis.call('DEL', source)
redis.call('ZREM', si, source)
return {'ok'}
