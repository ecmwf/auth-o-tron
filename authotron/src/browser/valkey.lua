local prefix = KEYS[1]
local op = ARGV[1]
local session_wire_bytes_limit = tonumber(ARGV[#ARGV - 1])
local session_envelope_bytes_reserve = tonumber(ARGV[#ARGV])
if not session_wire_bytes_limit or not session_envelope_bytes_reserve or session_envelope_bytes_reserve <= 0 or session_wire_bytes_limit <= session_envelope_bytes_reserve then
  return redis.error_reply('invalid wire limits')
end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local function prune(index)
  redis.call('ZREMRANGEBYSCORE', index, '-inf', now)
end
local function quota(key, limit, window)
  local start = math.floor(now / window)
  local old = redis.call('HMGET', key, 'window', 'used')
  local used = 0
  if old[1] or old[2] then
    if not tonumber(old[1]) or not tonumber(old[2]) or tonumber(old[2]) < 0 then error('invalid browser quota') end
  end
  if tonumber(old[1]) == start then used = tonumber(old[2]) or 0 end
  if used >= limit then return false end
  redis.call('HSET', key, 'window', start, 'used', used + 1)
  redis.call('PEXPIRE', key, window * 2)
  return true
end
local forms = prefix .. ':forms'
local sessions = prefix .. ':sessions'
local leases = prefix .. ':leases'
local function typed(key, expected)
  local actual = redis.call('TYPE', key).ok
  if actual ~= 'none' and actual ~= expected then error('invalid browser key type') end
end
local function allowed(command, ...)
  if not redis.acl_check_cmd(command, ...) then error('browser command permission denied') end
end
local function quota_permissions(key)
  allowed('HSET', key, 'window', '0', 'used', '1')
  allowed('PEXPIRE', key, '1000')
end
-- Mutation-command permissions are checked before writes. Later reads may still
-- fail; this is preflight, not rollback for OOM or unexpected runtime errors.
if op == 'form' then
  quota_permissions(prefix .. ':form-quota')
  allowed('ZREMRANGEBYSCORE', forms, '-inf', now)
  allowed('HSET', prefix .. ':form:' .. ARGV[2], 'csrf', ARGV[3], 'flow', ARGV[4], 'expires', '0')
  allowed('PEXPIRE', prefix .. ':form:' .. ARGV[2], ARGV[5])
  allowed('ZADD', forms, '0', ARGV[2])
elseif op == 'session' then
  allowed('ZREMRANGEBYSCORE', sessions, '-inf', now)
  allowed('SET', prefix .. ':session:' .. ARGV[2], ARGV[4], 'PX', ARGV[5])
  allowed('ZADD', sessions, '0', ARGV[2])
  if ARGV[3] ~= '' then
    allowed('DEL', prefix .. ':session:' .. ARGV[3])
    allowed('ZREM', sessions, ARGV[3])
  end
elseif op == 'consume' or op == 'discard' then
  allowed('DEL', prefix .. ':form:' .. ARGV[2])
  allowed('ZREM', forms, ARGV[2])
elseif op == 'admit' or op == 'quota' then
  quota_permissions(prefix .. ':verify-quota')
  if op == 'admit' then
    allowed('ZREMRANGEBYSCORE', leases, '-inf', now)
    allowed('ZADD', leases, '0', ARGV[2])
  end
elseif op == 'release' then
  allowed('ZREM', leases, ARGV[2])
end
-- Redis scripts are atomic but do not roll back runtime errors: check types first.
if op == 'form' or op == 'consume' or op == 'discard' then
  typed(forms, 'zset')
  typed(prefix .. ':form:' .. ARGV[2], 'hash')
  if op == 'form' then typed(prefix .. ':form-quota', 'hash') end
elseif op == 'session' then
  typed(sessions, 'zset')
  typed(prefix .. ':session:' .. ARGV[2], 'string')
elseif op == 'read' then
  typed(prefix .. ':session:' .. ARGV[2], 'string')
elseif op == 'admit' or op == 'release' then
  typed(leases, 'zset')
  if op == 'admit' then typed(prefix .. ':verify-quota', 'hash') end
elseif op == 'quota' then
  typed(prefix .. ':verify-quota', 'hash')
end
if op == 'form' then
  local ttl, cap, limit, window = tonumber(ARGV[5]), tonumber(ARGV[6]), tonumber(ARGV[7]), tonumber(ARGV[8])
  if not ttl or ttl <= 0 or not cap or cap <= 0 or not limit or limit <= 0 or not window or window <= 0 then return redis.error_reply('invalid arguments') end
  prune(forms)
  if redis.call('ZCARD', forms) >= cap then return {'capacity'} end
  if not quota(prefix .. ':form-quota', limit, window) then return {'limited'} end
  local key = prefix .. ':form:' .. ARGV[2]
  redis.call('HSET', key, 'csrf', ARGV[3], 'flow', ARGV[4], 'expires', now + ttl)
  redis.call('PEXPIRE', key, ttl)
  redis.call('ZADD', forms, now + ttl, ARGV[2])
  return {'ok'}
elseif op == 'consume' then
  local key = prefix .. ':form:' .. ARGV[2]
  if redis.call('HSTRLEN', key, 'csrf') ~= 64 or redis.call('HSTRLEN', key, 'flow') > 8 or redis.call('HSTRLEN', key, 'expires') > 16 then return {'missing'} end
  local values = redis.call('HMGET', key, 'csrf', 'flow', 'expires')
  if values[1] ~= ARGV[3] or values[2] ~= ARGV[4] or not tonumber(values[3]) or tonumber(values[3]) <= now then return {'missing'} end
  redis.call('DEL', key)
  redis.call('ZREM', forms, ARGV[2])
  return {'ok'}
elseif op == 'discard' then
  redis.call('DEL', prefix .. ':form:' .. ARGV[2])
  redis.call('ZREM', forms, ARGV[2])
  return {'ok'}
elseif op == 'session' then
  local ttl, cap = tonumber(ARGV[5]), tonumber(ARGV[6])
  if not ttl or ttl <= 0 or not cap or cap <= 0 or string.len(ARGV[4]) > session_wire_bytes_limit - session_envelope_bytes_reserve then return redis.error_reply('invalid arguments') end
  prune(sessions)
  local previous = ARGV[3]
  local count = redis.call('ZCARD', sessions)
  if previous ~= '' and redis.call('ZSCORE', sessions, previous) then count = count - 1 end
  if count >= cap then return {'capacity'} end
  local expires = now + ttl
  redis.call('SET', prefix .. ':session:' .. ARGV[2], '1\n' .. string.format('%.0f', expires) .. '\n' .. ARGV[4], 'PX', ttl)
  redis.call('ZADD', sessions, expires, ARGV[2])
  if previous ~= '' then
    redis.call('DEL', prefix .. ':session:' .. previous)
    redis.call('ZREM', sessions, previous)
  end
  return {'ok'}
elseif op == 'read' then
  local key = prefix .. ':session:' .. ARGV[2]
  local size = redis.call('STRLEN', key)
  if size == 0 then return {'missing'} end
  if size > session_wire_bytes_limit then return {'corrupt'} end
  local value = redis.call('GET', key)
  local version, expiry = string.match(value, '^(%d+)\n(%d+)\n')
  if version ~= '1' or not tonumber(expiry) then return {'corrupt'} end
  if tonumber(expiry) <= now then return {'missing'} end
  return {'ok', value}
elseif op == 'admit' then
  local limit, window, cap, ttl = tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[5]), tonumber(ARGV[6])
  if not limit or limit <= 0 or not window or window <= 0 or not cap or cap <= 0 or not ttl or ttl <= 0 then return redis.error_reply('invalid arguments') end
  -- Locally admitted attempts spend shared quota, including invalid credentials
  -- and optional shared-cap rejection. Locally saturated requests do not call Valkey.
  if not quota(prefix .. ':verify-quota', limit, window) then return {'limited'} end
  prune(leases)
  if redis.call('ZCARD', leases) >= cap then return {'limited'} end
  local expires = now + ttl
  redis.call('ZADD', leases, expires, ARGV[2])
  return {'ok', string.format('%.0f', expires)}
elseif op == 'release' then
  if redis.call('ZSCORE', leases, ARGV[2]) == ARGV[3] then redis.call('ZREM', leases, ARGV[2]) end
  return {'ok'}
elseif op == 'quota' then
  local limit, window = tonumber(ARGV[3]), tonumber(ARGV[4])
  if not limit or limit <= 0 or not window or window <= 0 then return redis.error_reply('invalid arguments') end
  if not quota(prefix .. ':verify-quota', limit, window) then return {'limited'} end
  return {'ok'}
end
return redis.error_reply('invalid operation')
