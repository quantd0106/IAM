// Fixed session-only transition: callers cannot supply commands or Lua source.
export const redisSessionStateScript = `
local key = KEYS[1]
local operation = ARGV[1]
local raw
if operation == 'create' then
  raw = ARGV[2]
else
  raw = redis.call('GET', key)
  if not raw then return nil end
end

local function uuid(value)
  if type(value) ~= 'string' or #value ~= 36 then return false end
  if value:sub(9,9) ~= '-' or value:sub(14,14) ~= '-'
    or value:sub(19,19) ~= '-' or value:sub(24,24) ~= '-' then
    return false
  end
  local compact = value:gsub('-', '')
  if #compact ~= 32 or not compact:match('^%x+$') then return false end
  local lower = value:lower()
  if value == '00000000-0000-0000-0000-000000000000'
    or value == 'ffffffff-ffff-ffff-ffff-ffffffffffff' then return true end
  return lower:sub(15,15):match('^[1-8]$') ~= nil
    and lower:sub(20,20):match('^[89ab]$') ~= nil
end

local function timestamp(value)
  return type(value) == 'number' and value >= 0
    and value <= 9007199254740991 and value == math.floor(value)
end

local fields = {
  userId = true, authTime = true, mfaLevel = true,
  createdAt = true, lastActivityAt = true, absoluteExpiresAt = true
}
local decoded, state = pcall(cjson.decode, raw)
local valid = decoded and type(state) == 'table'
if valid then
  local count = 0
  for field in pairs(state) do
    count = count + 1
    if not fields[field] then valid = false end
  end
  valid = valid and count == 6 and uuid(state.userId)
    and type(state.mfaLevel) == 'string' and #state.mfaLevel > 0
    and timestamp(state.authTime) and timestamp(state.createdAt)
    and timestamp(state.lastActivityAt) and timestamp(state.absoluteExpiresAt)
  if valid then
    valid = state.absoluteExpiresAt > state.authTime
      and state.absoluteExpiresAt > state.createdAt
      and state.absoluteExpiresAt > state.lastActivityAt
  end
end
if not valid then
  if operation ~= 'create' then redis.call('DEL', key) end
  return nil
end

-- One server-side clock decision; never use application/network timing for TTL.
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
if state.absoluteExpiresAt <= now then
  if operation ~= 'create' then redis.call('DEL', key) end
  return nil
end
if operation == 'read' then return raw end

local idleSeconds = tonumber(ARGV[3])
local ttl = math.min(idleSeconds * 1000, state.absoluteExpiresAt - now)
local deadline = now + ttl
if operation == 'touch' then
  state.lastActivityAt = now
  -- cjson's default 14-digit number encoding could round safe integers and
  -- extend absoluteExpiresAt. Encode strings with cjson, integers losslessly.
  raw = '{"userId":' .. cjson.encode(state.userId)
    .. ',"authTime":' .. string.format('%.0f', state.authTime)
    .. ',"mfaLevel":' .. cjson.encode(state.mfaLevel)
    .. ',"createdAt":' .. string.format('%.0f', state.createdAt)
    .. ',"lastActivityAt":' .. string.format('%.0f', state.lastActivityAt)
    .. ',"absoluteExpiresAt":' .. string.format('%.0f', state.absoluteExpiresAt)
    .. '}'
end
-- Absolute millisecond expiry prevents rounding/command latency from adding life.
redis.call('SET', key, raw, 'PXAT', string.format('%.0f', deadline))
return raw
`;
