local M = {}
local rex = require("rex_pcre2")
local errorMessage = ""

local maskData = {
  1, -- (32 - 31 = ) 1
  3, -- 2
  7, -- 3
  15, -- 4
  31, -- 5
  63, -- 6
  127, -- 7
  255, -- 8
  511, -- 9
  1023, -- 10
  2047, -- 11
  4095, -- 12
  8191, -- 13
  16383, -- 14
  32767, -- 15
  65535, -- 16
  131071, -- 17
  262143, -- 18
  524287, -- 19
  1048575, -- 20
  2097151, -- 21
  4194303, -- 22
  8388607, -- 23
  16777215, -- 24
  33554431, -- 25
  67108863, -- 26
  134217727, -- 27
  268435455, -- 28
  536870911, -- 29
  1073741823, -- 30
  2147483647, -- 31
  4294967295, -- 32
}

-- 32 - hex2value["x" .. h]
local hex2value = {
  x255 = 0,
  x254 = 1,
  x252 = 2,
  x248 = 3,
  x240 = 4,
  x224 = 5,
  x192 = 6,
  x128 = 7,
  x0   = 8,
}

local function fread(path)
    local fp = assert(io.open(path, "r"))
    local fbody = fp:read("*all")
    fp:close()
    return fbody
end

local function splitAddress(address)
  itr = rex.split(address, "\\.")
  local decs = {}
  for dec in itr do
    table.insert(decs, dec)
  end
  return decs
end

local function address2decimal(address)
  local decs = splitAddress(address)
  return decs[4] +
         decs[3] * 256 +
         decs[2] * 65536 +
         decs[1] * 16777216
end

local function decimalRangeOfMask(networkAddress,netmaskLength)
  if netmaskLength + 0 >= 32 then
      errorMessage = "invalid netmask-length"
      return
  end
  local decimalAddress = address2decimal(networkAddress)
  local flip = 32 - netmaskLength
  local min = decimalAddress + 1
  local max = decimalAddress + maskData[flip]
  return { min = min, max = max }
end

local function address2length(address)
  local decs = splitAddress(address)
  local value = 0
  local len = 32
  for i = 4, 1, -1 do
    value = hex2value["x" .. decs[i]]
    if not value then return end
    if value <= 0 then return len end
    len = len - value
  end
  return len
end

--
-- ex.
--     if isSubnetMember("111.7.80.66", "111.7.80.64/27") then
--       print("111.7.80.66 in 111.7.80.64/27")
--     end
--
local function isSubnetMember(adr, subnet)
  local itr = rex.split(subnet, "/", 2)
  local subnetAddress = itr()
  local mask = itr()
  

  local decSubnetAddress = address2decimal(subnetAddress)
  local minOfMask = decSubnetAddress
  local maxOfMask = decSubnetAddress
  if mask then
    if rex.match(mask, "^\\d+\\.") then
      mask = address2length(mask)
    end
    local range = decimalRangeOfMask(subnetAddress,mask)
    if not range then return end
    minOfMask = range.min
    maxOfMask = range.max
  end

  local decAddress = address2decimal(adr)
  if decAddress >= minOfMask and decAddress <= maxOfMask then return true end
  return false
end

--
-- allows.conf example
--
--   122.22.4.0/24
--   210.34.92.5
--   127.0.0.0/8
--
function M.isAllowed(sourceAddress, filePath)
  local fbody = fread(filePath)
  local r = rex.new("(\\d+\\.[^\\s;]+)")
  if not r then print("new error"); return false end
  r:jit_compile()
  -- for subnet in rex.gmatch(fbody, "(\\d+\\.[^\\s;]+)") do
  for subnet in rex.gmatch(fbody, r) do
    if isSubnetMember(sourceAddress, subnet) then
      return true
    end
  end
  return false
end

function M.new(o)
	o = o or {}
	return o
end

return M

--[[

Example

	local subnet = require "subnet"
	local isAllowed = subnet.isAllowed(
      "192.168.0.2",
      "/path/to/allows.conf"
    )
	if isAllowed then
		print("is allowed.")
	else
		print("is NOT allowed.")
	end

Example allows.conf

    # localhost
    allow 127.0.0.1;

    # Private Network Address: Class C
    allow 192.168.0.0/24;

    ...

]]--

