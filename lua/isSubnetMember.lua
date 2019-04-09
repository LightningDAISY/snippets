#! /usr/local/openresty/bin/resty
local address = "111.7.80.66";
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

function fread(path)
    local fp = assert(io.open(path, "r"))
    local fbody = fp:read("*all")
    fp:close()
    return fbody
end

function address2decimal(address)
  itr = rex.split(address, "\\.")
  local decs = {}
  for dec in itr do
    table.insert(decs, dec)
  end

  return decs[4] +
         decs[3] * 256 +
         decs[2] * 65536 +
         decs[1] * 16777216
end

function decimalRangeOfMask(networkAddress,netmaskLength)
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

--
-- ex.
--     if isSubnetMember("111.7.80.66", "111.7.80.64/27") then
--       print("111.7.80.66 in 111.7.80.64/27")
--     end
--
function isSubnetMember(adr, subnet)
  local itr = rex.split(subnet, "/", 2)
  local subnetAddress = itr()
  local mask = itr()

  local decSubnetAddress = address2decimal(subnetAddress)
  local minOfMask = decSubnetAddress
  local maxOfMask = decSubnetAddress
  if mask then
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
function main()
  local fbody = fread("allows.conf")
  for subnet in rex.gmatch(fbody, "(\\d+\\.[^\\s;]+)") do
    if isSubnetMember(address, subnet) then
      print(address .. " is matched. " .. subnet)
      return
    end
  end
  print(address .. " is not matched.")
end

main()

