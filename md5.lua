-- A MD5-Encryption Library implemented in Lua-5.3
-- Copyright (c) 2016 sysu_AT < owtotwo@163.com >

-- Using GNU Lesser General Public License (LGPL)
-- [ http://www.gnu.org/licenses/lgpl-3.0.en.html ] for License Text
-- [ https://en.wikipedia.org/wiki/MD5 ] for Algorithm Detials


-- Notice that may be it can't not support the big file (>50M) very well. (Because
-- it should load the whole file in memory at a time.)
-- (But I think you will not encrypt the file which is larger than 10M in Lua frequently.)

-- API : md5.string(str) and md5.file(filename)
local md5 = {}


-- aux functions
local function buffer_to_hex(buffer)
	if type(buffer) ~= "string" then error("Wrong type " .. type(buffer)) end
	local ret = ""
	for i = 1, #buffer do
		ret = ret .. string.format("%02x", buffer:byte(i))
	end
	return ret
end

--[[
local function print_hex(str)
	if type(str) ~= "string" then error("Wrong type " .. type(str)) end
	for i = 1, #str - 3, 4 do
		local tmp = string.unpack("=I4", str:sub(i, i + 3))
		io.write(string.format("0x%08x", tmp) .. " ")
	end
	if (#str % 4) > 0 then 
		local tmp = string.unpack("=I4", str:sub(-(#str % 4), -1) .. "\0\0\0")
		print(string.format("0x%08x", tmp))
	end
end

local function uint32_to_str(num)
	return string.format("0x%08x", num)
end
--]]

-- some const-value tables

local K_table = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
}

-- Equivalent to below
--[[ 
local K_table = {}
for i = 1, 64 do
	K_table[i] = math.floor(2^32 * math.abs(math.sin(i)))
end
--]]

local padding_buffer = "\x80" .. string.pack("I16I16I16I16", 0x0, 0, 0, 0)

local s_table = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
}

local to_uint32 = function(...)
	local ret = {}
	for k, v in ipairs({...}) do
		ret[k] = v & ((1 << 32) - 1)
	end
	return table.unpack(ret)
end

local left_rotate = function(x, n)
	return (x << n) | ((x >> (32 - n)) & ((1 << n) - 1))
end

local function md5_chunk_deal(md5state, chunk_index)
	if #md5state.state ~= 16 then
		error("Wrong sizes of arguments") 
	end
	local A, B, C, D, end_pos = string.unpack("=I4 =I4 =I4 =I4", md5state.state)
	local a, b, c, d = A, B, C, D
	if end_pos ~= 17 then error("Fail to unpack the states") end
	
	local M = table.pack(string.unpack(
		"=I4=I4=I4=I4 =I4=I4=I4=I4" ..
		"=I4=I4=I4=I4 =I4=I4=I4=I4", 
		md5state.buffer:sub(chunk_index, chunk_index + 63))
	)	
	
	local F, g
	for i = 0, 63 do
	
		if i < 16 then
			F = (B & C) | ((~B) & D)
			g = i
		elseif i < 32 then
			F = (D & B) | (~D & C)
			g = (5 * i + 1) % 16
		elseif i < 48 then
			F = B ~ C ~ D
			g = (3 * i + 5) % 16
		elseif i < 64 then
			F = C ~ (B | ~D)
			g = (7 * i) % 16
		else error("Out of range") end
		
		local tmp = left_rotate((A + F + K_table[i + 1] + M[g + 1]), s_table[i + 1])
		D, C, B, A = to_uint32(C, B, B + tmp, D)
	end
	
	md5state.state = string.pack("I4 I4 I4 I4", to_uint32(a + A, b + B, c + C, d + D))
end


local function Encrypt(md5state)
	local remain_size = #md5state.buffer % 64
	local padding_size = (remain_size < 56 and 56 - remain_size) or 120 - remain_size
	
	local len_buffer = string.pack("=I8", 8 * #md5state.buffer) -- to be added to the buffer tail
	md5state.buffer = md5state.buffer .. (padding_buffer:sub(1, padding_size) .. len_buffer)

	for i = 1, #md5state.buffer, 64 do
		md5_chunk_deal(md5state, i)
	end
	return buffer_to_hex(md5state.state)
end


local function String(str)
	local md5state = {
		state = string.pack("=I4 =I4 =I4 =I4", 
			0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476),
		bit_count = 0, 
		buffer = str 
	}
	return Encrypt(md5state) -- string
end


local function File(filename, mode) 
	mode = mode or "rb"
	local file, _err = io.open(filename, mode)
	if not file then error(_err) end
	local md5state = {
		state = string.pack("=I4 =I4 =I4 =I4", 
			0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476),
		bit_count = 0, 
		buffer = file:read("a")
	}
	return Encrypt(md5state) -- string
end


md5 = { string = String, file = File }

return md5
