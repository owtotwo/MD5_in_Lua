-- A MD5-Encryption Library implemented in Lua-5.3

-- Notice that may be it can't not support the big file (>2GB) very well. (Because
-- it should load the whole file in memory at a time.)
-- (But I think you will not encrypt the big file which is larger than 1GB in Lua)
local md5 = {}


-- aux functions
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
--[[
for i = 1, 64 do
	K_table[i] = math.floor(2^32 * math.abs(math.sin(i)))
end
--]]

local s_table = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
}

local to_uint32 = function(...)
	-- return x | ((1 << 32) - 1)
	local ret = {}
	for k, v in ipairs({...}) do
		ret[k] = v & ((1 << 32) - 1)
	end
	return table.unpack(ret)
end

local left_rotate = function(x, n)
--[[
	local func = function(x) return uint32_to_str(to_uint32(x)) end
	x = to_uint32(x)
	local tmp = (1 << (32 - n)) - 1
	local ret = (x << n) | ((x >> (32 - n)) & (tmp))
	print("x = " .. func(x) .. ", n = " .. (n) .. ", ret = " .. func(ret))
	return ret
--]]
	x = to_uint32(x)
	return (x << n) | ((x >> (32 - n)))
end

local function md5_chunk_deal(state_bytestr, chunk_bytestr)
	if (#state_bytestr ~= 16) or (#chunk_bytestr ~= 64) then
		error("Wrong sizes of arguments") 
	end
	local A, B, C, D, end_pos = string.unpack("=I4 =I4 =I4 =I4", state_bytestr)
	local a, b, c, d = A, B, C, D
	if end_pos ~= 17 then error("Fail to unpack the states") end
	
	local M = table.pack(string.unpack("=I4=I4=I4=I4 =I4=I4=I4=I4" ..
		"=I4=I4=I4=I4 =I4=I4=I4=I4", chunk_bytestr))	
	
	local F, g
	for i = 0, 63 do
		print("Round " .. (i + 1))
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
		
		local tmp = D
		D = C
		C = B
		print("Before deal --> " .. uint32_to_str(to_uint32(B)))
		
		local B_tmp = (A + F + K_table[i + 1] + M[g + 1])
		print("Temp deal --> " .. uint32_to_str(to_uint32(B_tmp)))
		B = B + left_rotate(B_tmp, s_table[i + 1])
		
		print("After deal --> " .. uint32_to_str(to_uint32(B)))
		print(" --> A = " .. uint32_to_str(A))
		print(" --> F = " .. uint32_to_str(F))
		print(" --> K_table[i + 1] = " .. uint32_to_str(K_table[i + 1]))
		print(" --> M[g + 1] = " .. uint32_to_str(M[g + 1]))
		print(" --> s_table[i + 1] = " .. s_table[i + 1])
		print(" --> Sum = " .. uint32_to_str(to_uint32(B)))
		A = tmp
		
		-- D, C, B, A = C, B, left_rotate(), A
		
		A, B, C, D = to_uint32(A, B, C, D)
		--[[
		print("A = " .. uint32_to_str(A))
		print("B = " .. uint32_to_str(B))
		print("C = " .. uint32_to_str(C))
		print("D = " .. uint32_to_str(D))
		--]]
	end
		A, B, C, D = to_uint32(a + A, b + B, c + C, d + D)
		print("A = " .. uint32_to_str(A))
		print("B = " .. uint32_to_str(B))
		print("C = " .. uint32_to_str(C))
		print("D = " .. uint32_to_str(D))
	return string.pack("=I4 =I4 =I4 =I4", A, B, C, D)
end

-- md5.string("a") --> 0cc175b9c0f1b6a831c399e269772661
function md5.string(bytestr)
	bytestr = bytestr or ""
	local md5state = {
		state = string.pack("=I4 =I4 =I4 =I4", 
			0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476),
		bit_count = 0, 
		buffer = string.pack("I4I4I4I4 I4I4I4I4 I4I4I4I4 I4I4I4I4",
			0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) -- 64 bytes
	}
	
	result = md5_chunk_deal(md5state.state, md5state.buffer)
	return result
end

print("Over")
print_hex(md5.string())
return md5
