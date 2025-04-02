-- Copyright (C) by Yichun Zhang (agentzh)


local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local C = ffi.C
--local setmetatable = setmetatable
--local error = error
local tonumber = tonumber


local _M = { _VERSION = '0.14' }


ffi.cdef[[
typedef unsigned char u_char;

u_char * ngx_hex_dump(u_char *dst, const u_char *src, size_t len);

intptr_t ngx_atoi(const unsigned char *line, size_t n);
]]

local str_type = ffi.typeof("uint8_t[?]")

local BUF_MAX_LEN = 1024
local hex_buf = ffi_new(str_type, BUF_MAX_LEN)
function _M.to_hex(s)
    local len = #s
    local buf_len = len * 2
    local buf
    if buf_len <= BUF_MAX_LEN then
        buf = hex_buf
    else
        buf = ffi_new(str_type, buf_len)
    end
    C.ngx_hex_dump(buf, s, len)
    return ffi_str(buf, buf_len)
end


function _M.ffi_str_to_decimal_array(ffi_str)
    local decimal_array = {}
    for i = 0, #ffi_str - 1 do
        -- 将每个字节转换为十进制值
        decimal_array[i + 1] = ffi_str:byte(i + 1)
    end
    
    return decimal_array
end
-- 将 iv 的 cdata 转换为十进制的 Lua table
function _M.cdata_to_table(cdata, length)
    local tbl = {}
    for i = 0, length - 1 do
        tbl[i + 1] = cdata[i]
    end
    return tbl
end


function _M.atoi(s)
    return tonumber(C.ngx_atoi(s, #s))
end


return _M
