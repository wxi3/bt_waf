local _M = {}
local bit = require "bit"
local ffi = require "ffi"

local ffi_new    = ffi.new
local ffi_string = ffi.string
local lib, loaded
ffi.cdef[[
    typedef signed char GoInt8;
    typedef unsigned char GoUint8;
    typedef short GoInt16;
    typedef unsigned short GoUint16;
    typedef int GoInt32;
    typedef unsigned int GoUint32;
    typedef long long GoInt64;
    typedef unsigned long long GoUint64;
    typedef GoInt64 GoInt;
    typedef GoUint64 GoUint;
    typedef size_t GoUintptr;
    typedef float GoFloat32;
    typedef double GoFloat64;
    typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];
    typedef struct { const char *p; ptrdiff_t n; } _GoString_;

    typedef _GoString_ GoString;

    typedef void *GoMap;
    typedef void *GoChan;
    typedef struct { void *t; void *v; } GoInterface;
    typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;
     GoUint8 PHPDetected(GoString path, GoInt versions);
     GoUint8 XssParse(GoString text);

    struct NadyParse_return {
            GoUint8 r0;
            char* r1;
    };
    struct NadyParse_return NadyParse(GoString data, GoString urlinfo);
]]

local function _loadlib()
	if (not loaded) then
		local path=BTWAF_INC..'/php_engine.so'
		if WAF_SYSTEM=="arm" then 
			path=BTWAF_INC..'/php_engine_arm.so'
		end 
		local ok=false
		ok,lib=pcall(function()
		    return ffi.load(path)
		end)
		if not ok then
		    lib=false
		end
		if (lib) then
			loaded = true
			return true
		else
			return false
		end
	else
		return true
	end
end

function _M.php_detected(string,version)
	if (not loaded) then
		if (not _loadlib()) then
			return false
		end
	end
	if  #string>500*1024 then return false end
    local info = ffi.new("GoString", {string, #string})
	return lib.PHPDetected(info,version)
end

function _M.xss_detected(string)
	if (not loaded) then
		if (not _loadlib()) then
			return false
		end
	end
    local goStr = ffi.new("GoString", {string, #string})
	return lib.XssParse(goStr)
end

function _M.nday_detected(str,urlinfo)
	if (not loaded) then
		if (not _loadlib()) then
			return false
		end
	end
    local data = ffi.new("GoString", {str, #str})
    local url = ffi.new("GoString", {urlinfo, #urlinfo})
    local ret = lib.NadyParse(data,url)
    return ret.r0,ffi.string(ret.r1)
end

return _M
