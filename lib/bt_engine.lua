local _M = {}
local ffi = require "ffi"

local lib, loaded,ok
ffi.cdef[[
 int IsCheck(const char *name,const char *buf);
]]

_M.version = "0.1.1"
local function _loadlib()
	if (not loaded) then
		local path=BTWAF_INC..'/bt_engine.so'
		if WAF_SYSTEM=="arm" then 
			path=BTWAF_INC..'/bt_engine_arm.so'
		end
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

function _M.sqli(name,string)
	if (not loaded) then
		if (not _loadlib()) then
			return false,""
		end
	end
	local is_check=lib.IsCheck(name,string)
	if is_check==1 then 
	    return true,"sql"
	elseif is_check==2 then 
	    return true,"rce"
	    
	 else 
	    return false 
	end 
end



return _M