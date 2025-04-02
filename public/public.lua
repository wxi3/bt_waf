local public = {}
local ffi = require("ffi")

local ck = require "new_cookie"
local ipmatcher =require "ipmatcher"
local is_type = ""
local error_rule = ""
local server = require "websocket.server"

-- cffi相关函数开始
ffi.cdef [[
    typedef struct DIR DIR;
    struct dirent {
        uint64_t      d_ino;
        int64_t       d_off;
        unsigned short d_reclen;
        unsigned char  d_type;
        char           d_name[];
    };


    DIR *opendir(const char *name);
    struct dirent *readdir(DIR *dirp);
    int closedir(DIR *dirp);
    int mkdir(const char *path, int mode);

    typedef unsigned int uid_t;
    typedef unsigned int gid_t;

    int chown(const char *path, uid_t owner, gid_t group);
	int access(const char *pathname, int mode);

    struct passwd {
        char *pw_name;
        char *pw_passwd;
        uid_t pw_uid;
        gid_t pw_gid;
        // 其他字段省略，可以根据实际需要添加
    };
    struct passwd *getpwnam(const char *name);

    typedef long time_t;
    typedef struct timeval {
        time_t tv_sec;
        time_t tv_usec;
    } timeval;

    typedef struct in6_addr {
        union {
            uint8_t u6_addr8[16];
            uint16_t u6_addr16[8];
            uint32_t u6_addr32[4];
        } in6_u;
    } in6_addr;

    int inet_pton(int af, const char *src, void *dst);

    int gettimeofday(struct timeval *tv, void *tz);
]]

--判断文件是否存在
function public.os_file_exists(filename)
    -- access 函数返回0表示成功，文件存在
    return ffi.C.access(filename, 1) == 0
end


--获取CPU的核心数量
function public.get_num_procs()
    local file = io.popen("nproc")
    if file==nil then return 1 end
    local output = file:read("*a")
    file:close()
    local num_cores = tonumber(output) or 1
    return num_cores
end



--获取毫秒时差
function public.getMilliseconds()
    local tv = ffi.new("struct timeval")
    ffi.C.gettimeofday(tv, nil)
    return tonumber(tv.tv_sec) * 1000 + tonumber(tv.tv_usec) / 1000
end

--计算某个函数的毫秒数
function public.measureTime(func,name)
    local startTime = public.getMilliseconds()
    for i=1,1 do
        func()
    end 
    local endTime = public.getMilliseconds()
    local elapsedTime = endTime - startTime
    public.logs("函数:"..name.." 执行1W次的时间为: "..tostring(elapsedTime).." 毫秒")
    return elapsedTime
end


-- 设置文件或目录的所有者和组
-- @param path 文件或目录路径
-- @param owner 用户ID
-- @param group 组ID
-- @return 是否成功设置所有者和组
function public.chown(path, owner, group)
    local result = ffi.C.chown(path, owner, group)
    if result == 0 then
        return true
    else
        return false
    end
end

--判断文件是否存在
--@param path 文件路径
--@return true or false
function public.file_exists(path)
    local file = io.open(path, "r")
    if file then
        io.close(file)
        return true
    end
    return false
end


-- 根据用户名获取用户的UID
-- @param username 用户名
-- @return 用户的UID，如果用户不存在则返回nil
function public.getUIDByUsername(username)
    local passwdStruct = ffi.C.getpwnam(username)
    if passwdStruct ~= nil then
        local uid = tonumber(passwdStruct.pw_uid)
        return uid
    else
        return nil
    end
end


-- 新建目录
-- @param path 目录路径
-- @return true or false
function public.mkdir(path)
    local result = ffi.C.mkdir(path, tonumber("755", 8))  -- 755权限，表示读写执行权限
    if result == 0 then
        return true
    else
        return false
    end
end



--获取文件夹下的所有文件
--@param path 文件夹路径
--@return 文件列表
function public.isdir(path)
    local dir_list = {}
    -- Open a directory
    local dir = ffi.C.opendir(path)
    if dir == nil then
        return false
    end
    ffi.C.closedir(dir)
    return true
end 

-- cffi相关函数结束

--获取文件夹下的所有文件
--@param path 文件夹路径
--@return 文件列表
function public.listdir(path)
    local dir_list = {}
    local dir = ffi.C.opendir(path)
    if dir == nil then
        return dir_list
    end
    local entry = ffi.C.readdir(dir)
    while entry ~= nil do
        local entryName = ffi.string(entry.d_name)
        if entryName ~= "." and entryName ~= ".." then
            table.insert(dir_list, entryName)
        end
        entry = ffi.C.readdir(dir)
    end
    ffi.C.closedir(dir)
    return dir_list
end


-- 遍历/www/server 目录判断是否存在monitor 目录
function public.is_monitor()
    -- 判断缓存中是否存在
    if ngx.shared.btwaf:get("is_monitor") and ngx.shared.btwaf:get("is_monitor")=="1" then
        return true
    end
    local server_list = public.listdir("/www/server")
    for _, v in ipairs(server_list) do
        if v == "monitor" then
            ngx.shared.btwaf:set("is_monitor", "1")
            return true
        end
    end
    ngx.shared.btwaf:set("is_monitor", "0")
    return false
end


-- 追加文件内容
-- @param filename 文件名
-- @param body 内容
-- @return true or false
function public.append_file(filename, body)
    local fp = io.open(filename, "a+")
    if fp == nil then
        return nil
    end
    fp:write(body)
    fp:flush()
    fp:close()
    return true
end

-- 日志写入
-- @param ... 内容
-- @return true or false
function public.logs(...)
    local data = "[" .. os.date("%Y-%m-%d %H:%M:%S") .. "]"
    for _, v in ipairs({...}) do
        if type(v) == "table" then -- 如果是table，尝试格式化输出
            Json.encode_sparse_array(true, 1)
            data = data .. "\n" .. tostring(v) .. ": \n" .. public.PrintTable(v)
        else
            data = data .. " " .. tostring(v)
        end
    end
    local log_file = "/www/wwwlogs/btwaf_debug.log"
    public.append_file(log_file, data .. "\n")
end


--ip转为整数
--@param ip ip地址
--@return 整数
function public.ip2long(ip)
    local num = 0
    if ip and type(ip) == "string" then
        local o1, o2, o3, o4 = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
        if o1 == nil or o2 == nil or o3 == nil or o4 == nil then
            return 0
        end
        num = 2 ^ 24 * o1 + 2 ^ 16 * o2 + 2 ^ 8 * o3 + o4
    end
    return num
end

-- 整数转为IP
function public.long2ip(long)
    local floorList = {}
    local yushu = long
    for i = 3, 0, -1 do
        local res = math.floor(yushu / (256 ^ i))
        table.insert(floorList, tonumber(res))
        yushu = yushu - res * 256 ^ i
    end
    return table.concat(floorList, ".")
end


-- 验证是否为127.0.0.1
-- @param ip ip地址
-- @return true or false
function public.is_localhost(ip)
    if not ip then
        return false
    end
    if ip == "unknown" then
        return false
    end
    if public.find_str(ip, ":") then
        return false
    end
    local ip_nmber = public.ip2long(ip)
    if ip_nmber == 0 then
        return false
    end
    if ip_nmber >= 2130706433 and ip_nmber <= 2130706687 then
        return true
    end
    return false
end


--判断是否是内网地址
--@param ip ip地址
--@return true or false
function public.is_internal_ip(ips)
    if not ips then
        return false
    end
    if ips == "unknown" then
        return false
    end
    if public.find_str(ips, ":") then
        return false
    end
    local ip_nmber = public.ip2long(ips)
    if ip_nmber == 0 then
        return false
    end
    -- 192.168.0.1 到192.168.255.255
    if ip_nmber >= 3232235520 and ip_nmber <= 3232301055 then
        return true
    end
    -- 172.16.0.0  到172.16.255.255
    if ip_nmber >= 2886729728 and ip_nmber <= 2887843839 then
        return true
    end
    -- 10.0.0.1   到 10.255.255.255
    if ip_nmber >= 167772161 and ip_nmber <= 184549375 then
        return true
    end
    return false
end


-- 返回json格式数据
-- @param status 状态码
-- @param msg 返回信息
function public.return_message(status, msg)
    ngx.header.content_type = "application/json;"
    ngx.header.Cache_Control = "no-cache"
    ngx.status = status
    ngx.say(Json.encode(msg))
    ngx.exit(status)
end

-- 返回html格式数据
-- @param status 状态码
-- @param html 返回html
function public.return_html(status, html)
    ngx.header.content_type = "text/html"
    ngx.header.Cache_Control = "no-cache"
    ngx.status = status
    if ngx.ctx.header_btwaf==nil then 
        ngx.say(html)
    end 
    ngx.exit(status)
end

--统一返回格式
--@param status 状态码
--@param msg 返回信息
function public.get_return_state(status, msg)
    local result = {}
    result["status"] = status
    result["msg"] = msg
    return result
end

function public.read_file_body(filename)
	if filename==nil then return nil end
	local fp = io.open(filename,'r')
	if fp == nil then
        return nil
	end
	local fbody = fp:read("*a")
    fp:close()
    if fbody == '' then
        return nil
    end
	return fbody
end

function public.read_file_body_rb(filename)
	if filename==nil then return nil end
	local fp = io.open(filename,'rb')
	if fp == nil then
        return nil
	end
	local fbody = fp:read("*a")
    fp:close()
    if fbody == '' then
        return nil
    end
	return fbody
end
function public.read_file(name)
    local fbody = public.read_file_body(BTWAF_RUN_PATH.."/rule/" .. name .. '.json')
    if fbody == nil then
        return {}
    end
    --判断Json格式是否正确
    local status, result = pcall(Json.decode, fbody)
    if status then
        return result
    end
    return {}
end


function public.re_png(filename)
	local fp = io.open(filename,'rb')
	if fp == nil then
        return nil
    end
	local fbody = fp:read("*a")
    fp:close()
    if fbody == '' then
        return nil
    end
	return fbody
end

function public.write_file(filename,body)
	local fp = io.open(filename,'w')
	if fp == nil then
        return nil
    end
	fp:write(body)
	fp:flush()
	fp:close()
	return true
end

-- 搜索字符串(非匹配模式)
-- @param str 字符串
-- @param find_str 查找的字符串
-- @return bool
function public.find_str(str, find_str)
    if not str or not find_str then
        return false
    end
    local s, e = string.find(str, find_str, 1, true)
    if s and e then
        return true
    end
    return false
end

-- 验证是否为IPV4的地址
-- @param ip ip地址
-- @return true or false
function public.is_ipv4(ip)
    local pattern = "^(%d+)%.(%d+)%.(%d+)%.(%d+)$"
    local a, b, c, d = ip:match(pattern)
    if not (a and b and c and d) then
        return false
    end
    if tonumber(a) > 255 or tonumber(b) > 255 or tonumber(c) > 255 or tonumber(d) > 255 then
        return false
    end
    return true
end

--验证是否为IPV6的地址
--@param ip ip地址
--@return true or false
function public.is_ipv6(ip)
    local ipv6_addr = ffi.new("in6_addr")
    local result = ffi.C.inet_pton(10, ip, ipv6_addr)

    return result == 1
end

--判断是否为IP格式
function public.is_ip(ip)
    if public.is_ipv4(ip) then
        return true
    end
    if public.is_ipv6(ip) then
        return true
    end
    return false    
end

--判断是否为IP格式
function public.is_ipaddr(client_ip)
    if public.find_str(client_ip, ":") then
        return true
    end
    if public.is_ipv4(client_ip) then
        return true
    end
    return false
end

-- 字符串分割
-- @param string 字符串
-- @param reps 分割符
-- @return 分割后的字符串列表
function public.split(string, reps)
    if string == nil or string == "" or reps == nil then
        return nil
    end
    local result = {}
    for match in (string .. reps):gmatch("(.-)" .. reps) do
        table.insert(result, match)
    end
    return result
end


-- 取ngx.var.request_uri 不带参数的值
function public.get_request_uri()
    --返回的是字符串
    local uri = ngx.var.request_uri
    if uri==nil then return "/" end
    uri=uri:gsub('//+', '/')
    if uri==ngx.var.uri then return uri end
    --通过byte
    for i = 1, #uri do
        local byte = uri:byte(i)
        if byte == 63 then
            return uri:sub(1, i - 1)
        end
    end
    return uri
end

-- 取ngx.var.request_uri 不带参数的值
function public.get_request_uri_static(uri)
    local static={"css","js","png","gif","ico","jpg","jpeg","bmp","flush","swf","pdf","rar","zip","doc","docx","xlsx","gz","7z","tar","mp3","mp4","bz2"}

    ngx.ctx.suffix=""
    for i = #uri, #uri-6,-1 do
        local byte = uri:byte(i)
        if byte == 46 then
            ngx.ctx.suffix=uri:sub(i+1,#uri)
            break
        end
    end
    if static[ngx.ctx.suffix] then
        return false
    end

    return true
end



-- 字符串分割  【适用于复杂的字符粗分割-性能差】
-- @param string 字符串
-- @param reps 分割符
-- @return 分割后的字符串列表
function public.split2(input, delimiter)
    input = tostring(input)
    delimiter = tostring(delimiter)
    if (delimiter=='') then return false end
    local pos,arr = 0, {}
    for st,sp in function() return string.find(input, delimiter, pos, true) end do
        table.insert(arr, string.sub(input, pos, st - 1))
        pos = sp + 1
    end
    table.insert(arr, string.sub(input, pos))
    return arr
end


function public.get_server_name_waf()
	local c_name = ngx.var.server_name
	local my_name = ngx.shared.btwaf:get(c_name)
	if my_name then return my_name end
    if c_name =='_' then 
	    c_name="未绑定域名"
	end
	local tmp = public.read_file_body(BTWAF_RUN_PATH .. '/domains.json')
	if not tmp then return c_name end
	local domains = Json.decode(tmp)
	for _,v in ipairs(domains)
	do
		for _,d_name in ipairs(v['domains'])
		do
			if c_name == d_name then
				ngx.shared.btwaf:set(c_name,v['name'],3600)
				return v['name']
			end
		end
	end
    if c_name =='127.0.0.1' then 
        ngx.shared.btwaf:set(c_name,"127.0.0.1",3600)
    end 
	return c_name
end

function public.arrlen(arr)
	if not arr then return 0 end
	local count = 0
	for _,v in pairs(arr)
	do
		count = count + 1
	end
	return count
end

-- 只需要判断是否存在 长度是否大于0
function public.is_len(arr)
	if not arr then return 0 end
	local count = 0
	for _,v in pairs(arr)
	do
		count = count + 1
        break
	end
	return count
end

function public.count_sieze(data)
    local count=0
    if type(data)~="table" then return count end 
	for _,v in pairs(data) 
	do
	    count=count+1
	end 
	return count
end 

--获取规则列表
--@param rule_info 规则信息
--@return 规则列表
function public.select_rule(rules)
    if not rules then
        return {}
    end
    local new_rules = {}
    for _, v in ipairs(rules) do
        if v[1] == 1 then
            table.insert(new_rules, v[2])
        end
    end
    return new_rules
end

function public.select_rule_args(rules)
	if not rules then return {} end
	local new_rules = {}
	for i,v in ipairs(rules)
	do 
		if v[1] == 1 then
		    local new_rules2 = {}
		    table.insert(new_rules2,v[2])
		    table.insert(new_rules2,v[3])
		    if v[5]~=nil then 
		        table.insert(new_rules2,v[5])
		    else
		        table.insert(new_rules2,100)
		    end
			table.insert(new_rules,new_rules2)
		end
	end
	return new_rules
end



function public.is_site_config(cname)
	if Site_config[ngx.ctx.server_name] ~= nil then
		if cname == 'cc' then
			return Site_config[ngx.ctx.server_name][cname]['open']
		else
			return Site_config[ngx.ctx.server_name][cname]
		end
	end
	return true
end

--获取表长度
--@param data 表
--@return 长度
function public.len(data)
    local count = 0
    if type(data) ~= "table" then
        return count
    end
    for k, v in pairs(data) do
        count = count + 1
    end
    return count
end


function public.ip_count_check()
	if ngx.shared.spider:get(ngx.ctx.ip) then return false end
    if not ngx.ctx.cc_ip_max_status then return false end
    if ngx.ctx.cc_ip_max==nil then return false end
    if ngx.ctx.cc_ip_max_static==nil then return false end
    if ngx.ctx.uri=="/" then return false end
    local ip=ngx.ctx.ip
    local ipcount=ngx.shared.ip:get(ip)
    if not ipcount then 
        ngx.shared.ip:set(ip,2,86400)
        ipcount=1
    else 
        ngx.shared.ip:incr(ip,1)
    end
    local cc_ip_max=2000 
    if ngx.ctx.cc_ip_max>2000 then cc_ip_max=ngx.ctx.cc_ip_max end
    if ngx.ctx.cc_ip_max_static and cc_ip_max<5000 then cc_ip_max=5000 end
    if ipcount>cc_ip_max then 
   		local safe_count,_ = ngx.shared.drop_sum:get(ip)
		if not safe_count then
			ngx.shared.drop_sum:set(ip,2,86400)
			safe_count = 1
		else
			ngx.shared.drop_sum:incr(ip,1)
		end
		local lock_time = (ngx.ctx.endtime * safe_count)
		if lock_time > 86400 then lock_time = 86400 end
		ngx.shared.drop_ip:set(ip,ngx.ctx.retry+1,lock_time)
		IpInfo.bt_ip_filter(ip,lock_time)
		ngx.ctx.is_type='cc'
		local msg="单IP防护"..'一天内内累计超过'..cc_ip_max..'次请求,封锁' .. lock_time .. '秒'
		if ngx.ctx.cc_ip_max_static then 
		    msg=msg.."(包括所有静态资源)"
		end 
		IpInfo.write_log('cc',msg)
		IpInfo.write_drop_ip('cc',lock_time,msg)
    end 
end 

function public.is_static()
    if ngx.ctx.method=="GET" then 
		if Config['static_cc']~=nil and Config['static_cc']==true then return false end
        if ngx.shared.btwaf_data:get(ngx.md5(ngx.ctx.uri)) then
            if ngx.ctx.cc_ip_max_status==true and ngx.ctx.cc_ip_max_static==true then public.ip_count_check() end 
            return true
        end
        if  ngx.re.find(ngx.ctx.uri,"\\.(js|css|gif|jpg|jpeg|png|bmp|swf|ico|woff|woff2|webp|mp4|mp3)$","isjo") then 
            ngx.shared.btwaf_data:set(ngx.md5(ngx.ctx.uri), 1, 3600)
            return true
        end
    end
    if ngx.ctx.cc_ip_max_status==true then public.ip_count_check() end
    return false
end

function public.return_html_body(title, t1, li, l2)
    local html_data = public.read_file_body(BTWAF_RUN_PATH .. "/html/default_return.html")
    local check_html, _ = string.gsub(html_data, "{{title}}", title)
    check_html, _ = string.gsub(check_html, "{{t1}}", t1)
    check_html, _ = string.gsub(check_html, "{{li}}", li)
    check_html, _ = string.gsub(check_html, "{{l2}}", l2)
    return check_html
end


function public.return_html_data(title, t1, li, l2)
    local html_data = public.read_file_body(BTWAF_RUN_PATH .. "/html/default_return.html")
    ngx.status = 403
    ngx.header.content_type = "text/html;charset=utf8"
    ngx.header.Cache_Control = "no-cache"
    local check_html, _ = string.gsub(html_data, "{{title}}", title)
    check_html, _ = string.gsub(check_html, "{{t1}}", t1)
    check_html, _ = string.gsub(check_html, "{{li}}", li)
    check_html, _ = string.gsub(check_html, "{{l2}}", l2)
    ngx.say(check_html)
    ngx.exit(403)
end

function public.is_ssl()
    if(ngx.re.match(ngx.ctx.request_uri,'^/.well-known/pki-validation/',"jo")) then return true end 
    if(ngx.re.match(ngx.ctx.request_uri,'^/.well-known/acme-challenge/',"jo")) then return true end    
end 

-- Cookie转为table
-- @return cookie table
function public.getcookie()
    local cookie, _ = ck:new()
    if not cookie then
        return nil
    end
    if cookie:get_cookie_size()==0 then
        return nil 
    end 
    return cookie
end


function public.process_json_args(json_args, t)
    if type(json_args) ~= "table" then
        return {}
    end
    local t = t or {} 
    for k, v in pairs(json_args) do
        if type(v) == "table" then
            for _k, _v in pairs(v) do
                if type(_v) == "table" then
                    t = public.process_json_args(_v, t)
                else
                    if type(t[k]) == "table" then
                        table.insert(t[k], _v)
                    elseif type(t[k]) == "string" then
                        local tmp = {}
                        table.insert(tmp, t[k])
                        table.insert(tmp, _v)
                        t[k] = tmp
                    else
                        t[k] = _v
                    end
                end
            end
        else
            if type(t[k]) == "table" then
                table.insert(t[k], v)
            elseif type(t[k]) == "string" then
                local tmp = {}
                table.insert(tmp, t[k])
                table.insert(tmp, v)
                t[k] = tmp
            else
                t[k] = v
            end
        end
    end
    return t
end

function public.de_dict (l_key,l_data)
	if type(l_data) ~= "table" then return l_data end
	if public.arrlen(l_data) == 0 then return l_data end
	if not l_data then return false end
	local r_data = {}
	if public.arrlen(l_data) >= 8000 then 
	    ngx.ctx.is_type='参数过多'
		IpInfo.lan_ip('sql','非法请求')
		return true
	end
	for li,lv in pairs(l_data)
	do
		r_data[l_key..tostring(li)] = lv
	end
	return r_data
end


-- 获取今天开始时间戳
-- @return timestamp int 时间戳
function public.get_today_start_time()
	local start_time=ngx.shared.spider:get("get_today_start_time") 
	if start_time then return public.int(start_time) end
    local date_time = os.date("*t")
    date_time.hour = 0
    date_time.min = 0
    date_time.sec = 0
	local start_time=os.time(date_time)
	if tonumber(Hour)<23 then 
		ngx.shared.spider:set("get_today_start_time",start_time,1800)
	elseif tonumber(Hour)==23 and tonumber(Minute)<50 then 
		ngx.shared.spider:set("get_today_start_time",start_time,60)
	else 
		ngx.shared.spider:set("get_today_start_time",start_time,5)
	end
    return start_time
end

-- 获取今天结束时间戳
-- @return timestamp int 时间戳
function public.get_today_end_time()
    return public.get_today_start_time() + 86400
end

-- 指定统计值+1
-- @param string server_name  网站名称
-- @param string key  缓存key
-- @param int num 增加的值
-- @param int expire 过期时间(秒)
-- @return void
function public.logs_incr(server_name, key, num, expire)
    if not server_name or not key or not num then
        return
    end
    key = server_name .. "_" .. key
    local val = ngx.shared.uri_total:get(key)
    if val == nil then
        ngx.shared.uri_total:set(key, 0, expire)
    end
    ngx.shared.uri_total:incr(key, num)
    --获取统计值
end

-- 指定统计值+1
-- @param string server_name  网站名称
-- @param string key  缓存key
-- @param int num 增加的值
-- @param int expire 过期时间(秒)
-- @return void
function public.logs_get(server_name, key)
    if not server_name or not key then
        return
    end
    key = server_name .. "_" .. key
    local val = ngx.shared.uri_total:get(key)
    if val == nil then
        val = 0
    end
    return val
end




-- 获取缓存
-- @param string key
-- @return int
function public.get_cache(server_name,key)
    if not key then return end
    local skey = server_name .. '_status_' .. key
    local res =  ngx.shared.uri_total:get(skey)
    if res == nil then
        res = 0
    end
    return res
end


-- 获取锁
-- @param string key 锁的key
-- @return bool
function public.is_lock(key)
    -- 获取锁
    local lock_key = "lock_" .. key
    return ngx.shared.uri_total:add(lock_key, 1, 0.5)
end


-- 获取锁
-- @param string key 锁的key
-- @return bool
function public.is_lock_end(key,expire)
    -- 获取锁
    local lock_key = "lock_" .. key
    return ngx.shared.uri_total:add(lock_key, 1, expire)
end


-- 获取前1分钟
-- @return string 分钟数
function public.get_pre_minute()
    local time = os.time()
    local tmp_str = os.date("%Y-%m-%d %H:%M", time - 60)
    local tmp_arr = public.split(tmp_str, " ")
    local day = tmp_arr[1]
    local tmp_arr2 = public.split(tmp_arr[2], ":")
    local hour = tmp_arr2[1]
    local minute = tmp_arr2[2]
    return day, tonumber(hour), tonumber(minute)
end


function public.insert_request_total()
    local lock_key = 'public.insert_request_total'
    local lock = public.is_lock_end(lock_key,30)
    if not lock then
        return
    end
    Database.ReportInsert()
end

-- 取整数
-- @param num number 要处理的数值
-- @return number 处理后的数值
function public.int(num)
    if num ~= num then
        return 0
    end
    return math.floor(num)
end

function public.get_html(ip,user_agent,server_name,today)
    local token = ngx.md5(ip..user_agent.."browser"..server_name..today)
	local count,_ = ngx.shared.btwaf:get(token)
	if count then
	    local retry=5
	    if Config['retry']>5 then 
	        retry=Config['retry']
	    end 
		if count > retry then
			local safe_count,_ = ngx.shared.drop_sum:get(ip)
			if not safe_count then
				ngx.shared.drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.drop_sum:incr(ip,1)
			end
			local lock_time = (Config['retry_time'] * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.drop_ip:set(ip,retry+1,lock_time)
			ngx.ctx.is_type='cc'
			ngx.shared.btwaf:delete(token)
            IpInfo.lan_ip('cc','攻击浏览器验证')
		else
			ngx.shared.btwaf:incr(token,1)
		end
	else
		ngx.shared.btwaf:set(token,1,Config['retry_cycle'])
	end
    local jsbody= string.format([[
        <!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
        <script src="/Rxizm32rm3CPpyyW_fingerprint2daasdsaaa.js?id=%s%s"></script>
        <script>
        var options={preprocessor:null,audio:{timeout:1000,excludeIOS11:true},fonts:{swfContainerId:'fingerprintjs2',swfPath:'flash/compiled/FontList.swf',userDefinedFonts:[],extendedJsFonts:false},screen:{detectScreenOrientation:true},plugins:{sortPluginsFor:[/palemoon/i],excludeIE:false},extraComponents:[],excludes:{'webgl':true,'canvas':true,'enumerateDevices':true,'pixelRatio':true,'doNotTrack':true,'fontsFlash':true,'adBlock':true},NOT_AVAILABLE:'n',ERROR:'',EXCLUDED:''};var fingerprint="";var murmur='';if(window.requestIdleCallback){requestIdleCallback(function(){Fingerprint2.get(options,function(components){var values=components.map(function(component){return component.value});murmur=Fingerprint2.x64hash128(values.join(''),31);sendWafValida()})})}else{setTimeout(function(){Fingerprint2.get(options,function(components){var values=components.map(function(component){return component.value});murmur=Fingerprint2.x64hash128(values.join(''),31);sendWafValida()})},500)};function sendWafValida(){var key='%s',value='%s',newWord='',newVal='';for(var i=0;i<murmur.length;i++){var _mur=String.fromCharCode(murmur.charAt(i).charCodeAt()-1);newWord+=_mur}for(var j=0;j<value.length;j++){var _val=String.fromCharCode(value.charAt(j).charCodeAt()+1);newVal+=_val};var url='/Rxizm32rm3CPpyyW_yanzheng_ip.php?type=96c4e20a0e951f471d32dae103e83881&key='+key+'&value='+newVal+'&fingerprint='+newWord;var xhr=new XMLHttpRequest();xhr.open('post',url);xhr.onreadystatechange=function(){if(xhr.readyState===4&&xhr.status===200){setTimeout(function(){location.reload()},3000)}};xhr.send()};
        </script>
    </body>
</html>]],ngx.md5(ip),os.time(),ngx.md5(ip),ngx.md5(user_agent))
    return jsbody
end 


-- 获取锁
-- @param string key 锁的key
-- @return bool
-- function public.is_lock(key)
--     -- 获取锁
--     local lock_key = "lock_" .. key
--     return ngx.shared.spider:add(lock_key, 1, 0.5)
-- end

-- 尝试加锁
-- @param string key        锁名称
-- @param number timeout    超时时间
function public.try_lock(key, timeout)
    -- 默认超时时间500ms
    if timeout == nil then
        timeout = 0.5
    end

    return ngx.shared.spider:add('lock_'..key, 1, timeout)
end

-- 释放锁
-- @param string key
-- @return void
function public.un_lock(key)
    local lock_key = "lock_" .. key
    ngx.shared.spider:delete(lock_key)
end



-- 记录规则命中日志
-- @param string status         状态    1:拦截   0:放行
-- @param string key            规则key(规则唯一id标识)
-- @param string timestimp      命中时间戳
-- @param string server_name    域名(网站名)
-- @param string uri            uri
-- @param string rule_name      规则名称
-- @param string rule_ps        规则描述(命中规则详情)
-- @param string ip             访问IP
function public.log_rule_hit(status, key, timestamp, rule_name, rule_ps, server_name, uri, ip)
    if server_name=="127.0.0.251" then return false end 
	if timestamp==nil then 
        timestamp=tonumber(ngx.now())
    end
	timestamp = math.floor(timestamp)

    -- 同一个网站下 60s内一个规则对应的相同uri ip只记录一次  
    local keys =  ngx.md5(server_name .. rule_ps.. ip..status)
    local keyword = ngx.shared.btwaf_data:get(keys)
    if keyword then
        return
    end
    ngx.shared.btwaf_data:set(keys, 1, 30)
    local country  = ngx.ctx.country
    local province =ngx.ctx.ip_province
    local city=ngx.ctx.ip_city
    if city==nil then city="" end 
    if province==nil then province="" end 
    if country==nil then country="" end 
    -- 查找状态
    local status_name = ""
    if status == 0 then
        status_name = "放行"
    elseif status == 1 then
        status_name = "拦截"
    elseif status == 2 then
        status_name = "人机验证"
    elseif status == 3 then
        status_name = "仅记录"
    end

    local mapping = {
        ["IP白名单"] = 1,
        ["IP黑名单"] = 2,
        ["URI白名单"] = 3,
        ["URI黑名单"] = 4,
        ["UA白名单"] = 5,
        ["UA黑名单"] = 6,
        ["地区限制"] = 7,
        ["人机验证"] = 8,
        ["云端恶意IP库"] = 9,
        ["网站后台入口保护"] = 10,
        ["自定义拦截"] = 11,
        ["内容替换"] = 12,
        ["自定义CC防御"] = 13,
        ["蜘蛛拦截"] = 14
    }

    -- 判断是否可以记录
    if BTWAF_RULES.rule_hit_list == nil then
        return
    end
    if BTWAF_RULES.rule_hit_list[rule_name] == nil or BTWAF_RULES.rule_hit_list[rule_name] == false then
        return
    end
    
    -- 获取规则对应序号 有对应的序号才记录日志
    local rule_type = 0
    if mapping[rule_name] then
        
        rule_type = mapping[rule_name]
        local log_data = ""
        log_data = status_name.."|"..key.."|"..timestamp.."|"..server_name.."|"..uri.."|"..rule_name.."|"..rule_type.."|"..rule_ps.."|"..ip.."|"..country.."|"..province.."|"..city
        public.enqueue(log_data)
       
    end
end

-- 将规则命中日志加入队列
function public.enqueue(data)
    local queue_key = "btwaf_rule_hit_queue"
    local max_queue_size = 2000
    local shared_dict = ngx.shared.btwaf_data
    local count_size = shared_dict:rpush(queue_key, data)
    if type(count_size) ~= "number" then
        return
    end
    if not ngx.shared.spider:get("rule_hit_queue_size") then
        ngx.shared.spider:set("rule_hit_queue_size", count_size, 120)
    end
    if count_size == nil then return end
    if count_size > max_queue_size then
        shared_dict:lpop(queue_key)
    end
end


function public.getFileSize(filePath)
    local file = io.open(filePath, "r")
    if not file then
        return 0
    end
    local size = file:seek("end")
    file:close()
    return size
end


function public.flush_rule_hit_log()
    ngx.sleep(1) -- 减少抢占冲突
    -- 锁名称
    local lock_key = 'workers.flush_rule_hit_log'
    -- 尝试加锁
    if not public.try_lock(lock_key, 30) then
        return
    end
    if not ngx.shared.spider:get("rule_hit_queue_size") then 
        return 
    end
    local queue_key = "btwaf_rule_hit_queue"
    local shared_dict = ngx.shared.btwaf_data
	local data = ""
	local num = 0
    -- 从队列的头部获取数据
    for i = 1, 2000 do
        local serialized_data, err = shared_dict:lpop(queue_key)
        if err ~= nil or serialized_data == nil then
            break
        end
        serialized_data = serialized_data .. "\n"
        num = num + 1
        data = data .. serialized_data
    end
    -- 如果为空 不写入
    if #data == 0 then
        -- 释放锁
        public.un_lock(lock_key)
        return
    end
	if num >= 2000 then
        public.write_file(BTWAF_RUN_PATH..'/btwaf_rule_hit.json', data)
        -- 释放锁
        public.un_lock(lock_key)
        return
	end
	public.append_file(BTWAF_RUN_PATH..'/btwaf_rule_hit.json', data)
	local file_site=public.getFileSize(BTWAF_RUN_PATH..'/btwaf_rule_hit.json')
    if file_site>512000 then 
        public.write_file(BTWAF_RUN_PATH..'/btwaf_rule_hit.json', data)
    end 
    -- 释放锁
    public.un_lock(lock_key)
end

function public.city_join(reg)
    if type(reg)~='table' then 
        return ''
    end 
    local info=""
    local count=0
    for i,_ in pairs(reg) 
    do  
        if count>0 then 
            i=","..i
        end 
        count=count+1
        info=info..i
    end 
    return info
end 

-- 处理小数点后保留几位 -- 四啥五入
-- @param val  number 要处理的数值
-- @param num number 保留位数
-- @return number 处理后的数值
function public.round(val, num)
    -- 如果为NAN则返回0
    if val ~= val then
        return 0
    end
    -- 默认保留2位小数
    local mult = 10 ^ (num or 2)
    return math.floor(val * mult + 0.5) / mult
end


-- 获取智能CC默认配置
-- @return table {
--     status int 拦截状态码，默认444
--     open bool 是否开启，默认开启
--     max_avg_proxy_time int 触发CC防御最大平均回源时间，默认200ms
--     max_err_count int 触发CC防御的最大错误次数，默认10次
--     max_qps int 只有QPS大于这个值才会触发CC防御，默认10
--     expire int 过期时间，默认120秒
--     ip_drop_time int 拦截IP的时间，默认360秒
--     ps string 描述
-- }
function public.get_default_smart_cc_config()
    local smart_cc = {}
    --针对499做一下特别优化
    local max_err_count=5
    local max_qps=10
    local expire=10
    if WAF_CPU_CORES<=2 then 
        max_qps=5
    end 
    if WAF_CPU_CORES <4 then
        max_err_count=5
        expire=15
        --核心数大于4小于8 错误为20
    elseif WAF_CPU_CORES>4  and WAF_CPU_CORES<8 then
        max_err_count=30
        expire=20
        --核心数大于8 小于16 的时候为50
    elseif WAF_CPU_CORES>8 and WAF_CPU_CORES<16 then
        max_err_count=50
        expire=30
        --大于16的时候为80
    elseif WAF_CPU_CORES>16 then
        max_err_count=80
        expire=30
    end
    smart_cc["status_count_499"]=max_err_count
    smart_cc["status"] = 444
    smart_cc["open"] = true
    smart_cc["max_avg_proxy_time"] = 2000
    smart_cc["max_err_count"] = 5
    smart_cc["expire"] = 30
    smart_cc["max_qps"] = max_qps
    smart_cc["ip_drop_time"] = 360
    smart_cc["ps"] = "智能CC防护"
    return smart_cc
end

function public.get_error499()
    local max_err_count=5
    if  WAF_CPU_CORES>4  and WAF_CPU_CORES<8 then
        max_err_count=30
    elseif WAF_CPU_CORES>8 and WAF_CPU_CORES<16 then
        max_err_count=50
    elseif WAF_CPU_CORES>16 then
        max_err_count=80
    end
    return max_err_count
end


-- 判断该IPv6是否为局域网IP
-- @param ip IPv6地址
-- @return bool
function public.is_lan_ipv6(ip)
    -- 回环地址
    if ip == "::1" then
        return true
    end
    -- 定义局域网IPv6前缀
    local localPrefixes = {
        "fc00", -- ULA前缀
        "fd00", -- ULA前缀
        "fe80" -- Link-Local前缀
    }

    -- 获取IPv6地址的前缀
    local prefix = string.sub(ip, 1, 4)

    -- 检查前缀是否匹配局域网前缀
    for _, localPrefix in ipairs(localPrefixes) do
        if prefix == localPrefix then
            return true -- 匹配成功，是局域网IP
        end
    end

    return false -- 前缀不匹配，不是局域网IP
end

-- 判断该IPv4是否为局域网IP
-- @param ip IPv4地址
-- @return bool
function public.is_lan_ipv4(ip)
    if not ip then
        return false
    end
    if public.find_str(ip, ":") then
        return false
    end
    if ip == "127.0.0.1" then
        return true
    end
    local ip_long = public.ip2long(ip)
    if ip_long >= 167772160 and ip_long <= 184549375 then
        return true
    end
    if ip_long >= 2886729728 and ip_long <= 2887778303 then
        return true
    end
    if ip_long >= 3232235520 and ip_long <= 3232301055 then
        return true
    end
    return false
end

-- 判断该IP是否为局域网IP
-- @param ip IP地址
-- @return bool
function public.is_lan_ip(ip)
    if not ip then
        return false
    end
    if public.find_str(ip, ":") then
        return public.is_lan_ipv6(ip)
    else
        return public.is_lan_ipv4(ip)
    end
end

function public.update_time()
    Today=ngx.today()
    local time_str = ngx.localtime()
    Hour = string.sub(time_str, 12, 13)
    -- 截取分钟，从第 14 位到第 15 位
    Minute = string.sub(time_str, 14, 15)
end 

--给每个网站增加蜘蛛开关的识别
function public.load_spider()
    for server_name,val in pairs(Site_config) 
    do
        if Site_config[server_name]['spider']~=nil then 
            for spider in pairs(Site_config[server_name]['spider']) 
            do 
                
                
            end 
        
        end 
    end 
end 

function public.generate_random_string(length)
    -- 定义可能的字符集
    local charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    -- 初始化空字符串用于构建随机字符串
    local random_str = ""
    -- 确保传入的长度是一个正整数
    if length <= 0 then
        return random_str
    end
    -- 循环指定的次数，每次从字符集中随机选择一个字符
    for i = 1, length do
        -- 生成一个随机索引
        local random_index = math.random(1, #charset)
        -- 随机选择一个字符并添加到结果字符串中
        random_str = random_str .. charset:sub(random_index, random_index)
    end
    -- 返回生成的随机字符串
    return random_str
end

--预处理自定义规则中的ip段等数据，以减少后续匹配时的计算量
function public.get_ip_ranges_from_customize(rules)
    local customize_groups = {}


    local function walk_node (node)
        if node["type"]=="block" then
            for _,v in ipairs(node["children"]) do
                walk_node(v)   -- return false
            end
        elseif node["type"] == "option" then
            if node["option"]["type"] =="ip" then
                local ip_groups = {}
                local tmp_ips =public.split(node["option"]["right_factor"], ",")
                if tmp_ips and public.len(tmp_ips) >= 1 then
                    for _, v in ipairs(tmp_ips) do
                        table.insert(ip_groups, v)
                    end
                end
                customize_groups[node["option"]["right_factor"]] = ipmatcher.new(ip_groups)
            elseif node["option"]["type"] =="ip_range" then
                local tmp_ip_ranges = public.split(node["option"]["right_factor"], ",")
                if tmp_ip_ranges and public.len(tmp_ip_ranges) >= 1 then
                    local ip_range_groups = {}
                    for _, v in ipairs(tmp_ip_ranges) do
                        if v ~="malicious_ip" then
                            table.insert(ip_range_groups, v)
                        end

                    end
                    customize_groups[node["option"]["right_factor"]] = ipmatcher.new(ip_range_groups)

                end
            end
        end
    end
    if rules == nil then
        return customize_groups
    end
    for _, v in pairs(rules) do
        walk_node(v["root"])
    end

    return customize_groups
end

-- 增加Token的值
-- @param string name 规则名称
function public.incrtoken(token, count)
    if ngx.shared.btwaf_data:get(token) then
        ngx.shared.btwaf_data:incr(token, 1)
    else
        ngx.shared.btwaf_data:set(token, count + 1, 3600)
    end
    return ngx.shared.btwaf_data:get(token)
end


--更新配置文件
-- @param 增加Token的值
-- @param filename 需要修改的文件
-- @param 需要存储的内容
function public.updateRule(token, filename, datas)
    if not ngx.shared.btwaf_data:get(token) then
        --写文件
        public.write_file(filename, Json.encode(datas))
        ngx.shared.btwaf_data:set(token, 1, 3)
        -- 触发一下更新
        ngx.shared.ipinfo:set("getconfig", "config", 2)
    end
end

-- @name 分辨是否是假蜘蛛
-- @param ip
-- @return status,msg
function public.query_dns(ip)
    if ngx.shared.spider:get("get_spider_error") then return false,"" end
    local dns_query,err= Dns:new{nameservers = {"114.114.114.114", {"223.5.5.5", 53} },retrans = 5,timeout = 2000}
    if not dns_query then return false,"" end
    local dns_table,err,tries=dns_query:reverse_query(ip)
    --如果出现错误则120秒后才能重新查询一次
    if err then
        ngx.shared.spider:set("get_spider_error",1,10)
    end
	if not dns_table then 
		return false,""
	end
	if type(dns_table)~='table' then return false end
    if dns_table['errcode']~=nil and dns_table['errstr']~=nil then 
        return true,"not spider"
    end
    if not dns_table[1] then return false end     
    if not  dns_table[1]['ptrdname'] then return false end 
    local ptrdname=dns_table[1]['ptrdname']
    if ngx.re.find(ptrdname,"crawl.baidu") then 
        return true,"baiduspider"
    end
    if ngx.re.find(ptrdname,"googlebot.com") then 
        return true,"googlebot"
    end 
    if ngx.re.find(ptrdname,"sogouspider") then 
        return true,"sogouspider"
    end 
    if ngx.re.find(ptrdname,"crawl.yahoo.net") then 
        return true,"yahoo"
    end
	if ngx.re.find(ptrdname,"crawl.yahoo.com") then 
        return true,"yahoo"
    end
    if ngx.re.find(ptrdname,"search.msn.com") then 
        return true,"bing"
    end 
    if ngx.re.find(ptrdname,"crawl.bytedance") then 
        return true,"bytedance"
    end 
    if ngx.re.find(ptrdname,"shenmaspider") then 
        return true,"shenmaspider"
    end
    return true,"not spider"
end

function public.send_spider(server_name,ip)
    if server_name=="127.0.0.251" then return false end 
    local keys =  ngx.md5(server_name .. ip)
    local keyword = ngx.shared.btwaf_data:get(keys)
    if keyword then return end
    ngx.shared.btwaf_data:set(keys, 1, 360)
    if not public.is_ip(ip) then return false end
    public.spider_enqueue(ip)
end

-- 将规则命中日志加入队列
function public.spider_enqueue(data)
    local queue_key = "btwaf_spider_enqueue"
    local max_queue_size = 500
    local shared_dict = ngx.shared.btwaf_data
    local count_size = shared_dict:rpush(queue_key, data)
    if type(count_size) ~= "number" then
        return
    end
    --如果有数据则写一个缓存变量
    ngx.shared.spider:set("btwaf_spider_enqueue", "1", 120)
    if count_size == nil then return end
    if count_size > max_queue_size then
        shared_dict:lpop(queue_key)
    end
end

function public.flush_spider()
    --减少抢占冲突
    ngx.sleep(1)
    local lock_key = 'workers.btwaf_spider_enqueue'
    -- 尝试加锁
    if not public.try_lock(lock_key, 30) then
        return
    end
    -- 如果都没有数据则直接返回
    if not ngx.shared.spider:get("btwaf_spider_enqueue") then
        return
    end
    local queue_key = "btwaf_spider_enqueue"
    local shared_dict = ngx.shared.btwaf_data
    -- 从队列的头部获取数据
    local spider={}
    local not_spider={}
    for i = 1, 500 do
        local serialized_data, err = shared_dict:lpop(queue_key)
        if err ~= nil or serialized_data == nil then
            break
        end
        local spider_statu,msg =public.query_dns(serialized_data)
        if spider_statu then 
            if msg=="not spider" then 
                not_spider[serialized_data]="not_spider"
            else 
                spider[serialized_data]=msg
            end
        end
    end
    if public.len(spider) >=1 then 
        local get_spider= Public.read_file('get_spider')
        local flag=false
        for key,value in pairs(spider) do 
            if get_spider[key]==nil then 
                get_spider[key]=value
                ngx.shared.spider:set(key, "1")
                flag=true
            end 
        end 
        if flag then
            public.write_file("/www/server/btwaf/rule/get_spider.json",Json.encode(get_spider))
        end 
    end 
    if public.len(not_spider) >=1 then 
        local get_spider= Public.read_file('not_spider')
        local flag=false
        for key,value in pairs(not_spider) do 
            if get_spider[key]==nil then 
                get_spider[key]=tonumber(ngx.now())+172800
                ngx.shared.btwaf:set(key.."not_spider", "1")
                flag=true
            end 
        end
        if public.len(get_spider) >2000 then 
            get_spider = {}
        end 
        if flag then 
            public.write_file("/www/server/btwaf/rule/not_spider.json",Json.encode(get_spider))
        end 
    end
    -- public.un_lock(lock_key)
end

function public.request_incr(status)
    if status==nil then return end
    if status==444 then 
		if ngx.ctx.today==nil or ngx.ctx.hour==nil or ngx.ctx.minute==nil then return false end
        local date_key=ngx.ctx.today .. '_' ..  tonumber(ngx.ctx.hour) .. '_' .. tonumber(ngx.ctx.minute)
        local key = 'req_'..date_key
        public.logs_incr("global",key,1,360)
        public.logs_incr(ngx.ctx.server_name,key,1,360)
        public.logs_incr(ngx.ctx.time,'qps',1,10)
    end
end


function public.read_cms_file(name)
    local fbody = public.read_file_body(BTWAF_CMS_PATH.."/" .. name .. '.json')
    if fbody == nil then
        return {}
    end
    --判断Json格式是否正确
    local status, result = pcall(Json.decode, fbody)
    if status then
        return result
    end
    return {}
end


function public.load_cms_rule()
    local tmp={}
    for _, filename in pairs(public.listdir(BTWAF_CMS_PATH)) do

        local mod_name = string.match(filename, "(.*)%.json")
        if mod_name then 
            local cmsdata=public.read_cms_file(mod_name)
            if  cmsdata~=nil and cmsdata and cmsdata["status"]~=nil and cmsdata["type"]~=nil then 
                if cmsdata["status"] and  cmsdata["type"]=="uri" then 
                    BTWAF_CMS_OBJS[mod_name]=cmsdata
                    -- cmsdata["file_path"]=mod_name
                    local url=cmsdata["left_factor"]
                    local operator=cmsdata["operator"]
                    local cms_type=operator
                    if BTWAF_CMS_OBJS[cms_type]==nil then
                        BTWAF_CMS_OBJS[cms_type]={}
                    end
                    if BTWAF_CMS_OBJS[cms_type][url]==nil then
                        BTWAF_CMS_OBJS[cms_type][url]=""
                        BTWAF_CMS_OBJS[cms_type][url]=mod_name
                    else
                        if cms_type=="eq" then 
                            BTWAF_CMS_OBJS[cms_type][url]=mod_name
                        else
                            BTWAF_CMS_OBJS[cms_type][url]=BTWAF_CMS_OBJS[cms_type][url]..","..mod_name
                        end
                    end
                end
            end 
        end 
    end 
end

function public.gzip_encode(compressed_encode)
    local ok,zlib = pcall(function()
    	return require "ffi-zlib"
    end)
    if not ok then return compressed_encode end 
    if not zlib then return compressed_encode end 
    local chunk = 16384
    local uncompressed = ''
    local in_adler
    local out_adler
    local in_crc
    local out_crc
    local count = 0
    local input = function(bufsize)
     local start = count > 0 and bufsize*count or 1
        local finish = (bufsize*(count+1)-1)
        count = count + 1
        if bufsize == 1 then
            start = count
            finish = count
        end
        local data = compressed_encode:sub(start, finish)
        if  #data==0 then return nil end 
        in_crc = zlib.crc(data, in_crc)
        in_adler = zlib.adler(data, in_adler)
        uncompressed = uncompressed..data
        return data
    end
    local output_table = {}
    local output = function(data_infos)
        out_crc = zlib.crc(data_infos, out_crc)
        out_adler = zlib.adler(data_infos, out_adler)
        table.insert(output_table, data_infos)
    end
    local ok, err = zlib.deflateGzip(input, output, chunk)
    if not ok then
        return compressed_encode
    end
    local compressed = table.concat(output_table,'')
    return compressed
end 

function public.ungzip(body)
    
    local ok,zlib = pcall(function()
    	return require "ffi-zlib"
    end)
    if not ok then return body end 
    if not zlib then return body end 
    
     local ok2,iconv = pcall(function()
    	return require "iconv"
    end)
    if not ok2 then return body end 
    if not iconv then return body end 
    local s,e = string.byte(body,1,2)
    if s ~= 31 or e ~= 139 then
        return body
    end
    local in_adler = nil
    local out_adler = nil
    local in_crc = nil
    local out_crc = nil
    local output_table = {}
    local output = function(data)
        out_crc = zlib.crc(data, out_crc)
        out_adler = zlib.adler(data, out_adler)
        table.insert(output_table, data)
    end
    local count = 0
    local input = function(bufsize)
        local start = count > 0 and bufsize*count or 1
        local finish = (bufsize*(count+1)-1)
        count = count + 1
        if bufsize == 1 then
            start = count
            finish = count
        end
        local data = body:sub(start, finish)
        in_crc = zlib.crc(data, in_crc)
        in_adler = zlib.adler(data, in_adler)
        return data
    end
    local ok, err = zlib.inflateGzip(input, output, 15+32)
    if not ok then
        return body
    end
    body = table.concat(output_table,'')
    local t, count = iconv:new('UTF-8', 'UTF-8',#body):convert(body)
    return t
end


function public.aes(body)
    if ngx.var.http_X_Requested_With and ngx.var.http_X_Requested_With=="XMLHttpRequest" then return body end
	if ngx.ctx.method~='GET' and #body<5000 then return body end
    if ngx.ctx.white_rule==nil then return body end 
    if ngx.ctx.white_rule==true then return body end
    if #body<1000 then return body end
    local random_index = math.random(1, 4)
    ngx.ctx.crawler_html_text=''
    if Site_config~=nil and  Site_config[ngx.ctx.server_name]~=nil and Site_config[ngx.ctx.server_name]['crawler']~=nil then 
        local htmlnew=Site_config[ngx.ctx.server_name]['crawler']['htmlnew']
        if htmlnew~=nil and htmlnew['type']~=nil and htmlnew['type']=="text" and htmlnew["text"]~=nil and htmlnew["text"]~="" then 
            ngx.ctx.crawler_html_text=htmlnew["text"]
        end
    end
    if random_index==4 then 
        return public.aes_gcm(body)
    elseif random_index==3 then 
        return public.aes_cbc(body) 
    elseif random_index==2 then 
        return public.aes_cfb(body)
    elseif random_index==1 then 
        return public.aes_ctr(body)
    else 
        return body
    end 
end

function public.aes_gcm(body)
    local gzip=false
    local s,e = string.byte(body,1,2)
    if s == 31 or e == 139 then
        body_tmp=public.ungzip(body)
		local s,e = string.byte(body_tmp,1,2)
		if s == 31 or e == 139 then return body end 
		gzip=true
		body=body_tmp
    end
    local random_key = public.generate_random_string(32)
    local iv =public.generate_random_string(12)
    local aes_default = AES_OBJ:new(random_key,nil,AES_OBJ.cipher(256,"gcm"),{iv = iv})
    if aes_default==nil or not aes_default then return body end 
    local encrypted = aes_default:encrypt(body)
    local key=String_OBJ.cdata_to_table(aes_default._key,32)
    local iv =String_OBJ.cdata_to_table(aes_default._iv,12)
    local tag=String_OBJ.ffi_str_to_decimal_array(encrypted[2])
    local html_data=""
    if #ngx.ctx.crawler_html_text>1 then 
        html_data=BTWAF_RULES.aes_gcm_customize
        html_data=ngx.re.sub(html_data, "{{content}}", ngx.ctx.crawler_html_text, "jo")
    else 
        html_data=BTWAF_RULES.aes_gcm
    end 
    local check_html = ngx.re.sub(html_data, "{{raw_key}}", Json.encode(key), "jo")
    check_html = ngx.re.sub(check_html, "{{encrypted}}", String_OBJ.to_hex(encrypted[1]), "jo")
    check_html = ngx.re.sub(check_html, "{{tag}}", Json.encode(tag), "jo")
    check_html = ngx.re.sub(check_html, "{{iv}}", Json.encode(iv), "jo")
    ngx.var.waf2monitor_blocked="动态加密|成功返回动态加密后的网页内容"
    if gzip then 
        return public.gzip_encode(check_html)
    end
    return check_html
end 
    


function public.aes_cbc(body)
    local gzip=false
    local s,e = string.byte(body,1,2)
    if s == 31 or e == 139 then
        body_tmp=public.ungzip(body)
		local s,e = string.byte(body_tmp,1,2)
		if s == 31 or e == 139 then return body end 
		gzip=true
		body=body_tmp
    end
    local random_key = public.generate_random_string(16)
    local iv =public.generate_random_string(16)
    local aes_default = AES_OBJ:new(random_key,nil,AES_OBJ.cipher(128,"cbc"),{iv=iv})
    local encrypted = aes_default:encrypt(body)
    encrypted=String_OBJ.to_hex(encrypted)
    local key=String_OBJ.cdata_to_table(aes_default._key,16)
    local iv =String_OBJ.cdata_to_table(aes_default._iv,16)
    local html_data=""
    if #ngx.ctx.crawler_html_text>1 then 
        html_data=BTWAF_RULES.aes_cbc_customize
        html_data=ngx.re.sub(html_data, "{{content}}", ngx.ctx.crawler_html_text, "jo")
    else 
        html_data=BTWAF_RULES.aes_cbc
    end 
     local check_html = ngx.re.sub(html_data, "{{raw_key}}", Json.encode(key), "jo")
    check_html = ngx.re.sub(check_html, "{{encrypted}}", encrypted, "jo")
    check_html = ngx.re.sub(check_html, "{{iv}}", Json.encode(iv), "jo")
    ngx.var.waf2monitor_blocked="动态加密|成功返回动态加密后的网页内容"
    if gzip then 
        return public.gzip_encode(check_html)
    end
    return check_html
end 


function public.aes_cfb(body)
    local gzip=false
    local s,e = string.byte(body,1,2)
    if s == 31 or e == 139 then
        body_tmp=public.ungzip(body)
		local s,e = string.byte(body_tmp,1,2)
		if s == 31 or e == 139 then return body end 
		gzip=true
		body=body_tmp
    end
    local random_key = public.generate_random_string(16)
    local iv =public.generate_random_string(16)
    local aes_default = AES_OBJ:new(random_key, nil, AES_OBJ.cipher(128, "ofb"), {iv = iv})
    local encrypted = aes_default:encrypt(body)
    encrypted=String_OBJ.to_hex(encrypted)
    local key=String_OBJ.cdata_to_table(aes_default._key,16)
    local iv =String_OBJ.cdata_to_table(aes_default._iv,16)
    local html_data=""
    if #ngx.ctx.crawler_html_text>1 then 
        html_data=BTWAF_RULES.aes_ofb_customize
        html_data=ngx.re.sub(html_data, "{{content}}", ngx.ctx.crawler_html_text, "jo")
    else 
        html_data=BTWAF_RULES.aes_ofb
    end 
     local check_html = ngx.re.sub(html_data, "{{raw_key}}", Json.encode(key), "jo")
    check_html = ngx.re.sub(check_html, "{{encrypted}}", encrypted, "jo")
    check_html = ngx.re.sub(check_html, "{{iv}}", Json.encode(iv), "jo")
    ngx.var.waf2monitor_blocked="动态加密|成功返回动态加密后的网页内容"
    if gzip then 
        return public.gzip_encode(check_html)
    end
    return check_html
end 


function public.aes_ctr(body)
    local gzip=false
    local s,e = string.byte(body,1,2)
    if s == 31 or e == 139 then
        body_tmp=public.ungzip(body)
		local s,e = string.byte(body_tmp,1,2)
		if s == 31 or e == 139 then return body end 
		gzip=true
		body=body_tmp
    end
    local random_key = public.generate_random_string(16)
    local iv =public.generate_random_string(16)
    local aes_default = AES_OBJ:new(random_key, nil, AES_OBJ.cipher(128, "ctr"), {iv = iv})
    local encrypted = aes_default:encrypt(body)
    encrypted=String_OBJ.to_hex(encrypted)
    local key=String_OBJ.cdata_to_table(aes_default._key,16)
    local iv =String_OBJ.cdata_to_table(aes_default._iv,16)
    local html_data=""
    if #ngx.ctx.crawler_html_text>1 then 
        html_data=BTWAF_RULES.aes_ctr_customize
        html_data=ngx.re.sub(html_data, "{{content}}", ngx.ctx.crawler_html_text, "jo")
    else 
        html_data=BTWAF_RULES.aes_ctr
    end 
     local check_html = ngx.re.sub(html_data, "{{raw_key}}", Json.encode(key), "jo")
    check_html = ngx.re.sub(check_html, "{{encrypted}}", encrypted, "jo")
    check_html = ngx.re.sub(check_html, "{{iv}}", Json.encode(iv), "jo")
    ngx.var.waf2monitor_blocked="动态加密|成功返回动态加密后的网页内容"
    if gzip then 
        return public.gzip_encode(check_html)
    end
    return check_html
end 


function public.ungzipbit(body)
    local ok,zlib = pcall(function()
    	return require "ffi-zlib"
    end)
    if not ok then return body end 
    if not zlib then return body end 
    local s,e = string.byte(body,1,2)
    if s ~= 31 or e ~= 139 then
        return body
    end
    local in_adler = nil
    local out_adler = nil
    local in_crc = nil
    local out_crc = nil
    local output_table = {}
    local output = function(data)
        out_crc = zlib.crc(data, out_crc)
        out_adler = zlib.adler(data, out_adler)
        table.insert(output_table, data)
    end
    local count = 0
    local input = function(bufsize)
        local start = count > 0 and bufsize*count or 1
        local finish = (bufsize*(count+1)-1)
        count = count + 1
        if bufsize == 1 then
            start = count
            finish = count
        end
        local data = body:sub(start, finish)
        in_crc = zlib.crc(data, in_crc)
        in_adler = zlib.adler(data, in_adler)
        return data
    end
    local ok, err = zlib.inflateGzip(input, output, 15+32)
    if not ok then
        return body
    end
    body = table.concat(output_table,'')
    return body
end


function iconv_to_utf_8(body)
    local ok2,iconv = pcall(function()
    	return require "iconv"
    end)
    if not ok2 then return body end 
    if not iconv then return body end 

    local t, count = iconv:new('UTF-8', 'UTF-8',#body):convert(body)
    return t
end 

function public.gd_png(body,types,domain)
    local startTime = public.getMilliseconds()
    local ok,gd = pcall(function()
    	return require "gd.init"
    end)
    if not ok then return  end
    local s,e = string.byte(body,1,2)
    if s == 31 or e == 139 then
        local body_tmp=public.ungzipbit(body)
       	local s,e = string.byte(body_tmp,1,2)
		if s == 31 or e == 139 then 
		    return  end 
		gzip=true
		body=body_tmp
    end
    local ext=""
    local a,b,c,d = string.byte(body,1,4)
    if a==137 and b==80 and c==78 and d==71 then 
        ext="png"
    end
    if a==255 and b==216 and c==255 and d==224 then 
        ext="jpg"
    end 
    local im=nil
    if ext=="png" then 
         im = gd.createFromPngStr(body)
    elseif ext=="jpg"  then 
         im = gd.createFromJpegStr(body)
    else
        return 
    end 
    if im ==nil then   return  end 
    local srcWidth = im:sizeX()
    local srcHeight = im:sizeY()
    local lblue = im:colorAllocateAlpha(200, 200, 200, 50)
    gd.useFontConfig(true)
    local text = domain
    if Site_config~=nil and  Site_config[ngx.ctx.server_name]~=nil and Site_config[ngx.ctx.server_name]['crawler']~=nil then 
        local htmlnew=Site_config[ngx.ctx.server_name]['crawler']['picturenew']
        if htmlnew~=nil and htmlnew['type']~=nil and htmlnew['type']=="text" and htmlnew["text"]~=nil and htmlnew["text"]~="" then 
            text=htmlnew["text"]
        end
    end
    local font = "/www/server/btwaf/lib/gd/Vera.ttf"
    local fontSize = 8
    local angle = math.rad(35)
    
    local spacing = 40
    
    local function generatePositions(width, height, fontSize, spacing)
      local positions = {}
      local x =20
      local y = 10
      while y < height - spacing do
        while x < width - spacing do
          table.insert(positions, { x = x, y = y })
          x = x + fontSize * 15
        end
        x = spacing
        y = y + fontSize * 15
      end
    
      return positions
    end
    local positions = generatePositions(srcWidth, srcHeight, fontSize, spacing)
    for i, pos in ipairs(positions) do
        im:stringFTEx(lblue, font, fontSize, angle, pos.x, pos.y, text, { linespacing = 0.5 })
    end
    local name =ngx.ctx.uri..domain
    local file_name=BTWAF_RUN_PATH.."/picture/"..ngx.ctx.server_name.."/"..ngx.md5(name..text).."."..types
    if ext=="png" then  im:pngEx(file_name,1) end
    if ext=="jpg" then  im:jpeg(file_name,90) end
    gd.destroy(im)
end 
    
function public.static_watermark()
    if ngx.ctx.crawler_picture==false then return false end 
    if #ngx.ctx.url_split<4 then return false end 
    local ext=ngx.ctx.url_split:sub(#ngx.ctx.url_split-3,#ngx.ctx.url_split)
    if ext==".png" or ext==".jpg" or ext=="jpeg" then 
        if ext=="jpeg" then jpeg=".jpeg" end 
        local name =ngx.ctx.uri..ngx.ctx.server_name
        local text = ngx.ctx.server_name
        if Site_config~=nil and  Site_config[ngx.ctx.server_name]~=nil and Site_config[ngx.ctx.server_name]['crawler']~=nil then 
            local htmlnew=Site_config[ngx.ctx.server_name]['crawler']['picturenew']
            if htmlnew~=nil and htmlnew['type']~=nil and htmlnew['type']=="text" and htmlnew["text"]~=nil and htmlnew["text"]~="" then 
                text=htmlnew["text"]
            end
        end
        local file_name=BTWAF_RUN_PATH.."/picture/"..ngx.ctx.server_name.."/"..ngx.md5(name..text)..ext
        local file_info=public.read_file_body_rb(file_name)
        if file_info==nil then return false end 
        if ext==".png" then ngx.header["Content-Type"] = "image/png" end 
        if ext==".jpg" then ngx.header["Content-Type"] = "image/jpeg" end 
        if ext==".jpeg" then ngx.header["Content-Type"] = "image/jpeg" end 
        ngx.ctx.is_crawler_picture=true
        ngx.say(file_info)
    end 
end 

function public.user_count()
    local cache_count=ngx.shared.btwaf_data:get("user_count_size")
    if cache_count~=nil then return cache_count end 
    local keys=ngx.shared.user:get_keys()
    local count=0
    for i,v in pairs(keys) 
    do
        count=count+1
    end
    ngx.shared.btwaf_data:set("user_count_size",count,2)
    return count
end 


function public.timeout_count()
    if ngx.ctx.timeout==false then return false end
    local limit_user=ngx.ctx.timeout_limiting["user"]
    local limit_time=tonumber(ngx.ctx.timeout_limiting["time"])*60

    local wb, err = server:new{
        timeout = 2000,
        max_payload_len = 512,
    }
    if not wb then
        return ngx.exit(444)
    end
    local timout_token =ngx.md5("timeout"..ngx.ctx.ip .. ngx.ctx.ua)
    -- 获取或创建连接信息
    local function get_or_create_connection_info()
        local conn_count = ngx.shared.btwaf_data:get("total_connections")
        if conn_count==nil then 
            ngx.shared.btwaf_data:set("total_connections",1,86400)
            ngx.shared.btwaf_data:set(timout_token, 1,600)
            return 1,1
        end 
        local position,err = ngx.shared.btwaf_data:get(timout_token)
        if not  position  then
            conn_count=conn_count+1
            position = conn_count
            ngx.shared.btwaf_data:set(timout_token, tonumber(position),600)
            ngx.shared.btwaf_data:incr("total_connections", 1)
        end
        return position, conn_count
    end

    local function decr(key, decrement, initial)
        local value, err = ngx.shared.btwaf_data:get(key)
        if not value then
            if initial then
                value = initial
            else
                return nil
            end
        end
        value = tonumber(value) - decrement
        if value < 0 then
            value = 0
        end
        ngx.shared.btwaf_data:set(key, value)
        return value
    end
    
    local function websocket_handler()
        local position, total_connections = get_or_create_connection_info()
        if not position then
            return ngx.exit(444)
        end
        if position>total_connections then 
            total_connections=position
        end 
        local response = Json.encode({pos = position, total = total_connections})

        local ok, err = wb:send_text(response)
        if not ok then
            local new_total_connections = decr("total_connections", 1, 0)
            ngx.shared.btwaf_data:delete(timout_token)
            return
        end
        local is_del_flag=false
        ngx.ctx.white_rule=true
        while true do
            local flag=false
            local position, total_connections = get_or_create_connection_info()
            if not position then
                is_del_flag=true
                return ngx.exit(444)
            end
            local data, typ, err = wb:recv_frame()
            if data then 
                is_del_flag=true
                break
            end 
            if typ=="close" then
                break
            end
            
            if position>total_connections then 
                total_connections=position
                flag=true
            end
            local response = Json.encode({pos = position, total = total_connections})
            local ok, err = wb:send_text(response)
            if not ok then
                is_del_flag=true
                break
            end
            if position==1 or  position<20 or total_connections<20  then 
                local user_count=public.user_count()
                if user_count<limit_user then 
                    ngx.var.waf2monitor_blocked="等待室排队完成|排队完成,正在请求原网页"
                    local user_token="user"..ngx.md5(ngx.ctx.ip.. ngx.ctx.ua)
                    ngx.shared.user:set(user_token,1,30)
                    ngx.shared.btwaf_data:set(user_token,1,limit_time)
                     local response = Json.encode({pos = 0, total = total_connections})
                     wb:send_text(response)
                     is_del_flag=true
                    break
                end 
            end
        end
        if is_del_flag then 
            local new_total_connections = decr("total_connections", 1, 0)
            ngx.shared.btwaf_data:delete(timout_token)
        end 
        return new_total_connections
    end
    return websocket_handler()
end

-- 全站应用
function public.limit_users()
    if ngx.req.is_internal() then return false end
    if ngx.ctx.timeout==false then return false end
    if BTWAF_OBJS.cc.is_api() then return false end 
    local limit_qps=tonumber(ngx.ctx.timeout_limiting["qps"])
    local limit_user=tonumber(ngx.ctx.timeout_limiting["user"])
    local limit_time=tonumber(ngx.ctx.timeout_limiting["time"])*60
    local limit_type=ngx.ctx.timeout_limiting["identity"]["type"]
    local limit_text=ngx.ctx.timeout_limiting["identity"]["text"]
    local load_time=ngx.ctx.time
    if load_time==nil then return false end 
    if ngx.var.request_uri=="/.btwaf_api/btwaf_user_count" then return false end 
    local qps=public.logs_get(ngx.ctx.server_name..load_time-1,'qps')
    if qps<limit_qps then return false end
    local user_token="user"..ngx.md5(ngx.ctx.ip.. ngx.ctx.ua)
    if  ngx.shared.user:get(user_token) then 
      return false end 
    if ngx.shared.btwaf_data:get(user_token) then  
      ngx.shared.user:set(user_token,1,30)
      return false 
    end
    local conn_count = ngx.shared.btwaf_data:get("total_connections")
    if conn_count==nil or conn_count==0 then 
      local user_count= public.user_count()
      if user_count<limit_user then 
          ngx.shared.user:set(user_token,1,30)
          ngx.shared.btwaf_data:set(user_token,1,limit_time)
          return
      end
    end
    ngx.var.waf2monitor_blocked="等待室|发送等待请求内容"
    ngx.ctx.limit_users=true
    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.header.Cache_Control = "no-cache"
    ngx.status = 200
    if limit_type=="default" then 
        ngx.say(BTWAF_RULES.timeout_html)
    else 
        local html_data=BTWAF_RULES.timeout_user_html
        html_data=ngx.re.sub(html_data, "{{content}}", limit_text, "jo")
        ngx.say(html_data)
    end 
    ngx.exit(200)
end



return public