--[[
    @name ip 相关的库文件
    @role ip归属地、ip是否被拦截
    @author lkq@bt.cn
    @time 2023-08-17
    @version 1.0
]] --

local ipinfo = {}
local database =require 'database'
-- local ip=ngx.ctx.ip
-- local server_name=ngx.ctx.server_name

-- 蜘蛛ID规则
-- @param 默认是记录了7个蜘蛛 分别记录了他的名称、UA关键词、和host的关键词
ipinfo.zhizhu = {
    [1] = {
        ["id"] = 1,
        ["name"] = "百度",
        ["ua_key"] = "Baiduspider",
        ["host_key"] = "baidu.com"
    },
    [2] = {
        ["id"] = 2,
        ["name"] = "Google",
        ["ua_key"] = "Googlebot",
        ["host_key"] = "googlebot.com"
    },
    [3] = {
        ["id"] = 3,
        ["name"] = "360",
        ["ua_key"] = "360Spider",
        ["host_key"] = "0"
    },
    [4] = {
        ["id"] = 4,
        ["name"] = "搜狗",
        ["ua_key"] = "Sogou",
        ["host_key"] = "crawl.sogou.com"
    },
    [5] = {
        ["id"] = 5,
        ["name"] = "雅虎",
        ["ua_key"] = "Yahoo!",
        ["host_key"] = "yahoo.net"
    },
    [6] = {
        ["id"] = 6,
        ["name"] = "必应",
        ["ua_key"] = "bingbot",
        ["host_key"] = "search.msn.com"
    },
    [7] = {
        ["id"] = 7,
        ["name"] = "头条",
        ["ua_key"] = "bytespider",
        ["host_key"] = "bytedance.com"
    }
}

--实例化maxminddb
--@param 无
--@return 无
function ipinfo.initmaxminddb()
    if Geo == nil then
        local ok
        ok, Geo =pcall(function()  return require "maxminddb" end )
        if not ok then
            return nil
        end
        local ok2, data =pcall( function() if not Geo.initted() then Geo.init(BTWAF_INC .. "/GeoLite2-City.mmdb") end end
        )
        if not ok2 then
            Geo = nil
        end
    end
    if type(Geo) == "number" then
        return nil
    end
    if Geo == nil then
        return nil
    end
end

-- 获取IP位置信息
-- @param ip IP地址
-- @return IP位置信息 string|table
-- 1:IP地址不合法 2.内网地址 3. 未知地址
function ipinfo.get_ip_position_data(ip)
    ipinfo.initmaxminddb()
    --判断是否为IPV4地址
    -- if not Public.is_ipv4(ip) then
    --     return "3"
    -- end
    if type(Geo) == "number" then
        return "3"
    end
    if Geo == nil then
        return "3"
    end
    if Geo.lookup == nil then
        return "3"
    end
    local res, err = Geo.lookup(ip)
    if not res then
        return "2"
    else
        return res
    end
end

--获取IP地址的国家
--@param ip IP地址
--@return IP地址的国家
function ipinfo.get_country(ip)
    local ipdata=ngx.shared.ipinfo:get(ip)
    if ipdata then
        --如果前两位是中国
        if string.sub(ipdata,1,6) == "中国" then
            --使用|分割
            local per_info=Public.split2(ipdata,"|")
            if type(per_info)~="table" then
                return "中国","","",""
            end
            return "中国",per_info[2],per_info[3],per_info[4]
        else
            return ipdata
        end
    end
    local ip_postion = ipinfo.get_ip_position_data(ip)
    if ip_postion == "2" or ip_postion == "1" or ip_postion == "3" then
        return "","","",""
    end
    if ip_postion["country"] == nil then
        return "","","",""
    end
    if ip_postion["country"]["country"] == nil then
        return "","","",""
    end
	if ip_postion["country"]["tag"]==nil then 
		ip_postion["country"]["tag"]=""
	end 
    if ip_postion["country"]["country"] == "中国" then
        ngx.shared.ipinfo:set(ip, ip_postion["country"]["country"].."|"..ip_postion["country"]["province"].."|"..ip_postion["country"]["city"].."|"..ip_postion["country"]["tag"], 600)
    else
        ngx.shared.ipinfo:set(ip, ip_postion["country"]["country"], 600)
    end
    
    return ip_postion["country"]["country"],ip_postion["country"]["province"],ip_postion["country"]["city"],ip_postion["country"]["tag"]
end


function ipinfo.bt_ip_filter(ip,time_out)
    local ipcount = ngx.shared.btwaf:get('token_ipcount')
    if not ipcount then 
        ipcount=1
        ngx.shared.btwaf:set('token_ipcount',1,1800)
    else
        ngx.shared.btwaf:incr('token_ipcount',1)
    end
    if ipcount>120 then 
        local ok,_ = pcall(function()
		    return ngx.sleep(0.1)
        end)
    end
    local bt_ip_filter='/dev/shm/.bt_ip_filter'
    local fp = io.open(bt_ip_filter,'rb')
    local token_key = 'bt_ip_filter_ip_list'
    local dony_ip = '+,'..ip..','..tostring(time_out)
	if fp == nil then
        local tbody = ngx.shared.btwaf:get(token_key)
        if not tbody then
            tbody = dony_ip
        else
            tbody = tbody .. "\n" .. dony_ip
        end
        Public.write_file(bt_ip_filter,tbody)
		ngx.shared.btwaf:delete(token_key)
    else
        local tbody = ngx.shared.btwaf:get(token_key)
        if not tbody then 
             tbody = dony_ip
        else
            tbody = tbody .."\n".. dony_ip
        end
        ngx.shared.btwaf:set('bt_ip_filter_ip_list',tbody,3600)
    end
end 



function ipinfo.get_client_ip_bylog()
	local client_ip = "unknown"
    local server_name=ngx.ctx.server_name
	if Site_config[server_name] then
		if Site_config[server_name]['cdn'] then
            local request_header=ngx.ctx.request_header
			for _,v in ipairs(Site_config[server_name]['cdn_header'])
			do
				if request_header[v] ~= nil and request_header[v] ~= "" then
					local header_tmp = request_header[v]
					if type(header_tmp) == "table" then header_tmp = header_tmp[1] end
					local tmpe=Public.split(header_tmp,',')
                    if Public.arrlen(tmpe)>=1 then 
                        if Site_config[server_name]['cdn_baidu'] ~=nil and Site_config[server_name]['cdn_baidu'] then 
                            client_ip=tmpe[1]
    				        client_ip=string.gsub(client_ip," ","")
                        else
    				        client_ip=tmpe[Public.arrlen(tmpe)]
    				        client_ip=string.gsub(client_ip," ","")
				        end 
						if request_header['remote-host'] and request_header['remote-host']~=nil then 
							if request_header['remote-host']==client_ip then 
								client_ip=tmpe[1]
								client_ip=string.gsub(client_ip," ","")
							end 
						end 
				    end
					if  Public.is_localhost(client_ip) then
						if tostring(ngx.var.remote_addr) == tostring(client_ip) then
							client_ip = ngx.var.remote_addr
						else
							client_ip = ngx.var.remote_addr
						end
					end
					break;
				end
			end
		end
	end
	if type(client_ip) == 'table' then client_ip = "" end
	if (Public.is_ipv4(client_ip)==false and string.match(client_ip,"^[%w:]+$") == nil) or client_ip == 'unknown'  then
		client_ip = ngx.var.remote_addr
		if client_ip == nil then
			client_ip = "unknown"
		end
	end
	-- if not ngx.shared.btwaf_data:get(client_ip) then 
	--     ngx.shared.btwaf_data:set(client_ip,0,3600)
	-- end
    if string.match(client_ip, "^[%w:]+$") then
        ngx.ctx.ipv6 = 1
    else
        ngx.ctx.ipv6 = 0
    end

    if Public.is_ipv4(client_ip) then
        --计算一下ip的整数
        ngx.ctx.iplong = Public.ip2long(client_ip)
        local country,province,city,tag = IpInfo.get_country(client_ip)
        if country then
            ngx.ctx.country = country
            ngx.ctx.ip_province=province
            ngx.ctx.ip_city=city
            ngx.ctx.ip_tag=tag
        else
            ngx.ctx.country = ""
        end
    else
        ngx.ctx.country = ""
        ngx.ctx.iplong = 0
    end
    
    ngx.ctx.ip=client_ip
	return client_ip
end

function ipinfo.write_to_file(logstr)
	local filename = Config["logs_path"] .. '/' .. ngx.ctx.server_name .. '_' .. ngx.today() .. '.log'
	local fp = io.open(filename,'ab')
	if fp == nil then return false end
	fp:write(logstr)
	fp:flush()
	fp:close()
	return true
end


function ipinfo.inc_log(name,rule)
    local server_name=ngx.ctx.server_name

	local total_path = BTWAF_RUN_PATH .. '/total.json'
	local tbody = ngx.shared.btwaf:get(total_path)
	if not tbody then
		tbody = Public.read_file_body(total_path)
		if not tbody then return false end
	end
	local total = Json.decode(tbody)
	if not total['sites'] then total['sites'] = {} end
	if not total['sites'][server_name] then total['sites'][server_name] = {} end
	if not total['sites'][server_name][name] then total['sites'][server_name][name] = 0 end
	if not total['rules'] then total['rules'] = {} end
	if not total['rules'][name] then total['rules'][name] = 0 end
	if not total['total'] then total['total'] = 0 end
	total['total'] = total['total'] + 1
	total['sites'][server_name][name] = total['sites'][server_name][name] + 1
	total['rules'][name] = total['rules'][name] + 1
	local total_log = Json.encode(total)
	if not total_log then return false end
	ngx.shared.btwaf:set(total_path,total_log)
	if not ngx.shared.btwaf:get('b_btwaf_timeout') then
		Public.write_file(total_path,total_log)
		ngx.shared.btwaf:set('b_btwaf_timeout',1,5)
	end
end

function ipinfo.write_drop_ip2(is_drop,drop_time,name,rule)
    local server_name=ngx.ctx.server_name
    local request_uri=ngx.ctx.request_uri
	local filename = BTWAF_RUN_PATH .. '/drop_ip.log'
	--local fp = io.open(filename,'ab')
	--if fp == nil then return false end
	if ngx.ctx.lan_type then ngx.ctx.lan_type=ngx.ctx.lan_type end 
	if ngx.ctx.is_type_rule then ngx.ctx.lan_type=ngx.ctx.is_type_rule end 
	if Config['send_to'] and Config['send_to'] ~='ERROR' then 
    	local logs_data={os.time(),"网站 "..server_name.." 遭到IP "..ngx.ctx.ip.." 的攻击".."URL为: "..request_uri}
	end
    local http_logs=BTWAF_OBJS.request_check.http_log()
    if ngx.ctx.body_info then http_logs=http_logs.."\n\n"..ngx.ctx.buffered end 
	local logtmp = {os.time(),ngx.ctx.ip,server_name,request_uri,drop_time,is_drop,ngx.ctx.method,ngx.var.http_user_agent,name,rule,http_logs}
	database.totla_log_insert('ip',server_name,ngx.ctx.ip,ngx.ctx.method,request_uri,ngx.var.http_user_agent, ngx.ctx.lan_type,name,'',http_logs,is_drop,drop_time)
	database.totla_log_insert('log',server_name,ngx.ctx.ip,ngx.ctx.method,request_uri,ngx.var.http_user_agent, ngx.ctx.lan_type,name,'',http_logs,'','')
    ipinfo.bt_ip_filter(ngx.ctx.ip,drop_time)
	local logstr = Json.encode(logtmp) .. "\n"
	--fp:write(logstr)
	--fp:flush()
	--fp:close()
	ipinfo.inc_log(is_drop,rule)
	return true
end



function ipinfo.lan_ip(type,name)
    local ip=ngx.ctx.ip
    local types="types"
    if type=="browser" then 
        type="cc"
        types="browser"
    end 
	local safe_count,_ = ngx.shared.drop_sum:get(ip)
	if not safe_count then
		ngx.shared.drop_sum:set(ip,1,86400)
		safe_count = 1
	else
		ngx.shared.drop_sum:incr(ip,1)
	end
	local lock_time = (ngx.ctx.endtime * safe_count)
	if lock_time > 86400 then lock_time = 86400 end
	ngx.shared.drop_ip:set(ip,ngx.ctx.retry+1,lock_time)
	local method = ngx.req.get_method()
	if ngx.ctx.error_rule then 
		ngx.ctx.rule = ngx.ctx.error_rule
		ngx.ctx.error_rule = nil
	end
	if ngx.ctx.is_type then 
		ngx.ctx.is_type_rule = ngx.ctx.is_type
		ngx.ctx.is_type = nil
	end
	local http_logs=BTWAF_OBJS.request_check.http_log()
	if ngx.ctx.body_info then http_logs=http_logs.."\n\n"..ngx.ctx.buffered end 
	local logtmp = {ngx.localtime(),ip,method,ngx.ctx.request_uri,ngx.var.http_user_agent,type,name,http_logs,ngx.ctx.is_type_rule}
	local logstr = Json.encode(logtmp) .. "\n"
	ipinfo.write_to_file(logstr)
	ipinfo.inc_log(type,ngx.ctx.rule)
	if type =='args' or type=='post' or type =='inc' then 
		ipinfo.write_drop_ip2('inc',lock_time,name,ngx.ctx.rule)
	else
		ipinfo.write_drop_ip2(type,lock_time,name,ngx.ctx.rule)
	end 
	if types~="browser" then 
	    if ngx.ctx.body_filter_run==nil then 
			Public.request_incr(Config['cc']['status'])
			ngx.exit(Config['cc']['status'])
		end 
	end 
end



function ipinfo.write_drop_ip(is_drop,drop_time,name)
    local server_name=ngx.ctx.server_name
    local ip=ngx.ctx.ip
	local filename = BTWAF_RUN_PATH .. '/drop_ip.log'
	--local fp = io.open(filename,'ab')
	--if fp == nil then return false end
	if ngx.ctx.lan_type then ngx.ctx.lan_type=ngx.ctx.lan_type end 
	if ngx.ctx.is_type_rule then ngx.ctx.lan_type=ngx.ctx.is_type_rule end 
	if Config['send_to'] and Config['send_to'] ~='ERROR' then 
    	local logs_data={os.time(),"网站 "..server_name.." 遭到IP "..ip.." 的攻击".."URL为: "..ngx.ctx.request_uri}
	end
    local http_logs=BTWAF_OBJS.request_check.http_log()
    if ngx.ctx.body_info then http_logs=http_logs.."\n\n"..ngx.ctx.buffered end 
	local logtmp = {os.time(),ip,server_name,ngx.ctx.request_uri,drop_time,is_drop,ngx.ctx.method,ngx.var.http_user_agent,name,ngx.ctx.rule,http_logs}
    if is_drop=='cc' then 
        if ngx.ctx.is_url_type~=nil and ngx.ctx.is_url_type=="智能CC" then 
            ngx.ctx.lan_type="智能CC"
            is_drop="smart_cc"
        end
    end
	database.totla_log_insert('ip',server_name,ip,ngx.ctx.method,ngx.ctx.request_uri,ngx.var.http_user_agent,ngx.ctx.lan_type,name,'',http_logs,is_drop,drop_time)
	database.totla_log_insert('log',server_name,ip,ngx.ctx.method,ngx.ctx.request_uri,ngx.var.http_user_agent,ngx.ctx.lan_type,name,'',http_logs,'','')
	ipinfo.bt_ip_filter(ip,drop_time)
	local logstr = Json.encode(logtmp) .. "\n"
	--fp:write(logstr)
	--fp:flush()
	--fp:close()
	ipinfo.inc_log(is_drop,ngx.ctx.rule)
	return true
end

function ipinfo.compare_ip2(ips)
    local ip=ngx.ctx.ip
	if ip == 'unknown' then return false end
	if string.find(ip,':') then return false end
	if  type(ips[2])~='number' and  type(ips[1])~='number' and  type(ngx.ctx.iplong)~='number' then  return false end
	if  ngx.ctx.iplong<=ips[2] and ngx.ctx.iplong>=ips[1] then return true end
	return false
end



--初始化阶段就把所有的蜘蛛IP加载到共享内存中
function ipinfo.load_spider()
    local spider_ip_segment={}
    
    -- 蜘蛛的IP段写入到内存中
    for i=1,9 do 
        local data = Public.read_file_body(BTWAF_INC .. "/" .. tostring(i) .. ".json")
        local ok, zhizhu_list_data =pcall( function() return Json.decode(data)  end )
        if  ok then
            for _, k in ipairs(zhizhu_list_data) do
                table.insert(spider_ip_segment,k)
            end
        end
    end
    
    for k,_ in pairs(BTWAF_RULES.get_spider) do 
        ngx.shared.spider:set(k, "1")
    end 
    for k,_ in pairs(BTWAF_RULES.not_spider) do 
        ngx.shared.btwaf:set(k.."not_spider", "1")
    end
    return spider_ip_segment
end
-- 根据蜘蛛id进行拦截
function ipinfo.spider_not(infos)
    if type(infos)~="table" then return false end 
    if infos["1"] then if ngx.re.find(ngx.ctx.ua,"Baiduspider","ijo") then  
        ngx.var.waf2monitor_blocked="蜘蛛拦截|".."该网站已设置禁止谷歌蜘蛛访问"
        Public.log_rule_hit(1,"蜘蛛拦截",ngx.ctx.time, "蜘蛛拦截", "匹配到禁止百度蜘蛛UA "..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
		Public.request_incr(444)
        ngx.exit(444) end end 
    if infos["2"] then if ngx.re.find(ngx.ctx.ua,"Googlebot","ijo") then  
        ngx.var.waf2monitor_blocked="蜘蛛拦截|".."该网站已设置禁止谷歌蜘蛛访问"
        Public.log_rule_hit(1,"蜘蛛拦截",ngx.ctx.time, "蜘蛛拦截", "匹配到禁止谷歌蜘蛛UA "..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
		Public.request_incr(444)
        ngx.exit(444) 
    end end 
    if infos["3"] then if ngx.re.find(ngx.ctx.ua,"360Spider","ijo") then  
        ngx.var.waf2monitor_blocked="蜘蛛拦截|".."该网站已设置禁止360蜘蛛访问"
        Public.log_rule_hit(1,"蜘蛛拦截",ngx.ctx.time, "蜘蛛拦截", "匹配到禁止360蜘蛛UA "..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
		Public.request_incr(444)
        ngx.exit(444) end end 
    if infos["4"] then if ngx.re.find(ngx.ctx.ua,"www.sogou.com","ijo") then  
        ngx.var.waf2monitor_blocked="蜘蛛拦截|".."该网站已设置禁止搜狗蜘蛛访问"
        Public.log_rule_hit(1,"蜘蛛拦截",ngx.ctx.time, "蜘蛛拦截", "匹配到禁止Sogou蜘蛛UA "..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
		Public.request_incr(444)
        ngx.exit(444) end  end 
    if infos["5"] then if ngx.re.find(ngx.ctx.ua,"Yahoo!","ijo") then  
        ngx.var.waf2monitor_blocked="蜘蛛拦截|".."该网站已设置禁止雅虎蜘蛛访问"
        Public.log_rule_hit(1,"蜘蛛拦截",ngx.ctx.time, "蜘蛛拦截", "匹配到禁止雅虎蜘蛛UA "..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
		Public.request_incr(444)
        ngx.exit(444) end end 
    if infos["6"] then if ngx.re.find(ngx.ctx.ua,"bingbot","ijo") then  
        ngx.var.waf2monitor_blocked="蜘蛛拦截|".."该网站已设置禁止必应蜘蛛访问"
        Public.log_rule_hit(1,"蜘蛛拦截",ngx.ctx.time, "蜘蛛拦截", "匹配到禁止必应蜘蛛UA "..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
		Public.request_incr(444)
        ngx.exit(444) end end 
    if infos["7"] then if ngx.re.find(ngx.ctx.ua,"Bytespider","ijo") then  
        ngx.var.waf2monitor_blocked="蜘蛛拦截|".."该网站已设置禁止头条蜘蛛访问"
        Public.log_rule_hit(1,"蜘蛛拦截",ngx.ctx.time, "蜘蛛拦截", "匹配到禁止头条蜘蛛UA "..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
		Public.request_incr(444)
        ngx.exit(444) end end 
    if infos["8"] then if ngx.re.find(ngx.ctx.ua,"YisouSpider","ijo") then  
        ngx.var.waf2monitor_blocked="蜘蛛拦截|".."该网站已设置禁止神马蜘蛛访问"
        Public.log_rule_hit(1,"蜘蛛拦截",ngx.ctx.time, "蜘蛛拦截", "匹配到禁止神马蜘蛛UA "..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
		Public.request_incr(444)
        ngx.exit(444) end end 
end 

-- 存在疑似蜘蛛的IP
function ipinfo.is_load_spider()
    if BTWAF_RULES.load_spider_count>=1 then 
        if  BTWAF_RULES.load_spider:match(ngx.ctx.ip) then 
            return true 
        end 
    end
    return false
end


--根据UA +IP地址 检测是否为蜘蛛
--@param ip IP地址
--@param ua UA
function ipinfo.reptile_entrance()
    	--微信回调IP放行
    if BTWAF_RULES.ip_pay_count>=1 then 
       if  BTWAF_RULES.ip_pay:match(ngx.ctx.ip) then 
           return true 
        end 
    end
    -- 蜘蛛爬取放行规则
    local info={}
    if ngx.ctx.spider_status and  not ngx.shared.spider:get(ngx.ctx.server_name.."spider_no") and  Site_config[ngx.ctx.server_name] and Site_config[ngx.ctx.server_name]['spider'] then 
        local spider_infos=ngx.shared.spider:get(ngx.ctx.server_name.."spider")
        if spider_infos then 
            spider_infos=Json.decode(spider_infos)
            ipinfo.spider_not(spider_infos)
        else
            local flag=false
            for i,v in ipairs(Site_config[ngx.ctx.server_name]['spider']) do 
                if not v["status"] then 
                    info[tostring(v["id"])]=true
                    flag=true
                end 
            end 
            if not flag then 
                ngx.shared.spider:set(ngx.ctx.server_name.."spider_no",1)
            else 
                ngx.shared.spider:set(ngx.ctx.server_name.."spider",Json.encode(info),3600)
                ipinfo.spider_not(info)
            end
        end
    end 
    --如果总开关关闭了、那么说明这个网站不需要蜘蛛爬取
    if not ngx.ctx.spider_status then  
        if ngx.re.find(ngx.ctx.ua,"Baiduspider|Googlebot|360Spider|www.sogou.com|Yahoo!|bingbot|Bytespider|YisouSpider","ijo") then 
            ngx.var.waf2monitor_blocked="蜘蛛拦截|".."该网站已设置禁止所有蜘蛛访问"
            Public.log_rule_hit(1,"蜘蛛拦截",ngx.ctx.time, "蜘蛛拦截", "匹配到禁止所有蜘蛛UA"..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
            ngx.exit(444)
        end 
    end 
    --判断是否已经是蜘蛛IP
    if ngx.shared.spider:get(ngx.ctx.ip) then
        return true
    end
    if  BTWAF_RULES.load_spider:match(ngx.ctx.ip) then 
        ngx.shared.spider:set(ngx.ctx.ip, "1",18000)
        return true 
    end 
    
    -- 如果不在蜘蛛列表中的IP
    if  ngx.re.find(ngx.ctx.ua,"Baiduspider|Googlebot|360Spider|www.sogou.com|Yahoo!|bingbot|Bytespider|YisouSpider","ijo") then
        if ngx.ctx.not_spider  then 
            -- 谷歌、360 头条蜘蛛 是确定的IP段
            if ngx.re.find(ngx.ctx.ua,"Googlebot|360Spider|Bytespider","ijo") then 
                ngx.ctx.is_type="假蜘蛛"
                ngx.var.waf2monitor_blocked="假蜘蛛拦截"
                ipinfo.lan_ip('cc','假蜘蛛拦截') 
            end 
            if ngx.shared.btwaf:get(ngx.ctx.ip.."not_spider") then 
                ngx.ctx.is_type="假蜘蛛"
                ngx.var.waf2monitor_blocked="假蜘蛛拦截"
                ipinfo.lan_ip('cc','假蜘蛛拦截') 
            end
            
        end 
        -- 那么需要研判一下是否为蜘蛛的IP
        Public.send_spider(ngx.ctx.server_name,ngx.ctx.ip)
    end 
    return false
end

function ipinfo.write_log(name,rule)
    local ip =ngx.ctx.ip
    local server_name=ngx.ctx.server_name
    local today=ngx.ctx.today
    local retry=ngx.ctx.retry
    local retry_time=ngx.ctx.retry_time
    local retry_cycle=ngx.ctx.retry_cycle
    local endtime=ngx.ctx.endtime
    local request_uri=ngx.ctx.request_uri
    
	local count,_ = ngx.shared.drop_sum:get(ngx.ctx.ip..ngx.ctx.today)
	if count then
		ngx.shared.drop_sum:incr(ip..today,1)
	else
		ngx.shared.drop_sum:set(ip..today,1,retry_cycle)
	end
	if Config['log'] ~= true or Public.is_site_config('log') ~= true then return false end
	local method = ngx.req.get_method()
	if ngx.ctx.error_rule then 
		rule = ngx.ctx.error_rule
		ngx.ctx.error_rule = nil
	end
	if ngx.ctx.is_type then 
	    if ngx.ctx.is_type==nil then 
	        ngx.ctx.lan_type='目录保护'
	    else
		    ngx.ctx.lan_type = ngx.ctx.is_type
		end
		ngx.ctx.is_type = nil
	end
	local http_logs=BTWAF_OBJS.request_check.http_log()
	if ngx.ctx.body_info then http_logs=http_logs.."\n\n"..ngx.ctx.buffered end 
	local logtmp = {ngx.localtime(),ip,method,request_uri,ngx.var.http_user_agent,name,rule,http_logs,ngx.ctx.lan_type}
	local logstr = Json.encode(logtmp) .. "\n"
	local count,_ = ngx.shared.drop_sum:get(ip..today)	
	if name =='cc' then
	    local safe_count,_ = ngx.shared.drop_sum:get(ip)
        if not safe_count then
        	ngx.shared.drop_sum:set(ip,1,86400)
        	safe_count = 1
        else
        	ngx.shared.drop_sum:incr(ip,1)
        end
        local lock_time = (endtime * safe_count)
        if lock_time > 86400 then lock_time = 86400 end
        ngx.shared.drop_ip:set(ip,retry+1,lock_time)
        ngx.shared.btwaf_data:delete(ip)
	end
	if count > retry-1 and name ~= 'cc' then
		local safe_count,_ = ngx.shared.drop_sum:get(ip)
		if not safe_count then
			ngx.shared.drop_sum:set(ip,1,86400)
			safe_count = 1
		else
			ngx.shared.drop_sum:incr(ip,1)
		end
		local lock_time = retry_time * safe_count
		if lock_time > 86400 then lock_time = 86400 end
		ngx.ctx.lan_type='封锁此IP'
		
		logtmp = {ngx.localtime(),ip,method,request_uri,ngx.var.http_user_agent,name,retry_cycle .. '秒以内累计超过'..retry..'次以上非法请求,封锁'.. lock_time ..'秒',http_logs,ngx.ctx.lan_type}
		logstr = logstr .. Json.encode(logtmp) .. "\n"
		ngx.shared.drop_ip:set(ip,retry+1,lock_time)
		ipinfo.write_drop_ip2('inc',lock_time,rule,name)
		ngx.shared.btwaf_data:delete(ip)
	else
	    if name ~= 'cc' then 
	        database.totla_log_insert('log',server_name,ip,method,request_uri,ngx.var.http_user_agent,ngx.ctx.lan_type,rule,name,http_logs,'','')
	    end
	end
	ipinfo.write_to_file(logstr)
	if name ~= 'cc' then  
		ipinfo.inc_log(name,rule)
	end
end


-- 判断IP是否为内地IP
-- @param ip IP地址
-- @return bool
function ipinfo.is_inland(ip)
    if ngx.ctx.country == "中国" and ngx.ctx.ip_province ~= "香港" and ngx.ctx.ip_province ~= "台湾" and ngx.ctx.ip_province ~= "澳门" then
        return true
    end
    return false
end


-- 判断IP是否为IDC IP
-- @param ip IP地址
-- @return bool
function ipinfo.is_idc(ip)
    -- local country = ipinfo.get_country(ip)
    -- if not country then
    --     return false
    -- end
    -- local tag = ngx.shared.ipinfo:get(ip .. "t")
    -- if not tag then
    --     return false
    -- end
    if ngx.ctx.ip_tag == "IDC" then
        return true
    end
    return false
end


return ipinfo