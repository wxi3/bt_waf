local white_balck={}

function white_balck.binary_search(data, value)
    local low, high = 1, #data
    local count =0
    while low <= high do
        count=count+1
        local mid = math.floor((low + high) / 2)
        local start, en = data[mid][1], data[mid][2]

        if value >= start and value <= en then
            return true
        elseif value < start then
            high = mid - 1
        else
            low = mid + 1
        end
    end
    return false
end

function white_balck.drop_abroad()
    if  Config['drop_abroad']==nil then return false end 
    if not Config['drop_abroad']['open'] or not Public.is_site_config('drop_abroad') then return false end
    if ngx.ctx.ip=='91.199.212.132' or ngx.ctx.ip=='91.199.212.133' or ngx.ctx.ip=='91.199.212.148' or ngx.ctx.ip=='91.199.212.151' or ngx.ctx.ip=='91.199.212.176' then return false end
    if Public.is_ssl() then return false end
    if  ngx.ctx.country=="" then return false end 
    if ngx.ctx.country=="内网地址" then return false end 
    if ngx.ctx.country=="中国" then  return false end 
	if BTWAF_RULES.system_black then 
	    ngx.var.waf2monitor_blocked="禁国外封锁增强"
        ngx.ctx.is_type="禁国外封锁增强"
		ngx.ctx.endtime=86400
        IpInfo.lan_ip('drop_abroad',"开启禁国外增强封锁、已将此IP拉入系统防火墙封禁24小时、如再次访问则增加24小时封锁")
	end
    ngx.var.waf2monitor_blocked="禁止海外访问"
	Public.request_incr(Config['drop_abroad']['status'])
    ngx.exit(Config['drop_abroad']['status'])
	return true
end



function white_balck.is_ip_lan()
    for k,v in ipairs(BTWAF_RULES.lanlist) do if IpInfo.compare_ip2(v) then return true end  end
    return false
end

function white_balck.binary_searchdrop_china()
    local server_name=ngx.ctx.server_name
	if Config['drop_china'] ==nil then return false end 
	if Site_config[server_name] ==nil then return false end 
	if Site_config[server_name]['drop_china'] ==nil then return false end
	if Public.is_ssl() then return false end
	if not Config['drop_china']['open'] or not Site_config[server_name]['drop_china'] then return false end
    local ip=ngx.ctx.ip
	if string.find(ip,':') then return false end
    if Config['drop_china']['open'] and Site_config[server_name]['drop_china'] then
        if ngx.ctx.country=="中国" then 
            ngx.var.waf2monitor_blocked="禁止国内访问"
			Public.request_incr(Config['drop_china']['status'])
            ngx.exit(Config['drop_china']['status'])
            return true 
        end
    end
    return false
end

function white_balck.drop_china()
    if Config['drop_china'] ==nil then return false end 
    local server_name=ngx.ctx.server_name
	if Site_config[server_name] ==nil then return false end 
	if Site_config[server_name]['drop_china'] ==nil then return false end 
	if not Config['drop_china']['open'] or not Site_config[server_name]['drop_china'] then return false end
    if Public.is_ssl() then return false end
    if ngx.ctx.country=="中国" then 
        ngx.var.waf2monitor_blocked="禁止国内访问"
		Public.request_incr(Config['cc']['status'])
        ngx.exit(Config['drop_abroad']['status'])
        return true 
    end
    return false
end




function white_balck.drop()
    local ip=ngx.ctx.ip

	local count,_ = ngx.shared.drop_ip:get(ip)
	if not count then return false end
	if count then
	    ngx.var.waf2monitor_blocked="已拉黑的IP"
    	IpInfo.bt_ip_filter(ip,ngx.ctx.endtime)
        ngx.exit(444)
    	return true
    end 
    return false
end

function white_balck.header_drop(ip)
	local count,_ = ngx.shared.drop_ip:get(ip)
	if not count then return false end
    return true
end

function white_balck.ip_black()
    local ip=ngx.ctx.ip

    if ngx.ctx.ipv6==1 and BTWAF_RULES.ipv6_black_count>=1 then 
        if BTWAF_RULES.ipv6_black:match(ngx.ctx.ip) then
            Public.log_rule_hit(1,"IP黑名单",ngx.ctx.time, "IP黑名单", "匹配到IP黑名单"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
            ngx.var.waf2monitor_blocked="IP黑名单"
			IpInfo.bt_ip_filter(ip,86400)
			Public.request_incr(Config['cc']['status'])
            ngx.exit(Config['cc']['status'])
        end
        return false
    else
        if Public.arrlen(BTWAF_RULES.ip_black_rules)==0 then return false end 
    	for _,rule in ipairs(BTWAF_RULES.ip_black_rules)
    	do
    		if IpInfo.compare_ip2(rule) then 
				local rule_msg=" 触发规则:"..Public.long2ip(rule[1]).."-"..Public.long2ip(rule[2])
				ngx.var.waf2monitor_blocked="IP黑名单"
    		    Public.log_rule_hit(1,"IP黑名单",ngx.ctx.time, "IP黑名单", "匹配到IP黑名单"..ngx.ctx.ip..rule_msg, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
				IpInfo.bt_ip_filter(ip,86400)
				Public.request_incr(Config['cc']['status'])
    		    ngx.exit(Config['cc']['status'])
    		return true end
    	end
    	return false
    end 
    
end

function white_balck.ip_white()
    local ip=ngx.ctx.ip
    if ngx.ctx.ipv6==1 and BTWAF_RULES.ipv6_white_count>=1 then
        if BTWAF_RULES.ipv6_white:match(ip) then
            ngx.var.waf2monitor_blocked="IP白名单"
            Public.log_rule_hit(0,"ip白名单",ngx.ctx.time, "IP白名单", "匹配到IP白名单"..ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
            return true
        end
        return false
    else 
        if Public.count_sieze(BTWAF_RULES.ip_white_rules)==0 then return false end 
    	if ngx.var.server_name =='_' and ip =='127.0.0.1' then return false end
    	for _,rule in ipairs(BTWAF_RULES.ip_white_rules) do	
    	    if IpInfo.compare_ip2(rule) then 
				local rule_msg=" 触发规则:"..Public.long2ip(rule[1]).."-"..Public.long2ip(rule[2])
                ngx.var.waf2monitor_blocked="IP白名单"
    	        Public.log_rule_hit(0,"ip白名单",ngx.ctx.time, "IP白名单", "匹配到IP白名单"..ip..rule_msg, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
    	        return true 
    	    end 
	    end
    	return false
    end 
end


function white_balck.url_white()
	if ngx.var.document_root=='/www/server/phpmyadmin' then return true end
	if Public.count_sieze(BTWAF_RULES.url_white_rules)>=1 then 
    	if BTWAF_OBJS.request_check.is_ngx_match(BTWAF_RULES.url_white_rules,ngx.ctx.request_uri,false) then
            if ngx.ctx.url_split then 
                if ngx.re.match(ngx.ctx.url_split,'/\\.\\./',"jo") then return false end
                --已加入URL白名单的情况下.某些API接口需要检测
                if white_balck.url_white_chekc_data() then return false end
                ngx.var.waf2monitor_blocked="URI白名单"
                Public.log_rule_hit(0,"URI白名单",ngx.ctx.time, "URI白名单", "匹配到URI白名单"..ngx.var.request_uri, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                return true
            end
    	end
    end
	if Public.count_sieze(BTWAF_RULES.url_white_senior)>=1 then
    	 for _,v2 in pairs(BTWAF_RULES.url_white_senior) do 
    	    local count =0 
	        local is_count=0
    	    for k,v in pairs(v2) do 
    	        if ngx.ctx.url_split~=nil and k~=nil and ngx.re.match(ngx.ctx.url_split,k,"jo") then
    	            count=Public.count_sieze(v)
                    if count==0 then  return true end
                    for _,v3 in pairs(v) do
                       local vargs=Public.split(v3,"=")
                       if Public.arrlen(vargs)==1 then 
                           if ngx.ctx.get_uri_args[vargs[1]] then 
                                is_count=is_count+1
                           end
                       else
                          if  ngx.ctx.get_uri_args[vargs[1]]==vargs[2] then 
                                is_count=is_count+1    
                          end 
                       end
                    end
                end 
    	    end
    	    if count~=0 and is_count~=0 and count==is_count then 
                ngx.var.waf2monitor_blocked="URI白名单"
                return true end 
    	 end
	end
	return false
end

function white_balck.url_black()
    if Public.arrlen(BTWAF_RULES.url_black_rules)==0 then return false end 
	if BTWAF_OBJS.request_check.is_ngx_match(BTWAF_RULES.url_black_rules,ngx.ctx.request_uri,false) then
	    Public.log_rule_hit(1,"URI黑名单",ngx.ctx.time, "URI黑名单", "匹配到URI黑名单"..ngx.var.request_uri, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
	    ngx.var.waf2monitor_blocked="URI黑名单"
	    ngx.exit(Config['get']['status']) 
	    return true 
	end
	return false
end


function white_balck.get_config_ua_white()
    local char_string=Config['ua_white']
    if not char_string then return false end
    if Public.arrlen(char_string) ==0 then return false end
    if Public.arrlen(char_string) >=1 then return char_string end
 end
 
 function white_balck.get_config_ua_black()
    local char_string=Config['ua_black']
    if not char_string then return false end
    if Public.arrlen(char_string) ==0 then return false end
    if Public.arrlen(char_string) >=1 then return char_string end
 end
 
function white_balck.ua_white()
    if  ngx.ctx.ua=="_" then return false end
    if type(ngx.ctx.ua) ~='string' then ngx.exit(200) end 
     local get_ua_list=white_balck.get_config_ua_white()
     if Public.arrlen(get_ua_list)==0 then return false end
     if get_ua_list then
         for __,v in pairs(get_ua_list)
         do
            if ngx.ctx.ua==v then return true end
            if ngx.re.match(ngx.ctx.ua,v,'ijo') then
                ngx.var.waf2monitor_blocked="UA白名单"
                Public.log_rule_hit(0,"UA白名单",ngx.ctx.time, "UA白名单", "匹配到UA白名单"..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                return true
            end
         end
     end
     return false
 end
 
function white_balck.ua_black()
     if  ngx.ctx.ua=="_" then return false end
     if type(ngx.ctx.ua) ~='string' then ngx.exit(200) end 
     local get_ua_list=white_balck.get_config_ua_black()
     if Public.count_sieze(get_ua_list)==0 then return false end
     if get_ua_list then
         for __,v in pairs(get_ua_list)
         do
            if ngx.ctx.ua==v then 
                ngx.var.waf2monitor_blocked="ua黑名单"
                ngx.ctx.is_type="ua黑名单"
                Public.log_rule_hit(1,"UA黑名单",ngx.ctx.time, "UA黑名单", "匹配到UA黑名单"..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                IpInfo.lan_ip('user_agent','ua黑名单拦截')
            return true end
            if ngx.re.match(ngx.ctx.ua,v,'ijo') then
                Public.log_rule_hit(1,"UA黑名单",ngx.ctx.time, "UA黑名单", "匹配到UA黑名单"..ngx.ctx.ua, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                ngx.ctx.is_type="ua黑名单"
                ngx.var.waf2monitor_blocked="ua黑名单"
                IpInfo.lan_ip('user_agent','ua黑名单拦截')
                return true 
            end
         end
     end
     return false
 end
 


function white_balck.url_white_chekc()
    local char_string=Config['url_white_chekc']
    if not char_string then return false end
    if Public.arrlen(char_string) ==0 then return false end
    if Public.arrlen(char_string) >=1 then
        return char_string 
    end
 end
 
function white_balck.url_white_chekc_data()
     local get_body=white_balck.url_white_chekc()
     if get_body==false then return false end
     if   ngx.ctx.url_split==nil then return false end
     if not ngx.ctx.url_split then return false end
     if get_body and ngx.ctx.url_split then
         for __,v in pairs(get_body)
         do
             if string.find(ngx.ctx.url_split,v) then 
                 return true
             end
         end
     end
     return false
 end
 

return white_balck