local cc={}
local ngx_match = ngx.re.find

function cc.cc_increase_static()
	local keys = {"css","js","png","gif","ico","jpg","jpeg","bmp","flush","swf","pdf","rar","zip","doc","docx","xlsx","webp"}
	for _,k in ipairs(keys)
	do
		local aa="/?.*\\."..k.."$"
		if ngx_match(ngx.ctx.uri,aa,"isjo") then
		    
			return true
		end
	end
	return false
end

--CC白名单
function cc.cc_uri_white()
    if Public.count_sieze(BTWAF_RULES.cc_uri_white_rules)==0 then return false end 
	if cc.cc_increase_static() then return true end
	if BTWAF_OBJS.request_check.is_ngx_match(BTWAF_RULES.cc_uri_white_rules,ngx.ctx.uri,false) then
		return true
	end
	if Site_config[ngx.ctx.server_name] ~= nil then
		if BTWAF_OBJS.request_check.is_ngx_match(Site_config[ngx.ctx.server_name]['cc_uri_white'],ngx.ctx.uri,false) then
			return true
		end
	end
	return false
end

function cc.is_api()
	if ngx.re.match(ngx.ctx.url_split,'/\\.\\./',"jo") then return false end
    local url_fraction=0
    if ngx.shared.cc:get(ngx.ctx.url_token.."url") then 
        ngx.ctx.is_api=true
        return true
    end 
    if ngx.re.find(ngx.ctx.url_split,"^(/api/|/wp-json/)","ijo")  then 
        url_fraction=10  
        if not ngx.re.find(ngx.ctx.ua,"^Mozilla","ijo") then 
            url_fraction=url_fraction+10
        end 
        if ngx.var.http_Authorization~=nil and ngx.var.http_Authorization~="" then 
            url_fraction=url_fraction+10
        end
        if ngx.shared.cc:get(ngx.ctx.url_token)  then 
            url_fraction=url_fraction+10
        end
        if url_fraction>=20 then 
            ngx.shared.cc:set(ngx.ctx.url_token.."url",1,60)
            ngx.ctx.is_api=true
			return true
        end
    elseif  ngx.shared.cc:get(ngx.ctx.url_token)  then 
        url_fraction=10
        if not ngx.re.find(ngx.ctx.ua,"^Mozilla","ijo") then 
            url_fraction=url_fraction+10
        end 
        if ngx.var.http_Authorization~=nil and ngx.var.http_Authorization~="" then 
            url_fraction=url_fraction+10
        end
        if ngx.var.http_X_Requested_With and ngx.var.http_X_Requested_With=="XMLHttpRequest" then 
            url_fraction=url_fraction+10
        end
		if ngx.var.http_sec_fetch_dest and ngx.var.http_sec_fetch_dest=="image"  then 
			url_fraction=url_fraction+10
		end
		if ngx.var.http_content_type and ngx.var.http_content_type=="application/json"  then 
            url_fraction=url_fraction+10
        end
        if url_fraction>=20 then 
            ngx.shared.cc:set(ngx.ctx.url_token.."url",1,60)
            ngx.ctx.is_api=true
			return true
        end
    end
    return false
end

--返回简单CC的key
function cc.return_cc_url()
    local ip=ngx.ctx.ip
    local server_name =ngx.ctx.server_name
    local request_uri=ngx.ctx.request_uri
    if Site_config[server_name]==nil then return request_uri end
    if Site_config[server_name]['cc_type_status']==nil then return request_uri end
    local cc_type_status=Site_config[server_name]['cc_type_status']
    if cc.is_api() then return request_uri end
    if cc_type_status ~=nil then 
        if cc_type_status==1 then 
            return request_uri
        elseif  cc_type_status==2 then
            return ngx.ctx.url_split
        elseif  cc_type_status==3 then 
            return ip..ngx.ctx.ua
        elseif  cc_type_status==4 then 
            return ip
        end
    end
    return request_uri
end

--人机验证
function cc.renjiyanzheng(type)
    if ngx_match(ngx.ctx.uri,"\\.(css|js|png|gif|ico|jpg|jpeg|bmp|flush|swf|pdf|rar|gz|zip|webp|doc|docx|xlsx|ts|sh|tiff|avi|mp3|mp4|xls|wav|exe|map|bak|tmp|dot|psd|txt|c|cpp|java|ico|dll|bat|woff|ttf|woff2|svg|json|xml)$","isjo") then return false end
	if cc.is_api() then return false end
	if ngx.var.http_X_Requested_With and ngx.var.http_X_Requested_With=="XMLHttpRequest" then return false end
	local waf_msg="跳转验证"
	if type=="browser" then waf_msg="浏览器验证" end 
	if type=="code" then waf_msg="验证码验证" end 
	if type=="renji" then waf_msg="人机验证" end 
	if type=="huadong" then waf_msg="滑动验证" end 
	local token=''
    local ip=ngx.ctx.ip
    local server_name =ngx.ctx.server_name
    local today=ngx.ctx.today
	if ngx.ctx.ua~=nil then 
		token=ngx.md5(ip..ngx.ctx.ua..server_name..type..today)
	else
		token=ngx.md5(ip..server_name..type..today)
	end 
	
	local cac_token=ngx.shared.btwaf:get(token)
	if not cac_token or cac_token==nil then 
	    ngx.var.waf2monitor_blocked="人机验证|触发人机验证,".."验证方式:["..waf_msg.."]"
	    Route.send_Verification_renji(type)
	end 
   local yanzheng_ipdata=ngx.md5(ip..ngx.ctx.ua)
   if ngx.shared.btwaf_data:get(cac_token) then 
   end 
   if ngx.shared.btwaf_data:get(cac_token) then 
      if ngx.shared.btwaf_data:get(cac_token) ~=yanzheng_ipdata then 
          ngx.shared.btwaf_data:delete(cac_token)
          ngx.shared.btwaf:delete(token)
	      ngx.var.waf2monitor_blocked="人机验证|触发人机验证,".."验证方式:["..waf_msg.."]"
          Route.send_Verification_renji(type)
      end
   end
    if type=="btwaf" and  ngx.shared.btwaf_data:get(token.."btwaf")  then  return false end 
    if ngx.ctx.cookie and  ngx.ctx.cookie:get(token) then 
		if ngx.ctx.cookie:get(token)==cac_token then
			if type=="btwaf" then
				ngx.var.waf2monitor_blocked="跳转验证成功"
				ngx.shared.btwaf_data:set(token.."btwaf","1",120)
			end
			return false
		end
    end
	ngx.shared.btwaf:delete(token)
	ngx.var.waf2monitor_blocked="人机验证|触发人机验证,".."验证方式:["..waf_msg.."]"
    Route.send_Verification_renji(type)
end

--人机
function cc.renji(type)
    local server_name =ngx.ctx.server_name
	if not Config['cc']['open'] or not ngx.ctx.site_cc then return false end
	if not Site_config[server_name] then return false end
	if not Site_config[server_name]['cc']['increase'] then return false end
	if type~="browser" then  cc.renjiyanzheng(type) end 
end

--人机验证
function cc.renji_cc(type)
	if not Config['cc']['open'] or not  ngx.ctx.site_cc then return false end
	if not Site_config[ngx.ctx.server_name] then return false end
	local token=ngx.md5(ngx.ctx.ip..ngx.ctx.ua..ngx.ctx.server_name..type..ngx.ctx.today)
	local cac_token=ngx.shared.btwaf:get(token)
	local waf_msg="跳转验证"
	if type=="browser" then waf_msg="浏览器验证" end 
	if type=="code" then waf_msg="验证码验证" end 
	if type=="renji" then waf_msg="人机验证" end 
	if type=="huadong" then waf_msg="滑动验证" end 
	if not cac_token or cac_token==nil then 
	    ngx.var.waf2monitor_blocked="人机验证|触发人机验证,".."验证方式:["..waf_msg.."]"
	    Route.send_Verification_renji(type)
	end 
	if ngx.ctx.cookie and ngx.ctx.cookie:get(token) then 
		if ngx.ctx.cookie:get(token)==cac_token then
			return false
		end
	end
    token=ngx.md5(ngx.ctx.ip..ngx.ctx.ua..ngx.ctx.server_name..type..ngx.ctx.today)
    ngx.shared.btwaf:delete(token)
	ngx.var.waf2monitor_blocked="人机验证|触发人机验证,".."验证方式:["..waf_msg.."]"
    Route.send_Verification_renji(type)
end

--自动CC检测
function cc.set_inser_cc()
	if not Site_config[ngx.ctx.server_name] then return false end 
	if not Site_config[ngx.ctx.server_name]['cc'] then return false end
	local cc_automatic=false
	local cc_time=nil
	local cc_retry_cycle=nil
	if Site_config[ngx.ctx.server_name]['cc_automatic'] or Config['cc_automatic'] then cc_automatic=true end
	if Config['cc_retry_cycle'] then 
	    cc_retry_cycle=Config['cc_retry_cycle']
	    cc_time=Config['cc_time']*5
	end
	if Site_config[ngx.ctx.server_name]['cc_retry_cycle'] then 
	    cc_retry_cycle=Site_config[ngx.ctx.server_name]['cc_retry_cycle']
	    cc_time=Site_config[ngx.ctx.server_name]['cc_time']*5
	end
	if cc_automatic then
		if cc_time == nil then return false end
		if cc_retry_cycle==nil then return false end
		if not ngx.shared.btwaf:get('cc_automatic'..ngx.ctx.server_name) then
			ngx.shared.btwaf:set('cc_automatic'..ngx.ctx.server_name,1,cc_time)
		else
			local ret22222=ngx.shared.btwaf:get('cc_automatic'..ngx.ctx.server_name)
			if (tonumber(ret22222)/2)>tonumber(cc_retry_cycle) then
			    if Site_config[ngx.ctx.server_name] then 
    				Site_config[ngx.ctx.server_name]['cc']['increase']=true
    				Site_config[ngx.ctx.server_name]['cc']['cc_increase_type']='js'
				    cc.renji("btwaf")
			    else 
			        return false
			    end
			else
			    ngx.shared.btwaf:incr('cc_automatic'..ngx.ctx.server_name,1)
			end
			
		end
	end
end

-- 简单CC检测
function cc.cc()
    if ngx.req.is_internal() then return false end
    local server_name=ngx.ctx.server_name
    local ip=ngx.ctx.ip
	if not Config['cc']['open'] or not ngx.ctx.site_cc then return false end
	if ngx.shared.btwaf_data:get(ngx.ctx.url_token.."url") and ngx.ctx.is_cc_url then 
		ngx.ctx.is_url_type="URL级CC防御"
		cc.renjiyanzheng("btwaf")
	end
	if Site_config[server_name]~=nil and Site_config[server_name]['cc'] and Site_config[server_name]['cc']['countrys'] then 
	    local site_country=Site_config[server_name]['cc']['countrys']
        if  ngx.ctx.country and  ngx.ctx.country~="" and Public.count_sieze(site_country)>=1 then 
            if site_country["海外"]~=nil then 
                if  ngx.ctx.country~="中国" then
                    cc.renjiyanzheng("btwaf")
                end 
            end 
            if site_country[ngx.ctx.country]~=nil then
                cc.renjiyanzheng("btwaf")
            end
        end 
	end 
	local token = ngx.md5(ip .. '_' .. cc.return_cc_url())
	local count= ngx.shared.btwaf:get(token)
	--token2 用于判断是否为解封了的IP
	local token2 = ngx.md5(ip .. '_' ..'return_cc_url')
	local count2= ngx.shared.btwaf:get(token2)
	if count and not count2 then 
	    ngx.shared.btwaf:delete(token)
	    count=0
	end
	if  count and count2  then
		if count > ngx.ctx.limit then
			local safe_count,_ = ngx.shared.drop_sum:get(ip)
			if not safe_count then
				ngx.shared.drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.drop_sum:incr(ip,1)
			end
			ngx.var.waf2monitor_blocked="CC拦截"
			local lock_time = (ngx.ctx.endtime * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.drop_ip:set(ip,ngx.ctx.retry+1,lock_time)
			IpInfo.bt_ip_filter(ip,lock_time)
			ngx.ctx.is_type='cc'
			IpInfo.write_log('cc',ngx.ctx.cycle..'秒内累计超过'..ngx.ctx.limit..'次请求,封锁' .. lock_time .. '秒')
			IpInfo.write_drop_ip('cc',lock_time,ngx.ctx.cycle..'秒内累计超过'..ngx.ctx.limit..'次请求,封锁' .. lock_time .. '秒')
			local cc_count=ngx.shared.btwaf_data:get(ngx.ctx.url_token.."cc")
			if cc_count~=nil and cc_count then 
				if cc_count>=5 then 
					if not ngx.shared.btwaf_data:get(ngx.ctx.url_token.."url") and ngx.ctx.is_cc_url and not cc.is_api() then 
						ngx.shared.btwaf_data:set(ngx.ctx.url_token.."url",1,120)
					end
				else
					ngx.shared.btwaf_data:incr(ngx.ctx.url_token.."cc",1)
				end
			else
				ngx.shared.btwaf_data:set(ngx.ctx.url_token.."cc",1,240)
			end
			Public.request_incr(Config['cc']['status'])
			ngx.exit(Config['cc']['status'])
			return true
		else
			ngx.shared.btwaf:incr(token,1)
			ngx.shared.btwaf:incr(token2,1)
		end
	else
		ngx.shared.btwaf:set(token,1,ngx.ctx.cycle)
		ngx.shared.btwaf:set(token2,1,ngx.ctx.cycle)
	end
	return false
end

-- 简单CC检测
function cc.header_cc()
    local ip=ngx.ctx.ip
	if not Config['cc']['open'] or not ngx.ctx.site_cc then return false end
	local token = ngx.md5(ip .. ngx.ctx.ua.. 'text/html')
	local count= ngx.shared.btwaf_data:get(token)
	--count2 用于判断是否为解封了的IP
	local token2 = ngx.md5(ip .. '_' ..'header_cc')
	local count2= ngx.shared.btwaf_data:get(token2)
	if count and not count2 then 
	    ngx.shared.btwaf_data:delete(token)
	    count=0
	end
	if count and count2 then
		if ngx.ctx.limit<120 then ngx.ctx.limit=120 end
		if ngx.ctx.cycle<60 then ngx.ctx.cycle=60 end
		if count > ngx.ctx.limit*3 then
			return true
		else
			ngx.shared.btwaf_data:incr(token,1)
			ngx.shared.btwaf_data:incr(token2,1)
		end
	else
		ngx.shared.btwaf_data:set(token,1,ngx.ctx.cycle)
		ngx.shared.btwaf_data:set(token2,1,ngx.ctx.cycle)
	end
	return false
end

--增强CC检测
function cc.cc3()
    local uri_request_args=ngx.ctx.get_uri_args
    local server_name =ngx.ctx.server_name
	if not Config['cc']['open'] or not ngx.ctx.site_cc then return false end
	if not Site_config[server_name] then return false end
	if  ngx.ctx.ua==nil then return false end
    if cc.cc_uri_white() then return false end 
	if cc.is_api() then return false end
	if ngx.var.http_X_Requested_With and ngx.var.http_X_Requested_With=="XMLHttpRequest" then return false end
	if not Site_config[server_name]['cc']['increase'] then 
        if  Config['url_cc_param']~=nil and ngx.ctx.url_split then 
            for k,v in pairs(Config['url_cc_param']) do 
                if v['stype']=='regular' then 
                    if ngx.re.match(ngx.ctx.url_split,k) then 
                        local param_count=Public.arrlen(v['param'])
                        if param_count>=1 and Public.count_sieze(uri_request_args)>=1 then 
                           local count =0
                            for _,v2 in ipairs(v['param']) do 
                                if uri_request_args[v2] then 
                                    count=count+1
                                end 
                            end
                            if count==param_count then 
                                if v['type']==1 then 
                                    cc.renji_cc("btwaf")
                                elseif v['type']==2 then 
                                    cc.renji_cc("code")
                                elseif v['type']==3 then 
                                    cc.renji_cc("renji")
                                elseif v['type']==4 then 
                                    cc.renji_cc("huadong")
                                end
                            end 
                        elseif param_count==0 then 
                            if v['type']==1 then 
                                cc.renji_cc("btwaf")
                            elseif v['type']==2 then 
                                cc.renji_cc("code")
                            elseif v['type']==3 then 
                                cc.renji_cc("renji")
                            elseif v['type']==4 then 
                                cc.renji_cc("huadong")
                            end
                        end
                    end 
                else
                    if k == ngx.ctx.url_split then 
                        local param_count=Public.arrlen(v['param'])
                        if param_count>=1 and Public.count_sieze(uri_request_args)>=1 then 
                            local count =0
                            for _,v2 in ipairs(v['param']) do 
                                if uri_request_args[v2] then 
                                    count=count+1
                                end 
                            end
                            if count==param_count then 
                                if v['type']==1 then 
                                    cc.renji_cc("btwaf")
                                elseif v['type']==2 then 
                                    cc.renji_cc("code")
                                elseif v['type']==3 then 
                                    cc.renji_cc("renji")
                                elseif v['type']==4 then 
                                    cc.renji_cc("huadong")
                                end
                            end 
                        else
                            if v['type']==1 then 
                                cc.renji_cc("btwaf")
                            elseif v['type']==2 then 
                                cc.renji_cc("code")
                            elseif v['type']==3 then 
                                cc.renji_cc("renji")
                            elseif v['type']==4 then 
                                cc.renji_cc("huadong")
                            end
                        end 
                    end 
                end
            end 
        end 
	end
	if Site_config[server_name]['cc']['cc_increase_type']=='code' then 
		cc.renji("code")
	elseif Site_config[server_name]['cc']['cc_increase_type']=='renji' then 
		cc.renji("renji")
	elseif Site_config[server_name]['cc']['cc_increase_type']=='huadong' then 
		cc.renji("huadong")
	elseif Site_config[server_name]['cc']['cc_increase_type']=='browser' then 
		cc.renji("browser")
	else 
		cc.renji("btwaf")
	end
end



-- 单URLCC检测
function cc.cc_uri_frequency()
    if Config['cc_uri_frequency'] ~=nil then 
        local url_data=ngx.ctx.url_split
        local ip=ngx.ctx.ip
        if Config['cc_uri_frequency'][url_data] then 
                if Config['cc_uri_frequency'][url_data]['frequency']==nil then return false end
                if Config['cc_uri_frequency'][url_data]['cycle']==nil then return false end
            	local token = ngx.md5(ip .. 'frequency' .. url_data)
            	local count,_ = ngx.shared.btwaf:get(token)
            	if count then
            		if count > tonumber(Config['cc_uri_frequency'][url_data]['frequency']) then
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
            		    IpInfo.bt_ip_filter(ip,lock_time)
            			ngx.ctx.is_type='cc'
            			IpInfo.write_log('cc',Config['cc_uri_frequency'][url_data]['cycle']..'秒内请求单一URL:'..url_data..'累计超过'..Config['cc_uri_frequency'][url_data]['frequency']..'次请求,封锁' .. lock_time .. '秒')
            			IpInfo.write_drop_ip('cc',lock_time,Config['cc_uri_frequency'][url_data]['cycle']..'秒内请求单一URL '..url_data..' '..Config['cc_uri_frequency'][url_data]['frequency']..'次请求,封锁' .. lock_time .. '秒')
            			Public.request_incr(Config['cc']['status'])
            			ngx.var.waf2monitor_blocked="单URLCC检测触发拦截"
						ngx.exit(Config['cc']['status'])
            			return true
            		else
            			ngx.shared.btwaf:incr(token,1)
            		end
            	else
            		ngx.shared.btwaf:set(token,1,tonumber(Config['cc_uri_frequency'][url_data]['cycle']))
            	end
	           return false
        end
    end 
end 

return cc