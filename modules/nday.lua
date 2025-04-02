local nday={}
local ngx_match = ngx.re.find

function nday.ThinkPHP_RCE5_0_23()
	if ngx.ctx.method == "POST" then
		ngx.req.read_body()
		local data = ngx.req.get_post_args()
		if data==nil then return false end 
		if data['_method']  and data['method'] and data['server[REQUEST_METHOD]'] then
		    ngx.ctx.is_type='ThinkPHP攻击'
			ngx.var.waf2monitor_blocked="ThinkPHP攻击"
			IpInfo.lan_ip('php','拦截ThinkPHP 5.x RCE 攻击')
		end
		if data['_method']  and data['method'] and data['server[]'] and data['get[]'] then
		    ngx.ctx.is_type='ThinkPHP攻击'
			ngx.var.waf2monitor_blocked="ThinkPHP攻击"
			IpInfo.lan_ip('php','拦截ThinkPHP 5.x RCE 攻击')
		end
		if type(data['_method'])=='string' then 
			if data['_method'] and ngx_match(data['_method'],'construct','ijo') then
                ngx.ctx.is_type='ThinkPHP攻击'
				ngx.var.waf2monitor_blocked="ThinkPHP攻击"
                IpInfo.lan_ip('php','拦截ThinkPHP 5.x RCE 攻击')
			end
		end
		if type(data['_method'])=='table' then 
		    if not data['_method'] then return false end
			for _,_v2 in pairs(data['_method']) do 
				if type(_v2)=='string' then 
					if ngx_match(_v2,'construct','ijo') then 
						ngx.ctx.is_type='ThinkPHP攻击'
						ngx.var.waf2monitor_blocked="ThinkPHP攻击"
						IpInfo.lan_ip('php','拦截ThinkPHP 5.x RCE 攻击,并且被封锁IP')
					end 
				end 
			end 
		end
	end
	return false
end

function nday.ThinkPHP_3_log()
    local uri=ngx.ctx.uri
	if string.find(uri,'^/Application/.+log$') or string.find(uri,'^/Application/.+php$') or string.find(uri,'^/application/.+log$') or string.find(uri,'^/application/.+php$') then 
	    ngx.ctx.is_type='ThinkPHP攻击'
		ngx.var.waf2monitor_blocked="ThinkPHP攻击"
		IpInfo.lan_ip('php','拦截ThinkPHP 3.x 获取敏感信息操作,并且被封锁IP')
	end
	if string.find(uri,'^/Runtime/.+log$') or string.find(uri,'^/Runtime/.+php$')  or string.find(uri,'^/runtime/.+php$') or string.find(uri,'^/runtime/.+log$')then 
	    ngx.ctx.is_type='ThinkPHP攻击'
		ngx.var.waf2monitor_blocked="ThinkPHP攻击"
		IpInfo.lan_ip('php','拦截ThinkPHP 3.x 获取敏感信息操作,并且被封锁IP')
	end
	return false
end

function nday.error_transfer_encoding()
	if Site_config then 
		if Site_config[ngx.ctx.server_name] then 
			if Site_config[ngx.ctx.server_name]['cdn'] then return false end 
		end 
	end 
	if ngx.ctx.request_header['transfer-encoding'] == nil then return false end 
	if ngx.ctx.request_header['transfer-encoding'] then
	    ngx.ctx.is_type='拦截分块请求'
		ngx.var.waf2monitor_blocked="拦截分块请求"
		IpInfo.lan_ip('scan','拦截 Transfer-Encoding 块请求,并且被封锁IP')
		return true
	else
		return false
	end
end


function nday.loadcms()
	if Config['cms_rule_open']~=nil and  ngx.ctx.cms_rule_name~=nil and ngx.ctx.cms_check_param ~=nil then 
		ngx.ctx.is_type="CMS专属规则"
		ngx.var.waf2monitor_blocked="CMS专属规则"
		IpInfo.write_log("通用漏洞拦截",ngx.ctx.cms_check_param["cms_type"].."专属规则".." >> 拦截规则:"..ngx.ctx.cms_check_param["info"].." >> 如需关闭此条规则请到 WAF页面-->专属规则--> 规则ID: "..ngx.ctx.cms_check_param["ruleid"])
		Public.return_html(Config['get']['status'],BTWAF_RULES.get_html)
	end 
end

return nday