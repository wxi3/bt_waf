local user_agent={}


function user_agent.user_agent()
	if not Config['user-agent']['open'] or not Public.is_site_config('user-agent') then return false end
	if BTWAF_OBJS.request_check.is_ngx_match(BTWAF_RULES.user_agent_rules,ngx.ctx.ua,'user_agent') then 
	    ngx.ctx.is_type="恶意爬虫"
	    ngx.var.waf2monitor_blocked="恶意爬虫"
	    IpInfo.lan_ip('user_agent','UA存在问题已经被系统拦截。并封锁IP') return true end
	return false
end


return user_agent