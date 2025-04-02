local cookie ={}



function cookie.cookie()
	if not Config['cookie']['open'] or not Public.is_site_config('cookie') then return false end

	if ngx.ctx.cookie and BTWAF_OBJS.request_check.is_ngx_match(BTWAF_RULES.cookie_rules,ngx.ctx.cookie:get_all(),'cookie') then
	    ngx.ctx.is_type="恶意Cookie拦截"
		ngx.var.waf2monitor_blocked="恶意Cookie拦截"
		IpInfo.write_log('cookie','cookie拦截')
		Public.return_html(Config['get']['status'],BTWAF_RULES.get_html)
		return true
	end
	return false
end

return cookie