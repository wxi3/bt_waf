local scan_black={}

function scan_black.scan_black()
	if not Config['scan']['open'] or not Public.is_site_config('scan') then return false end
	if BTWAF_OBJS.request_check.is_ngx_match(BTWAF_RULES.scan_black_rules['cookie'],ngx.ctx.request_header['cookie'],false) then
	    ngx.ctx.is_type="扫描器拦截"
		ngx.var.waf2monitor_blocked="扫描器拦截"
        IpInfo.lan_ip('scan','扫描器拦截,已封锁IP')
		return true
	end
	if BTWAF_OBJS.request_check.is_ngx_match(BTWAF_RULES.scan_black_rules['args'],ngx.ctx.request_uri,false) then
        ngx.ctx.is_type="扫描器拦截"
		ngx.var.waf2monitor_blocked="扫描器拦截"
        IpInfo.lan_ip('scan','扫描器拦截,已封锁IP')
		return true
	end
	for key,value in pairs(ngx.ctx.request_header)
	do
		if BTWAF_OBJS.request_check.is_ngx_match(BTWAF_RULES.scan_black_rules['header'],key,false) then
            ngx.ctx.is_type="扫描器拦截"
			ngx.var.waf2monitor_blocked="扫描器拦截"
            IpInfo.lan_ip('scan','扫描器拦截,已封锁IP')
			return true
		end
	end
	return false
end

return scan_black