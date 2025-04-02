local re_api={}

--指定uri重写
function re_api.rewrite_url()
	if Site_config[ngx.ctx.server_name] == nil then
		return false
	end
	if Site_config[ngx.ctx.server_name]['rewrite_url'] == nil then
		return false
	end
	if type(Site_config[ngx.ctx.server_name]['rewrite_url']) ~= 'table' and #Site_config[ngx.ctx.server_name]['rewrite_url'] == 0 then
		return false
	end
	for k,v in pairs(Site_config[ngx.ctx.server_name]['rewrite_url']) do
        
		local cleaned_uri, _ = string.gsub(ngx.var.request_uri, "/+", "/")
		if cleaned_uri == v then
			ngx.header['Content-Type'] = 'text/htm;charset=utf8'
			ngx.exit(404)
			return true
		end
		if ngx.var.uri == k then
			if v == k then
				return false
			end
			ngx.exec(v)
		end
	end
	return false
end

return re_api