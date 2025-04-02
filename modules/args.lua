local args={}
local ngx_match = ngx.re.find


function args.args()
    ngx.ctx.is_type=""
    if Public.len(ngx.ctx.get_uri_args)==0 then return false end
    local request_args=Public.process_json_args(ngx.ctx.get_uri_args)
	if Public.len(request_args)>=10000 then 
	    ngx.ctx.is_type="参数超过10000拦截"
		ngx.ctx.error_rule = '参数太多GET传递的参数数量超过10000,拒绝访问,如有误报请点击误报'
		IpInfo.write_log('sql','参数太多GET传递的参数数量超过10000,拒绝访问,如有误报请点击误报')
	    Public.return_html_data('网站防火墙','您的请求带有不合法参数，已被网站管理员设置拦截','GET传递的参数数量超过10000,拒绝访问','点击误报')
	end
	--进入研判程序
	Check.args_urlencoded(request_args)
end




function args.url()
	if not Config['get']['open'] or not Public.is_site_config('get') then return false end
	if Public.count_sieze(BTWAF_RULES.url_rules)==0 then return false end 
	if BTWAF_OBJS.request_check.is_ngx_match(BTWAF_RULES.url_rules,ngx.unescape_uri(ngx.ctx.uri),'url') then
		IpInfo.write_log('download','恶意下载')
		ngx.var.waf2monitor_blocked="恶意下载"
		Public.return_html(Config['get']['status'],BTWAF_RULES.get_html)
		return true
	end
	--args_urlencoded({uri})
	end

function args.url_path()
	if Site_config[ngx.ctx.server_name] == nil then return false end
	for _,rule in ipairs(Site_config[ngx.ctx.server_name]['disable_path'])
	do
		if ngx_match(ngx.ctx.uri,rule,"isjo") then
			ngx.ctx.is_type='站点URL黑名单'
			ngx.var.waf2monitor_blocked="站点URL黑名单"
			IpInfo.write_log('path','站点URL黑名单')
			Public.return_html(Config['other']['status'],BTWAF_RULES.other_html)
			return true
		end
	end
	return false
end

function args.url_ext()
	if Site_config[ngx.ctx.server_name] == nil then return false end
	for _,rule in ipairs(Site_config[ngx.ctx.server_name]['disable_ext'])
	do
		if ngx_match(ngx.ctx.uri,"\\."..rule.."$","isjo") then
		    ngx.var.waf2monitor_blocked="禁止扩展名拦截"
			IpInfo.write_log('file','禁止扩展名拦截')
			Public.return_html(Config['other']['status'],BTWAF_RULES.other_html)
			return true
		end
	end
	return false
end


function args.get_body_character_string()
    local char_string=Config['uri_find']
    if not char_string then return false end
    if Public.arrlen(char_string) ==0 then return false end
    if Public.arrlen(char_string) >=1 then return char_string end
 end
 
function args.url_find()
	local get_body=args.get_body_character_string()
	if get_body then
		for __,v in pairs(get_body)
		do
			if ngx.re.find(ngx.unescape_uri(ngx.ctx.request_uri),v) then
			    ngx.var.waf2monitor_blocked="url关键词拦截"
			    ngx.ctx.is_type="url关键词拦截"
			    IpInfo.lan_ip('other','url关键词拦截、触发的关键词为:['..v.."] 、已被系统封锁IP >> 如需关闭此条规则请在WAF-全局设置-URL关键词拦截-删除当前关键词")
			end
		end
	end
	return false
 end



function args.php_path()
	if Site_config[ngx.ctx.server_name] == nil then return false end
	for _,rule in ipairs(Site_config[ngx.ctx.server_name]['disable_php_path'])
	do
        local url_data=""
        if not ngx.ctx.url_split then 
            url_data=ngx.ctx.request_uri 
        else
            url_data=ngx.ctx.url_split
        end
		if ngx_match(url_data,rule .. "/?.*\\.php$","isjo") then
		    ngx.ctx.is_type='目录防护'
		    ngx.var.waf2monitor_blocked="目录禁止执行PHP文件"
			IpInfo.write_log('file','Nginx网站防火墙提醒您:当前目录禁止执行PHP文件,如有误报请在Nginx防火墙--站点配置--设置--禁止运行PHP的URL删除当前目录')
			Public.return_html_data('当前目录禁止执行PHP文件','当前目录禁止执行PHP文件','您当前目录设置了禁止访问PHP文件','Nginx防火墙--站点配置--设置--禁止运行PHP的URL删除当前目录')
		end
	end
	return false
end


function args.url_request_mode()
    local method=ngx.ctx.method
    if Public.count_sieze(BTWAF_RULES.url_request)>=1 then
	    for _,v2 in pairs(BTWAF_RULES.url_request) do
	        if ngx.re.match(ngx.ctx.url_split,v2["url"],"jo") then
	            if v2["type"]=="accept" then 
	                if v2["mode"][method]==nil then 
	                    ngx.var.waf2monitor_blocked="禁止访问的请求类型"
	                    Public.return_html_data('网站防火墙','宝塔WAF提醒您不允许您当前的请求类型','宝塔WAF提醒您不允许您当前的请求类型','Nginx防火墙-->全局设置-->URL请求类型拦截-->增加当前 【'..method..'】请求类型')
					   return true
	                end 
	            elseif v2["type"]=="refuse" then
	                if v2["mode"][method]~=nil then 
	                    ngx.var.waf2monitor_blocked="禁止访问的请求类型"
	                    Public.return_html_data('网站防火墙','宝塔WAF提醒您不允许您当前的请求类型','宝塔WAF提醒您不允许您当前的请求类型','Nginx防火墙-->全局设置-->URL请求类型拦截-->删除当前 【'..method..'】请求类型')
						return true
	                end 
	            end
	        end 
	   end 
	end
	return false
end 



function args.url_tell()
	if Site_config[ngx.ctx.server_name] == nil then return false end
	for _,rule in ipairs(Site_config[ngx.ctx.server_name]['url_tell'])
	do
		if ngx_match(ngx.ctx.uri,rule[1],"isjo") then
			if ngx.ctx.get_uri_args[rule[2]] ~= rule[3] then
				ngx.ctx.is_type="受保护的URL"
				ngx.var.waf2monitor_blocked="受保护的URL"
				IpInfo.write_log('url_tell','受保护的URL')
				Public.return_html(Config['other']['status'],BTWAF_RULES.other_html)
				return true
			end
		end
	end
	return false
end

function args.url_rule_ex()
	if Site_config[ngx.ctx.server_name] == nil then return false end
	if Public.count_sieze(Site_config[ngx.ctx.server_name]['url_rule'])==0 then return false end
    local request_args = nil
	if ngx.ctx.method == "POST" and not ngx.req.get_post_args() then
		local content_length=tonumber(ngx.ctx.request_header['content-length'])
		local max_len = 64 * 10240
		
		if content_length < max_len then
			ngx.req.read_body()
			request_args = ngx.req.get_post_args()
		end
	end
	for _,rule in ipairs(Site_config[ngx.ctx.server_name]['url_rule'])
	do
		if ngx_match(ngx.ctx.uri,rule[1],"isjo") then
			if BTWAF_OBJS.request_check.is_ngx_match(rule[2],ngx.ctx.get_uri_args,false) then
				ngx.ctx.is_type="URL专用过滤"
				ngx.var.waf2monitor_blocked="URL专用过滤"
				IpInfo.write_log('url_rule','URL_路由拦截')
				Public.return_html(Config['other']['status'],BTWAF_RULES.other_html)
				return true
			end
			
			if ngx.ctx.method == "POST" and request_args ~= nil then 
				if BTWAF_OBJS.request_check.is_ngx_match(rule[2],request_args,'post') then
					ngx.ctx.is_type="URL专用过滤"
					ngx.var.waf2monitor_blocked="URL专用过滤"
					IpInfo.write_log('post','URL_路由拦截')
					Public.return_html(Config['other']['status'],BTWAF_RULES.other_html)
					return true
				end
			end
		end
	end
	return false
end


return args