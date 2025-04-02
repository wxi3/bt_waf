local post={}

function post.post()
	if ngx.ctx.method == "GET" then return false end
	local content_length=tonumber(ngx.ctx.request_header['content-length'])
	if content_length == nil then return false end
	local content_type = ngx.req.get_headers(20000)["content-type"]
	if not content_type then return false end 
	if type(content_type)~='string' then 
		return Public.return_message(200,'Header Content-Type Error')
	end 
	if content_type and ngx.re.find(content_type, 'multipart',"oij") then return false end 
	if content_type and not ngx.re.find(content_type, 'application',"oij") then return false end 
	ngx.req.read_body()
	local request_args = ngx.req.get_post_args(1000000)
	if not request_args then
		if content_length >10000 then 
		    local request_uri22=ngx.ctx.url_split
			if request_uri22 ==nil then request_uri22='/' end
			local check_html = [[<html><meta charset="utf-8" /><title>Nginx缓冲区溢出</title><div>宝塔WAF提醒您,Nginx缓冲区溢出,传递的参数超过接受参数的大小,出现异常,<br>第一种解决方案:把当前url-->]]..'^'..request_uri22..[[加入到URL白名单中</br>第二种解决方案:面板-->nginx管理->性能调整-->client_body_buffer_size的值调整为2048K 或者4096K (推荐使用)</br></div></html>]]
			ngx.ctx.is_type="Nginx缓冲区溢出"
			ngx.ctx.error_rule="传递的参数超过接受参数的大小 第一种解决方案:点击URL加白按钮 >> 第二种解决方案:调整Nginx配置client_body_buffer_size的值调整为2048K 或者4096K (推荐使用)"
			IpInfo.write_log('upload','Nginx缓冲区溢出,传递的参数超过接受参数的大小,出现异常')
			ngx.header.content_type = "text/html;charset=utf8"
			ngx.header.Cache_Control = "no-cache"
			ngx.say(check_html)
			ngx.exit(200)
		end 
		return true
	end
	if Public.count_sieze(request_args)==0 then return false end 
	local list_data={}
	if type(request_args)=='table' then
		for k,v in pairs(request_args)
		do
			if type(v)=='table' then
				table.insert(list_data,Public.de_dict(k,v))
			end
            if type(v)=='string' then
				if not ngx.re.find(v,'^data:.+/.+;base64,',"jo") then
					if (#v) >=BTWAF_RULES.body_size then
					    ngx.ctx.is_type="参数长度拦截"
						IpInfo.write_log('sql',k..'     参数值长度超过80w已被系统拦截')
						Public.return_html(Config['post']['status'],BTWAF_RULES.post_html)
						return true
					end
				else
					local kkkkk=ngx.re.match(v,'^data:.+;base64,','ijo')
					if  kkkkk then 
						if kkkkk[0] then 
							if ngx.re.match(kkkkk[0],'php',"jo") or ngx.re.match(kkkkk[0],'jsp') then 
							    ngx.ctx.is_type='webshell防御'
								IpInfo.write_log('upload','拦截Bae64上传php文件')
								Public.return_html(Config['post']['status'],BTWAF_RULES.post_html)
							end 
						end
					end
				end
			end
		end
	end
	if content_type and  ngx.re.find(content_type, '^application/json',"oij") and ngx.req.get_headers(20000)["content-length"] and tonumber(ngx.req.get_headers(20000)["content-length"]) ~= 0 then
		local ok ,request_args_json = pcall(function()
			return Json.decode(ngx.req.get_body_data())
		end)
		if  ok and  type(request_args_json)=='table' then 
		    request_args_json=Public.process_json_args(request_args_json)
		    return BTWAF_OBJS.request_check.args_urlencoded(request_args_json)
		end 
	end 
	if list_data then 
		if Public.arrlen(list_data)>=1 then 
			for _,v2 in ipairs(list_data) do 
				BTWAF_OBJS.request_check.args_urlencoded(v2)
				request_args=Public.process_json_args(v2,request_args)
			end 
		else 
			request_args=Public.process_json_args(list_data,request_args)
		end 
	else
		request_args =Public.process_json_args(request_args)
	end
	if Public.count_sieze(request_args)>=8000 then
		ngx.ctx.is_type='参数超过8000拦截'
		ngx.ctx.error_rule = '参数太多POST传递的参数数量超过3000,拒绝访问,如有误报请点击误报'
		IpInfo.write_log('sql','参数太多POST传递的参数数量超过8000,拒绝访问,如有误报请点击误报')
		Public.return_html_data('网站防火墙','您的请求带有不合法参数，已被网站管理员设置拦截','网站防火墙提醒您POST传递的参数数量超过8000,拒绝访问','点击误报')
	end
	if Config['password']~=nil and Config['password'] and  request_args['password'] and request_args['username'] then 
	    if BTWAF_RULES.password[request_args['password']]==1 then 
	        if request_args['username']=="admin" or request_args['username']=="test" then 
    	        ngx.ctx.is_type="弱密码拦截"
				ngx.var.waf2monitor_blocked="弱密码拦截"
                IpInfo.write_log("sql","拦截弱密码"..request_args['password'].."， 如需要关闭请在全局设置中关闭弱密码拦截")
    	        Public.return_html_data('网站防火墙','您的登录所使用的密码为弱密码，已被管理员拦截','您的登录所使用的密码为弱密码,拒绝访问','全局设置中关闭弱密码拦截')
    	   end 
	    end
	end
	BTWAF_OBJS.request_check.args_urlencoded(request_args)
	return false
end


return post
