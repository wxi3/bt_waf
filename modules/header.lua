local header ={}


function  header.return_error3(method,msg)
	ngx.ctx.error_rule = msg
	IpInfo.write_log(method,msg)
end 

function header.method_type_check(method)
    local method_type={}
    if not Config['method_type'] then 
        return true
    else
        method_type=Config['method_type']
    end
    for _,v in ipairs(method_type) do
        if method == v[1] and not v[2] then
            
            return false 
        end
    end 
    return true 
end 

function header.header_check(header_data,len_data,header)
    for i,v in pairs(header_data) do
            if header == v[1] then 
                 if tonumber(len_data)>tonumber(v[2]) then return true end 
                 return false
            end
    end 
   	if len_data>20000 then return true end
    return false
end 



-- 取url后面的值
function header.get_http_referer(referer)
    for i = 1, #referer do
        local byte = referer:byte(i)
        if byte == 63 then
            return 
        end
    end
    return ngx.unescape_uri(referer)
end

function header.get_http_referer(referer)
    local list = {}
    local start_pos = string.find(referer, '?') or 1
    flag=false
    while start_pos <= #referer do
        local equals_pos = string.find(referer, '=', start_pos)
        if not equals_pos then flag=true break end
        local and_pos = string.find(referer, '&', equals_pos) or (#referer + 1)

        local param_value = ngx.unescape_uri(string.sub(referer, equals_pos+1, and_pos-1))
        table.insert(list, param_value)
        start_pos = and_pos + 1
    end
    if flag then 
        return {referer}
    end 
    return list
end


function header.header_len_check(request_header)
    	--检测referer
	local referer=ngx.var.http_referer
	if referer then
		Check.args_urlencoded(ngx.unescape_uri(referer))
-- 		Check.args_urlencoded(header.get_http_referer(referer))

	end 
    
    local method=ngx.ctx.method
	if method=='PROPFIND' or  method=='PROPPATCH' or method=='MKCOL' or method=='CONNECT'  or method=='SRARCH' or method=='REPORT' then return false end
    if not header.method_type_check(method) then
        ngx.ctx.is_type="请求类型过滤"
    	header.return_error3(method,'宝塔WAF提醒您不允许您当前的请求类型'..method..'此请求类型已经被禁用。如需开启请在Nginx防火墙-->全局设置-->HTTP请求过滤-->请求类型过滤开启'..method..'请求') 
    	Public.return_html_data('网站防火墙','宝塔WAF提醒您不允许您当前的请求类型','宝塔WAF提醒您不允许您当前的请求类型','Nginx防火墙-->全局设置-->HTTP请求过滤-->请求类型过滤开启'..method..'请求')
    end
    if not request_header then  
        ngx.ctx.is_type="header获取失败"
    	header.return_error3(method,'宝塔WAF提醒您header获取失败,可能是头部请求太长,如有误报.请调整nginx的header获取大小')
    	Public.return_html_data('网站防火墙','网站防火墙提醒您header获取失败','网站防火墙提醒您header获取失败','调整nginx的header获取大小')
    end
    local header_data={}
    if not  Config['header_len'] then
        return false
    else
        header_data=Config['header_len']
    end 
    for i,v in pairs(request_header) do
      if  header.header_check(header_data,#v,i) then  
		if i=='cookie' or i=='user-agent' then return false end 
        header.return_error3(method,'网站防火墙提醒您header头部参数'..i..'太长，如有误报请在Nginx防火墙--全局设置--HTTP请求过滤--请求头过滤调整'..i..'的长度,如果没有这个'..i..'的选项需要添加建议把长度默认为10000')
      	Public.return_html_data('网站防火墙','网站防火墙提醒您header头部参数'..i..'太长','网站防火墙提醒您header头部参数'..i..'太长','Nginx防火墙-->全局设置-->HTTP请求过滤-->请求头过滤调整'..i..'的长度。如果没有这个'..i..'的选项需要添加建议把长度默认为10000')
      end
    end
end




function header.ua_whilie2(ua)
	if not ua then return false end 
	ua = string.lower(ua)
    if ngx.re.match(ua,'baiduspider',"jo") then return true end 
    if ngx.re.match(ua,'googlebot',"jo") then return true end 
    if ngx.re.match(ua,'360spider',"jo") then return true end 
    if ngx.re.match(ua,'sogou',"jo") then return true end 
    if ngx.re.match(ua,'yahoo',"jo") then return true end 
    if ngx.re.match(ua,'bingbot',"jo") then return true end 
    if ngx.re.match(ua,'yisouspider',"jo") then return true end 
	if ngx.re.match(ua,'haosouspider',"jo") then return true end 
	if ngx.re.match(ua,'sosospider',"jo") then return true end 
	if ngx.re.match(ua,'weixin',"jo") then return true end 
	if ngx.re.match(ua,'iphone',"jo") then return true end
	if ngx.re.match(ua,'android',"jo") then return true end 
end 

function header.header_lan(header2)
    if not Config['is_browser'] then return false end 
    if type(header2['connection'])~='string' then return false end 
    if header.ua_whilie2(ngx.ctx.ua) then return false end
    if Public.is_ssl() then return false end
    if header2['connection'] =='1' then 
        if ngx.ctx.method =='GET' then ngx.ctx.method='args' end 
        if ngx.ctx.method =='POST' then ngx.ctx.method ='post' end 
        ngx.ctx.is_type='非浏览器请求'
        Public.write_log('other','非浏览器请求已被系统拦截,如想关闭此功能如下操作:Nginx防火墙--全局设置--非浏览器拦截')
	    ngx.exit(200)
    end
end


function header.is_check_header()
    local count=0
	if type(ngx.ctx.request_header)=='table' then
		for _,v in pairs(ngx.ctx.request_header)
		do
			if type(v)=='table' then
				for k2,v2 in pairs(v) do 
				   count=count+1 
				end
            end
            if type(v)=="string" then 
                count=count+1
            end
		end
	end
	if count>800 then 
	    return IpInfo.lan_ip('scan','header字段大于800 被系统拦截') 
	end
    return false
end


return header