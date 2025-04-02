--[[
#-------------------------------------------------------------------
# 宝塔Linux面板
#-------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
#-------------------------------------------------------------------
# Author: 梁凯强 <1249648969@qq.com>
#-------------------------------------------------------------------
#----------------------
# WAF防火墙 敏感词过滤
#----------------------
]]--

local body_filter={}

function body_filter.check_type()
  if ngx.header.content_type== nil then return false end
  if string.find(ngx.header.content_type, "text/html") ~= nil then
    return true
  end
  return false
end

-- 浏览器验证
function body_filter.browser()
    local server_name=ngx.ctx.server_name
    if  Site_config and Site_config[server_name]~=nil and Site_config[server_name]['cc']~=nil and Site_config[server_name]['cc']['cc_increase_type']=='browser' then
        if ngx.ctx.white_rule==false  and  Site_config[server_name] then 
            local ip =ngx.ctx.ip
        	local ua=ngx.ctx.ua 
        	local token2=ngx.md5(ip..ua..server_name.."browser"..server_name)
        	if not ngx.shared.btwaf:get(token2) then 
                local chunk= ngx.arg[1]
                if chunk then 
                    local chunks=""
                    if #chunk<100 then 
                          chunks=chunk
                    else
                        chunks =string.sub(chunk,1,100)
                    end 
                    if ngx.re.find(chunks,[[<!Doctype html>]],'ijo')  then
                        if ngx.var.uri=="/Rxizm32rm3CPpyyW_yanzheng_ip.php" then return false end 
                    	local token=ngx.md5(ip..ua..server_name.."browser"..ngx.ctx.today)
                    	local cac_token=ngx.shared.btwaf:get(token)
                    	if not cac_token or cac_token==nil then 
                    	    ngx.arg[1]=Public.get_html(ip,ua,server_name,ngx.ctx.today)..ngx.arg[1]
                    	    return true
                    	end 
                        local yanzheng_ipdata=ngx.md5(ip..ua)
                        if ngx.shared.btwaf_data:get(cac_token) then 
                            if ngx.shared.btwaf_data:get(cac_token) ~=yanzheng_ipdata then 
                                ngx.shared.btwaf_data:delete(cac_token)
                                ngx.shared.btwaf:delete(token)
                                    ngx.arg[1]=Public.get_html(ip,ua,server_name,ngx.ctx.today)..ngx.arg[1]
                                return true
                            end 
                        end
                        if ngx.ctx.cookie and  ngx.ctx.cookie:get(token) and ngx.ctx.cookie:get(token)==cac_token then 
                            return true
                        end
                        ngx.arg[1]=Public.get_html(ip,ua,server_name,ngx.ctx.today)..ngx.arg[1]
                        return true
                    end
                end
            end 
        end 
    end 
end

--替换body中的敏感词
function body_filter.run_body()
    if BTWAF_RULES.body_character_len==0 and ngx.ctx.crawler_html==false then return false end
    local whole=""
    local chunk, eof = ngx.arg[1], ngx.arg[2]
    local buffered = ngx.ctx.buffered
    if not buffered then
            buffered = {}
            ngx.ctx.buffered = buffered
    end
    if chunk ~= "" then
        buffered[#buffered + 1] = chunk
        ngx.arg[1] = nil
    end
    if eof then
        whole = table.concat(buffered)
        if #whole>1024000 then 
			ngx.arg[1]=whole 
			return false 
		end 
        ngx.ctx.buffered = nil
        local v3=""
        local c1=""
        if BTWAF_RULES.body_character then
            for __,v in pairs(BTWAF_RULES.body_character)
            do 
                for k2,v2 in pairs(v)
                do
                    if type(k2)=='string' then
                        if #v2 >#k2 then 
                            v2 =string.sub(v2, 0, #k2)
                        end 
                        if #v2 <#k2 then 
                            v3 =string.sub('                                                                                           ', 0,  #k2-#v2)
                            v2=v2..v3
                        end 
                        whole= string.gsub(whole,k2,v2)
                    end
                end
            end
        end
        if ngx.ctx.crawler_html then 
            ngx.arg[1]=Public.aes(whole)
        else 
            ngx.arg[1]=whole
        end
    end
end 

function body_filter.resp_header()
    local data="HTTP/1.1 500 Internal Server Error"
    data=data.."\nServer:nginx"
    for key, valu in pairs(ngx.resp.get_headers()) do
		if type(valu) == "string" then
			data = data .. key .. ": " .. valu .. "\n"
		end
		if type(valu) == "table" then
			for key2, val2 in pairs(valu) do
				data = data .. key .. ": " .. val2 .. "\n"
			end
		end
	end
    return data
end

function body_filter.is_error()
    --处理错误信息返回
	if  Config['sensitive_info']==nil or not Config['sensitive_info'] then return false end
    if ngx.ctx.buffered then
        if #ngx.ctx.buffered > 524288 then
            ngx.arg[1]=ngx.ctx.buffered
            return false
        end
    end
    ngx.ctx.buffered = (ngx.ctx.buffered or "") .. ngx.arg[1]
    ngx.arg[1]=nil
    if ngx.arg[2] then
        if BTWAF_OBJS.error_info.mysql_error(ngx.ctx.buffered) then 
            ngx.ctx.body_info=true
            --获取返回的header 
            ngx.ctx.is_type="敏感信息拦截"
            ngx.ctx.buffered=body_filter.resp_header().."\n"..ngx.ctx.buffered
            IpInfo.write_log("sql","网页报错返回存在SQL报错信息， 如需要关闭请在全局设置中关闭敏感信息检测")
            ngx.arg[1]=Public.return_html_body("网站防火墙",'网页报错返回存在敏感信息，已被管理员拦截','网页报错返回存在敏感信息，已被管理员拦截','全局设置中关闭敏感信息检测')
            return true
        end 
        ngx.arg[1]=ngx.ctx.buffered
    end
end 


function body_filter.set_html()
    if ngx.ctx.html and ngx.ctx.server_name then 
        if ngx.ctx.is_body==nil then
            local cunk=ngx.arg[1]
            if #cunk>100 then 
                ngx.ctx.is_body=true
            end
        end
        if ngx.arg[2] and ngx.ctx.is_body then 
            local token=ngx.md5(ngx.ctx.server_name..':'..ngx.ctx.url_split)
            if not ngx.shared.smart_cc:get(token)  then 
                ngx.shared.smart_cc:set(token,"text/html",3600)
            end
        end 
    end
end

function body_filter.crawler_picture()
    if ngx.ctx.is_crawler_picture==true then return false end 
    if ngx.ctx.is_crawler_picture_error==false then return false end 
    local types=""
    if ngx.ctx.is_crawler_picture_error==nil then ngx.ctx.is_crawler_picture_error=true end 
    -- 取uri的后缀名
    if not ngx.ctx.url_split then  return false end 
    if #ngx.ctx.url_split<4 then return false end 
    -- 取最后三位
    local ext=ngx.ctx.url_split:sub(#ngx.ctx.url_split-3,#ngx.ctx.url_split)
    if ngx.header.content_type=="image/png" and ext==".png" then 
        types="png"  
    elseif ngx.header.content_type=="image/jpeg" and ext==".jpg" then 
        -- 判断是否为jgp 或者jpge
        types="jpg"
    elseif ngx.header.content_type=="image/jpeg" and ext=="jpge" then 
        -- 判断是否为jgp 或者jpge
        types="jpge"
    else 
        ngx.ctx.is_crawler_picture_error=false
    end 
    ngx.ctx.buffered_tmp = (ngx.ctx.buffered_tmp or "") .. ngx.arg[1]
    if ngx.arg[2] then
        Public.gd_png(ngx.ctx.buffered_tmp,types,ngx.ctx.server_name)
        ngx.ctx.buffered_tmp=nil
    end
end 

-- 入口函数
function body_filter.body_btwaf()
	if not Config['open'] or not Public.is_site_config('open') then return false end
    if ngx.arg[2] then Logs.upstream_response_time() end 
	ngx.ctx.body_filter_run=true
    if ngx.status==500 and ngx.ctx.white_rule==false then  body_filter.is_error() end 
    if ngx.status~=200 then  return false end  
    if ngx.ctx.crawler_picture and ngx.header.content_type and  #ngx.header.content_type>6 and  ngx.header.content_type:sub(1,5)=="image" then 
        return body_filter.crawler_picture()
    end
    if not body_filter.check_type() then return false end 
    if Site_config[ngx.ctx.server_name]==nil then return false end
    if body_filter.browser() then return false end
    body_filter.run_body()
end

local ok,error = pcall(function()
	return body_filter.body_btwaf()
end)
if not ok then
    --10分钟记录一次
    if not ngx.shared.spider:get("btwaf_body") then 
        Public.logs(error)
        ngx.shared.spider:set("btwaf_body",1,360)
    end
end
