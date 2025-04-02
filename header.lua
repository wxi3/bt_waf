local header_filter={}
local cpath="/www/server/btwaf/"
local webshell_total="webshell_total/"
local today_H=os.date("%Y-%m-%d-%H")


function header_filter.read_webshell()
    local webshell_total="webshell_total/"
    if ngx.shared.btwaf_data:get(cpath..webshell_total..today_H..".json") then 
        return ngx.shared.btwaf_data:get(cpath..webshell_total..today_H..".json")
    end 
    local ok2,data=pcall(function()
              local data=Public.read_file_body(cpath..webshell_total..today_H..".json")
                return Json.decode(data)
    end )
    if ok2 then 
        ngx.shared.btwaf_data:set(cpath..webshell_total..today_H..".json",data,3600)
        return data
    else
        data={}
        ngx.shared.btwaf_data:set(cpath..webshell_total..today_H..".json",data,3600)
        Public.write_file(cpath..webshell_total..today_H..".json",Json.encode(data))
        return data
    end
end 


--记录PHP的访问日志
function header_filter.webshell_san()
    if ngx.ctx.url_split then 
        if ngx.re.match(ngx.ctx.url_split,'php$',"jo") then 
            local paths =ngx.var.document_root..ngx.ctx.url_split
            if ngx.ctx.url_split=="/Rxizm32rm3CPpyyW_yanzheng_ip.php" then return false end 
            if ngx.shared.btwaf_data:get(ngx.md5(paths)) then return false end 
            if ngx.ctx.url_split~="index.php" then 
                local webshell_info=header_filter.read_webshell()
                local flag =true
                if webshell_info[paths]~=nil then 
                    flag=false
                end 
                if flag then 
                    ngx.shared.btwaf_data:set(ngx.md5(paths),1,3600)
                    webshell_info[paths]=os.time()
                    ngx.shared.btwaf_data:set(cpath..webshell_total..today_H..".json",webshell_info,3600)
                    if not ngx.shared.btwaf_data:get(cpath..webshell_total..today_H..".json".."write_file") then 
                        local info=Public.count_sieze(webshell_info)
                        if info>=200 then 
                            ngx.shared.btwaf_data:delete(cpath..webshell_total..today_H..".json")
                            local data={}
                            Public.write_file(cpath..webshell_total..today_H..".json",Json.encode(data))
                        else
                            Public.write_file(cpath..webshell_total..today_H..".json",Json.encode(webshell_info))
                        end 
                        ngx.shared.btwaf_data:set(cpath..webshell_total..today_H..".json".."write_file",1,2)
                    end
                end
            end 
        end 
    end 
end 

function header_filter.header_btwaf()
    --获取返回的类型
    if not Config['open'] or not Public.is_site_config('open') then return false end
    if ngx.status==301 or ngx.status==302 then 
        if ngx.ctx.white_rule==true then return false end
        if ngx.ctx.proxy==nil then ngx.ctx.proxy=false end
		--解决301/302 拦截不了的问题
        ngx.ctx.request_header = ngx.req.get_headers(20000)
        ngx.ctx.server_name = Public.get_server_name_waf()
        local ip = IpInfo.get_client_ip_bylog()
        if ngx.var.http_user_agent then
            ngx.ctx.ua = ngx.var.http_user_agent
        else
            ngx.ctx.ua = "_"
    		ngx.ctx.request_header['user-agent']="_"
        end
        ngx.ctx.endtime=3600
        ngx.ctx.retry=10
        ngx.ctx.method = ngx.req.get_method()
        ngx.ctx.time = tonumber(ngx.now())
        ngx.ctx.request_uri = ngx.var.request_uri
        if BTWAF_OBJS.white_balck.ip_white() then 
            ngx.ctx.proxy=true
            ngx.ctx.white_rule=true return true end  
        BTWAF_OBJS.white_balck.ip_black()
        if BTWAF_OBJS.white_balck.ua_white() then  
            ngx.ctx.proxy=true
            ngx.ctx.white_rule=true return true end
        BTWAF_OBJS.white_balck.ua_black()
        if BTWAF_OBJS.white_balck.url_white() then 
            ngx.ctx.proxy=true
            ngx.ctx.white_rule=true return true end
		BTWAF_OBJS.white_balck.url_black()
        BTWAF_OBJS.white_balck.drop_abroad()
        BTWAF_OBJS.white_balck.drop_china()
        BTWAF_OBJS.city.reg_tions()
        BTWAF_OBJS.city.reg_city()
		BTWAF_OBJS.malicious_ip.malicious_ip()
        if BTWAF_OBJS.white_balck.header_drop(ip) then 
            Public.request_incr(Config['cc']['status'])
            ngx.exit(Config['cc']['status'])
        end
        ngx.ctx.proxy=true
        return false
    end
    local content_type=ngx.header.content_type
    -- 获取状态码
    if ngx.status==200 and content_type and ngx.re.find(content_type,"text/html","jo") then 
        ngx.header.content_length = nil
        ngx.ctx.html=true
    end 
	if ngx.status==200 then 
        if ngx.re.match(content_type,"application/json","ijo") then 
            if not ngx.shared.cc:get(ngx.ctx.url_token) then ngx.shared.cc:set(ngx.ctx.url_token,"json",360) end
        end
    end 
	if ngx.status==502 and ngx.ctx.is_cc_url then 
        if ngx.shared.cc:get(ngx.ctx.url_token.."html") then
            local count=ngx.shared.cc:get(ngx.ctx.url_token.."html")
            if count>10 then 
                if not ngx.shared.btwaf_data:get(ngx.ctx.url_token.."url") then  ngx.shared.btwaf_data:set(ngx.ctx.url_token.."url",1,120) end
            else
                ngx.shared.cc:incr(ngx.ctx.url_token.."html",1)
            end 
        end 
    end
    if ngx.ctx.method=="GET" and  ngx.status==200  and  content_type~=nil and  Config['cc']['open'] and  ngx.ctx.site_cc then
        local flag=true
        --取第一个字符串
        if ngx.ctx.white_rule then 
            flag=false
        end 
        if ngx.re.match(content_type,'text/html',"ijo") then 
            --如果网页有大小
			if not ngx.shared.cc:get(ngx.ctx.url_token.."html") then ngx.shared.cc:set(ngx.ctx.url_token.."html",1,360) end
            if ngx.header.content_length then 
                local content_length=tonumber(ngx.header.content_length)
                if content_length<100 then 
                    flag=false
                end
            end
            --如果是首页/ 那么随机百分之50的概率进入到CC中
            if ngx.ctx.url_split=="/" then 
                local random=math.random(1,100)
                if random<=50 then 
                    flag=false
                end 
            end
            if flag then 
                --检测CC
                if BTWAF_OBJS.cc.header_cc() then 
                    -- 如果IP不在封锁状态中则记录日志
                    if not ngx.shared.drop_ip:get(ngx.ctx.ip) then 
                        IpInfo.lan_ip('cc',ngx.ctx.cycle..'秒内累计超过'..ngx.ctx.limit..'次请求网页,触发CC拦截已被系统封锁IP')
                    end
                end
            end
        end
    end 
    if ngx.status==200 and ngx.ctx.method=="POST" and ngx.re.match(ngx.ctx.url_split,'php$',"jo") then
		if Config['webshell_opens'] then 
            header_filter.webshell_san()
		end 
    end 
    if ngx.status~=404 then
        return false end
    local is_open_status=false
    if Config['scan_conf']['open'] ~=nil then 
        is_open_status=Config['scan_conf']['open']
    end
    --周期
    local cycle=60
    if Config['scan_conf']['cycle'] ~=nil then 
        cycle=tonumber(Config['scan_conf']['cycle'])
    end 
    --最大次数
    local limit=120
    if Config['scan_conf']['limit'] ~=nil then 
        limit=tonumber(Config['scan_conf']['limit'])
    end 
    if ngx.status==404 and is_open_status and not ngx.shared.spider:get(ngx.ctx.ip) and ngx.ctx.white_rule==false then
        if not ngx.shared.btwaf_data:get(ngx.ctx.ip..'_san') then
            ngx.shared.btwaf_data:set(ngx.ctx.ip..'_san',1,cycle)
        else 
            ngx.shared.btwaf_data:incr(ngx.ctx.ip..'_san',1)
        end 
        if ngx.shared.btwaf_data:get(ngx.ctx.ip..'_san') >limit then 
            --如果IP不在封锁状态中则记录日志
            if not ngx.shared.drop_ip:get(ngx.ctx.ip) then 
                IpInfo.lan_ip('scan',cycle..'秒内 访问超过'..limit.."次不存在的页面.如需要调整请在【全局配置-常见扫描器】中修改频率")
            end
        end
    end
end
local ok,error = pcall(function()
    if not Config['open'] or not Public.is_site_config('open') then return false end
	ngx.ctx.header_btwaf=true
    local ingos=header_filter.header_btwaf()
    Logs.start()
	return ingos
end)

if not ok then
    --10分钟记录一次
    if not ngx.shared.spider:get("btwaf_header") then 
        Public.logs(error)
        ngx.shared.spider:set("btwaf_header",1,360)
    end 
end 
