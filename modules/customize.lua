--[[
    @name 自定义规则匹配
    @role
    @author hezhihong
    @time 2023-11-17
    @version 1.0
]]--
local customize={}



--只匹配参数名
function customize.Param_name(option)
    if option==nil or option=="" or option["operator"] == nil or option["operator"] =="" or option["right_factor"] ==nil or option["right_factor"] =="" then return false end
    local right_factor=Public.split(option["right_factor"],",")
    if right_factor==nil or right_factor=="" then return false end
    for _,v in ipairs(right_factor) do
        --包含
        if option["operator"] =="in" then
            if ngx.ctx.get_uri_args[v]==nil then
                return false
            end
            --不包含
        elseif option["operator"] =="not_in" then
            if ngx.ctx.get_uri_args[v]~=nil then
                return false
            end
        end
    end

    return true
end


--请求参数的数量
function customize.Param_count(option)
    if option==nil or option=="" or option["operator"] == nil or option["operator"] =="" or option["right_factor"] ==nil or option["right_factor"] =="" then return false end
    local check_count=tonumber(option["right_factor"])
    --大于
    if option["operator"] =="gt" then
        if ngx.ctx.uri_args_count>check_count then
            return true
        end
    --大于或等于
    elseif option["operator"] =="egt" then
        if ngx.ctx.uri_args_count>=check_count then
            return true
        end
    --小于
    elseif option["operator"] =="lt" then
        if ngx.ctx.uri_args_count<check_count then
            return true
        end
    --小于或等于
    elseif option["operator"] =="elt" then
        if ngx.ctx.uri_args_count<=check_count then
            return true
        end
    --等于
    elseif option["operator"] =="eq" then
        if ngx.ctx.uri_args_count==check_count then
            return true
        end
    
    end
    return false
end


--只匹配请求头名称
function customize.Request_header_name(option)
    if option==nil or option=="" or option["operator"] == nil or option["operator"] =="" or option["right_factor"] ==nil or option["right_factor"] =="" then return false end
    --包含
    if option["operator"]=="in" then
        if ngx.ctx.request_header[option["right_factor"]]~=nil then
            return true
        end
    --不包含
    elseif option["operator"]=="not_in" then
        if ngx.ctx.request_header[option["right_factor"]]==nil then
            return true
        end
    --其他情况
    else 
        return false
    end
    return false
end


--匹配请求头名称和值
function customize.Request_header(option)
    if option==nil or option=="" or option["operator"] == nil or option["operator"] =="" or option["right_factor"] ==nil or option["right_factor"] =="" or option["left_factor"] ==nil or option["left_factor"] =="" then return false end
    -- --正则表达式，不区分大小写
    -- if option["operator"]=="regexp" then
    --     if ngx.re.match(ngx.ctx.request_header[option["left_factor"]],v,"isjo") then
    --         return true
    --     end
    --匹配开头，不区分大小写
    if option["operator"]=="prefix" then
        if ngx.re.match(ngx.ctx.request_header[option["left_factor"]],"^"..option["right_factor"],"isjo") then
            return true
        end
    --匹配结尾，不区分大小写
    elseif option["operator"]=="suffix" then
        if ngx.re.match(ngx.ctx.request_header[option["left_factor"]],option["right_factor"].."$","isjo") then
            return true
        end
    --等于/完全匹配（不区分大小写）
    elseif option["operator"]=="eq" then
        if ngx.ctx.request_header[option["left_factor"]]==option["right_factor"] then
            return true
        end
    --不等于（不区分大小写）
    elseif option["operator"]=="neq" then
        if ngx.ctx.request_header[option["left_factor"]]~=option["right_factor"] then
            return true
        end
    --模糊匹配（不区分大小写）
    elseif option["operator"]=="like" then
        if ngx.re.match(ngx.ctx.request_header[option["left_factor"]],option["right_factor"],"isjo") then
            return true
        end
    end
    return false


    
end



--匹配请求头的数量
function customize.Request_header_count(option)
    if option==nil or option=="" or option["operator"] == nil or option["operator"] =="" or option["right_factor"] ==nil or option["right_factor"] =="" then return false end
    local check_count=tonumber(option["right_factor"])
    --等于
    if option["operator"] =="eq" then
        if ngx.ctx.request_header_count==check_count then
            return true
        end
    --大于
    elseif option["operator"] =="gt" then
        if ngx.ctx.request_header_count>check_count then
            return true
        end
    --大于或等于
    elseif option["operator"] =="egt" then
        if ngx.ctx.request_header_count>=check_count then
            return true
        end
    --小于
    elseif option["operator"] =="lt" then
        if ngx.ctx.request_header_count<check_count then
            return true
        end
    --小于或等于
    elseif option["operator"] =="elt" then
        if ngx.ctx.request_header_count<=check_count then
            return true
        end
    end
end


--匹配ip
function customize.Ip(option)
    if option==nil or option=="" or option["operator"] == nil or option["operator"] =="" or option["right_factor"] ==nil or option["right_factor"] =="" then return false end
    --等于
    if option["operator"] =="eq" then
        if ngx.ctx.ip==option["right_factor"] then
            return true
        end
    --不等于
    elseif option["operator"] =="neq" then
        if ngx.ctx.ip~=option["right_factor"] then
            return true
        end
    end
    --包含
    if option["operator"]=="in" then 
        if BTWAF_RULES.customize_groups_table~=nil and BTWAF_RULES.customize_groups_table[option["right_factor"]]~=nil and BTWAF_RULES.customize_groups_table[option["right_factor"]]:match(ngx.ctx.ip) then
            return true 
        end
    --不包含
    elseif option["operator"]=="not_in" then
        if BTWAF_RULES.customize_groups_table~=nil and BTWAF_RULES.customize_groups_table[option["right_factor"]]~=nil and not BTWAF_RULES.customize_groups_table[option["right_factor"]]:match(ngx.ctx.ip) then
            return true 
        end
    end
    return false
end


--匹配ip段
function customize.Ip_range(option)
    if option==nil or option=="" or option["operator"] == nil or option["operator"] =="" or option["right_factor"] ==nil or option["right_factor"] =="" then return false end
    if BTWAF_RULES.customize_groups_table==nil or BTWAF_RULES.customize_groups_table[option["right_factor"]]==nil then return false end
    -- local ip_ranges = Public.split(option["right_factor"], ",")
    -- if ip_ranges==nil or ip_ranges=="" then return false end
        --包含                  
    if option["operator"] =="in" then
        if BTWAF_RULES.customize_groups_table~=nil and BTWAF_RULES.customize_groups_table[option["right_factor"]]~=nil and BTWAF_RULES.customize_groups_table[option["right_factor"]]:match(ngx.ctx.ip) then
            return true
        end
    --不包含
    elseif option["operator"] =="not_in" then
        if BTWAF_RULES.customize_groups_table~=nil and BTWAF_RULES.customize_groups_table[option["right_factor"]]~=nil and not BTWAF_RULES.customize_groups_table[option["right_factor"]]:match(ngx.ctx.ip) then
            return true
        end
    end
    -- end
    return false
end


--匹配ip组
function customize.Ip_group(option)
    if option==nil or option=="" or option["operator"] == nil or option["operator"] =="" or option["right_factor"] ==nil or option["right_factor"] =="" then return false end
    local rules = Public.split(option["right_factor"], ",")
    if rules==nil or rules=="" then return false end
    local flag=false
    for _,v in ipairs(rules) do
        if v=="malicious_ip" then 
            if option["operator"]=="in" then
                -- 云端恶意IP库
                if BTWAF_OBJS.malicious_ip.malicious_ip() then
                    return true
                end
            elseif option["operator"]=="not_in" then
                if BTWAF_OBJS.malicious_ip.malicious_ip() then
                    return false
                end
            end
        else 
            if option["operator"]=="in" then
                -- IP 白名单级别最高
                if BTWAF_RULES.ip_group_list[v]:match(ngx.ctx.ip) then
                    return true
                end
            elseif option["operator"]=="not_in" then
                if  BTWAF_RULES.ip_group_list[v]:match(ngx.ctx.ip) then
                    return false
                end
            end
        end
    end
    if not flag and option["operator"]=="not_in" then return true end
    return false
    
end

--匹配User_agent
function customize.User_agent(option)
    if option==nil or option=="" or option["operator"] == nil or option["operator"] =="" or option["right_factor"] ==nil or option["right_factor"] =="" then return false end
    --以,号分隔option["right_factor"]的值
    local right_factor=Public.split(option["right_factor"],"|")
    if right_factor==nil or right_factor=="" then return false end
    local flag = true
    for _,v in ipairs(right_factor) do
        --等于
        if option["operator"]=="eq" then 
            if v == ngx.ctx.ua then
                return true
            end
        --为空
        elseif option["operator"]=="null" then 
            if  ngx.ctx.ua=="btwaf_null" then
                return true
            end 
        --不等于
        elseif option["operator"]=="neq" then
            if v ~= ngx.ctx.ua then
                return true
            end
        --包含
        elseif option["operator"]=="in" then
            if v == ngx.ctx.ua then
                return true
            end
        --不包含
        elseif option["operator"]=="not_in" then
            if v == ngx.ctx.ua then
                return false
            end
            --模糊匹配
        elseif option["operator"]=="like" then
            if ngx.re.match(ngx.ctx.ua,v,"isjo") then
                return true
            end
        end
    end
    if flag and option["operator"]=="not_in" then return true end
    return false
end

--匹配referer
function customize.Referer(option)
    if option==nil or option=="" or option["operator"] == nil or option["operator"] =="" or option["right_factor"] ==nil or option["right_factor"] =="" or ngx.ctx.referer==nil then return false end
    --以,号分隔option["right_factor"]的值
    local right_factor=Public.split(option["right_factor"],",")
    if right_factor==nil or right_factor=="" then return false end
    local flag = true
    for _,v in ipairs(right_factor) do
        --正则表达式，不区分大小写
        if option["operator"]=="regexp" then
            if ngx.re.match(ngx.ctx.referer,v,"isjo") then
                return true
            end
        elseif option["operator"]=="null" then
            if ngx.ctx.referer=="btwaf_referer_null" then
                return true
            end
        --匹配开头，不区分大小写
        elseif option["operator"]=="prefix" then
            if ngx.re.match(ngx.ctx.referer,"^"..v,"isjo") then
                return true
            end
        --匹配结尾，不区分大小写
        elseif option["operator"]=="suffix" then
            if ngx.re.match(ngx.ctx.referer,v.."$","isjo") then
                return true
        end
        --等于
        elseif option["operator"]=="eq" then 
            if v == ngx.ctx.referer then
                return true
            end
        --不等于
        elseif option["operator"]=="neq" then
            if v ~= ngx.ctx.referer then
                return true
            end
        --包含
        elseif option["operator"]=="in" then
            if v == ngx.ctx.referer then
                return true
            end
        --不包含
        elseif option["operator"]=="not_in" then
            if v == ngx.ctx.referer then
                return false
            end
        end
    end
    if flag and option["operator"]=="not_in" then return true end
    return false
end


--匹配ip地区
function customize.Ip_area(option)
    if option==nil or option=="" or option["operator"] == nil or option["operator"] =="" or option["right_factor"] ==nil or option["right_factor"] =="" then return false end
    local overall_country=ngx.ctx.country
    if overall_country==nil or overall_country=="" then return false end
    --以,号分隔option["right_factor"]的值
    if overall_country=="内网地址" then return false end 
    local right_factor=Public.split(option["right_factor"],",")
    if right_factor==nil or right_factor=="" then return false end
    --遍历right_factor的值
    local flag=false
    
    -- 等于的时候
    if option["operator"] =="eq" then
        for _,v in ipairs(right_factor) do 
            if v=="中国以外地区" then 
                if overall_country~="中国" then 
                    return true
                end 
            end 
            if overall_country==v then
                return true
            end
        end
    elseif option["operator"] =="neq" then
        for _,v in ipairs(right_factor) do 
            if v=="中国以外地区" then 
                if overall_country=="中国" then 
                    return false
                end 
            else 
                if overall_country==v then
                    return false
                end
            end 
        end
        return true
    end
    return false
end


--匹配参数名和值
function customize.Param(option)
    if option==nil or option=="" or option["left_factor"] =="" or option["left_factor"] ==nil or option["right_factor"] =="" or option["right_factor"] ==nil then return false end
    --正则表达式，不区分大小写
    if option["operator"]=="regexp" then
        if ngx.re.match(ngx.ctx.get_uri_args[option["left_factor"]],option["right_factor"],"isjo") then
            return true
        end
    --匹配开头，不区分大小写
    elseif option["operator"]=="prefix" then
        if ngx.re.match(ngx.ctx.get_uri_args[option["left_factor"]],"^"..option["right_factor"],"isjo") then
            return true
        end
    --匹配结尾，不区分大小写
    elseif option["operator"]=="suffix" then
        if ngx.re.match(ngx.ctx.get_uri_args[option["left_factor"]],option["right_factor"].."$","isjo") then
            return true
        end
    --等于/完全匹配（不区分大小写）
    elseif option["operator"]=="eq" then
        if ngx.ctx.get_uri_args[option["left_factor"]]==option["right_factor"] then
            return true
        end
    --不等于（不区分大小写）
    elseif option["operator"]=="neq" then
        if ngx.ctx.get_uri_args[option["left_factor"]]~=option["right_factor"] then
            return true
        end
    --模糊匹配（不区分大小写）
    elseif option["operator"]=="like" then
        if ngx.re.match(ngx.ctx.get_uri_args[option["left_factor"]],option["right_factor"],"isjo") then
            return true
        end
    end
    return false
end


--匹配uri 不带参数/带参数
function customize.Uri(option)
    if option==nil or option=="" or  option["right_factor"] =="" or option["right_factor"] ==nil then return false end
    local uri = ngx.ctx.url_split
    if option["type"]=="uri_with_param" then uri = ngx.var.request_uri end
    if option["type"]=="uri_param" then 
        uri = ngx.ctx.url_split[2]
    end
    if uri==nil or uri=="" then return false end
    --正则表达式，不区分大小写
    if option["operator"]=="regexp" then
        if ngx.re.match(uri,option["right_factor"],"isjo") then
            return true
        end
    --匹配开头，不区分大小写
    elseif option["operator"]=="prefix" then
        if ngx.re.match(uri,"^"..option["right_factor"],"isjo") then
            return true
        end
    --匹配结尾，不区分大小写
    elseif option["operator"]=="suffix" then
        if ngx.re.match(uri,option["right_factor"].."$","isjo") then
            return true
        end
    --等于/完全匹配（不区分大小写）
    elseif option["operator"]=="eq" then
        if uri==option["right_factor"] then
            return true
        end
    --不等于（不区分大小写）
    elseif option["operator"]=="neq" then
        if uri~=option["right_factor"] then
            return true
        end
    --模糊匹配（不区分大小写）
    elseif option["operator"]=="like" then
        if ngx.re.match(uri,option["right_factor"],"isjo") then
            return true
        end
    --包含（不区分大小写）
    elseif option["operator"]=="in" then
        local right_factor=Public.split(option["right_factor"],",")
        if right_factor==nil or right_factor=="" then return false end
        for _,v in ipairs(right_factor) do
            if uri==v then
                return true
            end
        end
    --不包含（不区分大小写）
    elseif option["operator"]=="not_in" then
        local right_factor=Public.split(option["right_factor"],",")
        if right_factor==nil or right_factor=="" then return false end
        for _,v in ipairs(right_factor) do
            if uri==v then
                return false
            end
        end
        return true
    end
    return false
end

-- 匹配请求方法
function customize.Request_method(option)
    if option==nil or option=="" or option["right_factor"] =="" or option["right_factor"] ==nil then return false end
    --遍历right_factor的值

    --等于
    if option["operator"] =="eq" then
        if ngx.ctx.method==option["right_factor"] then
            return true
        end
    --不等于
    elseif option["operator"] =="neq" then
        if ngx.ctx.method~=option["right_factor"] then
            return true
        end
    --包含
    elseif option["operator"]=="in" then
        local right_factor=Public.split(option["right_factor"],",")
        if right_factor==nil or right_factor=="" then return false end
        for _,v in ipairs(right_factor) do
            if ngx.ctx.method==v then
                return true
            end
        end
    --不包含
    elseif option["operator"]=="not_in" then
        local right_factor=Public.split(option["right_factor"],",")
        if right_factor==nil or right_factor=="" then return false end
        for _,v in ipairs(right_factor) do
            if ngx.ctx.method==v then
                return false
            end
        end
        return true
    end
    return false
end


-- 匹配请求头
function customize.Request_head(request_head,request_head_value,match_type)
    if request_head~=nil and request_head~="" and request_head_value~=nil and request_head_value~="" and match_type~=nil and match_type~="" then
        --等于
        if match_type=="eq" then
            if ngx.ctx.request_header[request_head]==request_head_value then
                return true
            end
        --不等于
        elseif match_type=="neq" then
            if ngx.ctx.request_header[request_head]~=request_head_value then
                return true
            end
        --匹配开头，不区分大小写
        elseif match_type=="prefix" then
            if ngx.re.match(ngx.ctx.request_header[request_head],"^"..request_head_value,"isjo") then
                return true
            end
        --匹配结尾，不区分大小写
        elseif match_type=="suffix" then
            if ngx.re.match(ngx.ctx.request_header[request_head],request_head_value.."$","isjo") then
                return true
            end
        --模糊匹配（不区分大小写）
        elseif match_type=="like" then
            if ngx.re.match(ngx.ctx.request_header[request_head],request_head_value,"isjo") then
                return true
            end
        end
    end
    return false
end


function customize.walk_node(node)
    --逻辑块
    if node["type"]=="block" then
        if node['logic'] == 'and' then 
            for _,v in ipairs(node["children"]) do
                if not customize.walk_node(v) then
                    return false
                end
            end
            return true
        elseif node["logic"]=="or" then 
            for _,v in ipairs(node["children"]) do
                if customize.walk_node(v) then
                    return true
                end
            end
            return false
        end
        return false
    --条件块
    elseif node["type"] == "option" then
        if  node["option"]==nil then return false end
        
        --处理各种类型的条件
        local option =node["option"]
        local option_type =option["type"]
        --单ip
        if option_type =="ip" then
            if customize.Ip(option) then 
                return true
            end
            
            return false
        --ip段
        elseif option_type =="ip_range" then
            if customize.Ip_range(option) then
                return true 
            
            end
            return false
        --ip组
        elseif option_type =="ip_group" then
            if customize.Ip_group(option) then 
                return true 
            end
            return false
        --ip归属地（地区）
        elseif option_type =="ip_belongs" then
            
            if customize.Ip_area(option) then 
                return true 
            end
            return false
        --user-agent
        elseif option_type =="user-agent" then
                
            if customize.User_agent(option) then 
                return true 
            end
            return false
            
        --referer 引用方
        elseif option_type =="referer" then
                
            if customize.Referer(option) then 
                return true 
            end
            return false
        --uri 不带参数
        elseif option_type =="uri" then
            if customize.Uri(option) then 
                return true 
            end
            return false
        --uri 带参数
        elseif option_type =="uri_with_param" then
            if customize.Uri(option) then 
                return true 
            end
            return false
        --uri参数,不带uri
        elseif option_type =="uri_param" then
            if customize.Uri(option) then 
                return true 
            end
            return false
        --请求参数（get+post）匹配名字和值
        elseif option_type =="param" then
            if customize.Param(option) then 
                return true 
            end
            return false
        --请求参数（get+post）只匹配参数名字
        elseif option_type =="param_name" then
            if customize.Param_name(option) then 
                return true end
            return false
        --请求参数 仅get
        elseif option_type =="get_param" then
            if ngx.ctx.method ~="GET" then return false end
            if customize.Param(option) then 
                return true end
            return false
        --请求参数 仅post
        elseif option_type =="post_param" then
            if ngx.ctx.method ~="POST" then return false end
            if customize.Param(option) then 
                return true end
            return false
        --请求参数的数量（get+post）
        elseif option_type =="param_length" then
            if customize.Param_count(option) then return true end
            return false
        --请求参数的数量 仅get
        elseif option_type =="get_param_length" then
            if ngx.ctx.method ~="GET" then return false end
            if customize.Param_count(option) then 
                return true end
            return false
        --请求参数的数量 仅post
        elseif option_type =="post_param_length" then
            if ngx.ctx.method ~="POST" then return false end
            if customize.Param_count(option) then 
                return true end
            return false
        elseif option_type =="method" then
            if customize.Request_method(option) then
                return true end
            return false
        --只匹配请求头的名称
        elseif option_type =="request_header_name" then
            if customize.Request_header_name(option) then
                return true 
            end
            return false
        --匹配请求头的名称和值
        elseif option_type =="request_header" then
            if customize.Request_header(option) then 
                return true end
            return false
        --请求头的数量
        elseif option_type =="request_header_length" then
            if customize.Request_header_count(option) then 
                return true end
            return false
        --其他情况
        else
            return false
        end
        
    end
end


--匹配规则通用方法
function customize.match_rule(match_site)
    -- 返回值 number
    -- 0 - 匹配失败
    -- 1 - 匹配成功 - 阻断/跳出
    -- 2 - 匹配成功 - 中断后续自定规则匹配

    
    
    for _,v in ipairs(BTWAF_RULES.customize[match_site]) do
        local match_rule = BTWAF_RULES.customize["rules"][v]
        
        
        if match_rule["status"]==1 and match_rule["root"]["type"]~=nil and match_rule["root"]["logic"]~=nil and match_rule["root"]["children"]~=nil then
            local flag=false
            --匹配规则
            flag=customize.walk_node(match_rule["root"])
            --当匹配到规则时
            if flag then
                local hit_type="观察模式"
                local hit_type_two ="自定义拦截"
                if match_rule["src"]==2 then
                    hit_type_two="自定义CC防御"
                end
                if match_rule["action"] ~=nil and match_rule["action"]["type"] ~=nil then
                    --执行放行动作
                    if match_rule["action"]["type"]=="allow" then
                        hit_type="放行"
                        hit_type="--匹配到规则名称["..match_rule["name"].."]"
                        customize.record_log(0,hit_type,v,hit_type_two)
                        return 1
                        --执行拦截动作
                    elseif match_rule["action"]["type"]=="deny" then
                        hit_type="拦截"
                        hit_type="--匹配到规则名称["..match_rule["name"].."]"
                        --当为自定义cc防御时，检测是否达到拦截阈值  match_rule["src"]  0 自定义规则 1 url白名单 2 自定义cc防御
                        if match_rule["src"]==2 and match_rule["action"]["cc"]["threshold"]~= nil then

                            --验证的次数
                            local ip = Public.get_client_ip()
                            local cache_key ="customize_cc__"..v..ip
                            local safe_count = ngx.shared.drop_sum:incr(cache_key, 1)

                            if not safe_count then
                                ngx.shared.drop_sum:set(cache_key,1,match_rule["action"]["cc"]["interval"])
                                safe_count = 1
                            end
                            --如果验证的次数 大于配置的值 则封锁
                            if safe_count >= match_rule["action"]["cc"]["threshold"] then
                                customize.record_log(1,hit_type,v,hit_type_two)
                                customize.intercept_ip('customize_cc','自定义CC防御拦截,已封锁IP',2,match_rule["action"]["block_time"])
                                Public.request_incr(444)
								ngx.exit(444)
                            elseif safe_count < match_rule["action"]["cc"]["threshold"] then
                                customize.record_log(0,hit_type,v,hit_type_two)
                                return 1
                            end
                        end
                        customize.record_log(1,hit_type,v,hit_type_two)
                        --响应444状态码
                        if match_rule["action"]["response"]["type"]=="no_response" or v["src"]==2 then

                            ngx.ctx.is_type="自定义拦截规则："..match_rule["name"]
                            ngx.var.waf2monitor_blocked="自定义规则|".."触发的规则名称:"..match_rule["name"]
                            ngx.ctx.error_rule="自定义拦截规则: "..match_rule["name"]
                            IpInfo.write_log('sql',ngx.ctx.is_type)
                            Public.request_incr(444)
							ngx.exit(444)
                            -- return Public.return_html(444, BTWAF_RULES.balck_page)
                        end
                        --默认拦截页面
                        ngx.ctx.is_type="自定义拦截规则："..match_rule["name"]
                        ngx.var.waf2monitor_blocked="自定义规则|".."触发的规则名称:"..match_rule["name"]
                        ngx.ctx.error_rule="自定义拦截规则: "..match_rule["name"]
                        IpInfo.write_log('sql',ngx.ctx.is_type)
                        return Public.return_html(Config['get']['status'], BTWAF_RULES.get_html)
                        --执行人机验证动作
                    elseif match_rule["action"]["type"]=="validate" then
                        local src_validate_type=match_rule["action"]["response"]["type"]
                        local validate_type=""
                        if src_validate_type=="validate_silence" then
                            validate_type="btwaf"
                        elseif src_validate_type=="validate_waiting" then
                            validate_type ="renji"
                        elseif src_validate_type=="validate_slide" then
                            validate_type ="huadong"
                        end

                        --当为自定义cc防御时，检测是否达到拦截阈值  match_rule["src"]  0 自定义规则 1 url白名单 2 自定义cc防御
                        if match_rule["src"]==2 and match_rule["action"]["cc"]["threshold"]~= nil then

                            --验证的次数
                            local cache_key ="customize_cc__"..v
                            local safe_count = ngx.shared.drop_sum:incr(cache_key, 1)

                            if not safe_count then
                                ngx.shared.drop_sum:set(cache_key,1,match_rule["action"]["cc"]["interval"])
                                safe_count = 1
                            end
                            --如果验证的次数 大于配置的值 则封锁
                            if safe_count >= match_rule["action"]["cc"]["threshold"] then
                                BTWAF_OBJS.cc.renjiyanzheng(validate_type)
                                customize.update_hit(v)
                            elseif safe_count < match_rule["action"]["cc"]["threshold"] then
                                return 2
                            end
                        end
                        BTWAF_OBJS.cc.renjiyanzheng(validate_type)
                        customize.update_hit(v)
                        return 2
                        --仅记录模式
                    elseif match_rule["action"]["type"]=="record" then
                        --执行记录日志
                        hit_type="--匹配到规则名称["..match_rule["name"].."]"
                        customize.record_log(3,hit_type,v,hit_type_two)

                        return 1
                        --执行url重定向
                    elseif match_rule["action"]["type"]=="redirect" then
                        hit_type_two="自定义重定向"
                        --执行跳转
                        hit_type="--匹配到规则名称["..match_rule["name"].."]"
                        customize.record_log(4,hit_type,v,hit_type_two)
                        --跳转到指定的url
                        if match_rule["action"]["response"]["type"]=="url" then
                            local redirect_code = ngx.HTTP_MOVED_PERMANENTLY -- 默认为301重定向
                            -- 检查是否设置为302重定向
                            if match_rule["action"]["response"]["status"] == 302 then
                                redirect_code = ngx.HTTP_MOVED_TEMPORARILY
                            end
                            --跳转到指定的url
                            ngx.redirect(match_rule["action"]["response"]["body"],redirect_code)
                        end
                        return 2
                    end
                end
                return 2
            end
        end
    end

    return 0
end

-- @name 自定义规则匹配入口函数
-- @param 
-- @return 
-- @author hezhihong
-- @time 2023-11-17
function customize.match_all()
    if ngx.ctx.customize_groups_table ==0 then return false end 
    if BTWAF_RULES.customize[ngx.ctx.server_name] ~= nil then
        local status_code = customize.match_rule(ngx.ctx.server_name)
        if status_code > 0 then
            if status_code == 1 then
                return true
            end
            return false
        end
    end
    return false

end


--写命中日志，更新命中次数
function customize.record_log(hit_status,hit_type,v,hit_type_two)
    -- 记录命中日志
    -- 当前时间戳
    local token=ngx.md5('customize_'..v)
    Public.log_rule_hit(hit_status,"自定义拦截",ngx.ctx.time, hit_type_two,hit_type, ngx.var.host, ngx.ctx.uri, ngx.ctx.ip)
    if BTWAF_RULES.customize_count[v]==nil then BTWAF_RULES.customize_count[v]=0 end
    BTWAF_RULES.customize_count[v]=Public.incrtoken(token,BTWAF_RULES.customize_count[v])
    Public.updateRule("customize_verification",BTWAF_RULE_PATH.."/customize_count.json",BTWAF_RULES.customize_count)
    
end

--更新命中次数
function  customize.update_hit(v)
    local token=ngx.md5('customize_'..v)
    if BTWAF_RULES.customize_count[v]==nil then BTWAF_RULES.customize_count[v]=0 end
    BTWAF_RULES.customize_count[v]=Public.incrtoken(token,BTWAF_RULES.customize_count[v])
    Public.updateRule("customize_verification",BTWAF_RULE_PATH.."/customize_count.json",BTWAF_RULES.customize_count)
end

-- 直接封锁IP
-- @param name 封锁的类型 例如:customize_cc
-- @param info 封锁的的原因
-- @param action 执行动作 
-- @param lock_time 封锁时间
-- @param threshold 访问次数阈值/周期

function customize.intercept_ip(name, info,action,lock_time)
   
    --添加拦截日志和封锁日志
    local insert = require "database"
    local ipinfo = require "ipinfo"
    local ip = ngx.ctx.ip
    local rule= '自定义CC防御拦截,已封锁IP'
    ngx.shared.drop_ip:set(ip,1,lock_time)
    insert.totla_insert(info, name, rule, Check.http_log(), action)
    insert.black_insert(info, name, rule, Check.http_log(), "customize_cc", lock_time)
    -- insert.area_intercept()
    -- insert.ip_intercept()
    if action == 1 then
        return false
    end
    --最终把IP拉黑到系统防火墙中
    ipinfo.add_filter(ip, lock_time)
end


return customize