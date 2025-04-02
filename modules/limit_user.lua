local limit_user={}
local limit_count = require "limit.count"
local limit_req = require "limit.req"


function limit_user.limit_count(key,count,time)
    local lim, err = limit_count.new("btwaf_data", count, time)
    if not lim then
        return false
    end
    local delay, err = lim:incoming(key, true)
    if not delay then
        if err == "rejected" then
            return true
        end
        return false
    end
    return false
end 

function limit_user.limit_req(key,count)
    local lim, err = limit_req.new("btwaf_data", tonumber(count), 0)
    if not lim then
        return false
    end
    
    local delay, err = lim:incoming(key, true)
    if not delay then
        if err == "rejected" then
            return true
        end
        return false
    end
    if delay >= 0.001 then
        local excess = err
        ngx.sleep(delay)
    end  
end 


-- 返回json格式数据
-- @param status 状态码
-- @param msg 返回信息
function limit_user.return_message(status, msg)
    ngx.header.content_type = "application/json;"
    ngx.header.Cache_Control = "no-cache"
    ngx.status = status
    ngx.say(msg)
    ngx.exit(status)
end

function limit_user.send_log(name)
    local msg="触发流量限制->规则名称[ "..name.." ]"
    Public.log_rule_hit(1,"流量限制",ngx.ctx.time, "自定义拦截", msg..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
end 
    

function limit_user.return_infos(v)
    if v["action"]=="drop" then
        local msg="触发流量限制->规则名称[ "..v["name"].." ]已被系统拦截IP"
        ngx.ctx.is_type="流量限制"
        limit_user.send_log(v["name"])
       IpInfo.lan_ip("cc",msg) 
       ngx.exit(444)
       return
    end 
    if v["action"]=="status_404" then 
        limit_user.send_log(v["name"])
        ngx.exit(404)
        return
    end 
    if v["action"]=="status_403" then 
        limit_user.send_log(v["name"])
        ngx.exit(403)
    end 
    if v["action"]=="status_502" then 
        limit_user.send_log(v["name"])
        ngx.exit(502)
    end 
    if v["action"]=="status_503" then 
        limit_user.send_log(v["name"])
        ngx.exit(503)
    end
    if v["action"]=="content" then 
        if v["return"]=="444" then ngx.exit(444) return end 
        if v["return"]=="html" then 
            limit_user.send_log(v["name"])
            local html_data = Public.read_file_body("/www/server/btwaf/html/limit.html")
            Public.return_html(v["status"], html_data)
            return 
        end 
        if v["return"]=="json" then
            limit_user.send_log(v["name"])
            local html_data = Public.read_file_body("/www/server/btwaf/html/limit.json")
            limit_user.return_message(200, html_data)
            return 
        end
    end 
end 

function limit_user.start()
    if BTWAF_RULES.limit_user_count==0 then return false end
    if ngx.req.is_internal() then return false end 
    for _, v in ipairs(BTWAF_RULES.limit_user) do
        if v["open"] then 
            local flag=false
            if v["site"]["allsite"] then  flag=true end
            if v["site"][ngx.ctx.server_name] then  
                flag=true end 
            if flag then 
               -- 判断URL
               flag=false
               if v["types"]=="all" then flag=true end
               if v["types"]=="url" and ngx.re.find(ngx.ctx.url_split,v["url"],"ijo") then flag=true end 
               if flag then 
                   local key=ngx.md5(ngx.ctx.ip..v["id"])
                   if v["condition"]==2 then key=ngx.md5(ngx.ctx.ip..ngx.ctx.ua..v["id"]) end 
                   if v["condition"]==3 then key=ngx.md5(ngx.ctx.server_name..v["id"]) end 
                   --研判类型
                   if v["region"]["req"] ~=nil then 
                       if limit_user.limit_req(key,v["region"]["req"]) then 
                           ngx.var.waf2monitor_blocked="流量限制|".."触发规则名称[ "..v["name"].." ]"
                           return limit_user.return_infos(v)
                        end
                   end
                   if v["region"]["count"]~=nil then 
                      if v["region"]["count"]["count"]~=nil and v["region"]["count"]["time"]~=nil then 
                        local count=v["region"]["count"]["count"]
                        local timeout=v["region"]["count"]["time"]
                        if limit_user.limit_count(key.."count",count,timeout) then 
                            ngx.var.waf2monitor_blocked="流量限制|".."触发规则名称[ "..v["name"].." ]"
                            return limit_user.return_infos(v)
                        end
                      end
                   end
               end 
            end
        end
    end 
end 

return limit_user