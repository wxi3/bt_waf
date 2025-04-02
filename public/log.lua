local logs = {}

-- 请求数统计
function logs.request_incr()
    local key = 'req_'.. logs.date_key
    Public.logs_incr("global",key,1,logs.cycle)
    Public.logs_incr(logs.server_name,key,1,logs.cycle)
    if ngx.ctx.proxy==nil then ngx.ctx.proxy=false end
    if ngx.ctx.proxy then
        Public.logs_incr("global","proxy_count"..key,1,logs.cycle)
        Public.logs_incr(logs.server_name,"proxy_count"..key,1,logs.cycle)
    end
    Public.logs_incr(logs.time,'qps',1,10)
    -- 智能CC
    logs.smart_cc_cache(logs.server_name,'qps',1,1)
end


-- 指定缓存值+1
-- @param string server_name  网站名称
-- @param string key  缓存key
-- @param int num 增加的值
-- @return void
function logs.cache_incr(server_name,key,num)
    if not key then return end
    local skey = server_name .. '_status_' .. key
    local val = ngx.shared.smart_cc:get(skey)
    if val == nil then
		logs.today_expire_time = Public.get_today_end_time() - logs.time
        ngx.shared.smart_cc:set(skey,0,logs.today_expire_time)
    end
    ngx.shared.smart_cc:incr(skey,num)
end

function logs.smart_cc_cache(server_name,key,num,expire_time)
    if BTWAF_RULES.smart_cc_list_count==0 then  return end
    if BTWAF_RULES.smart_cc_list[ngx.ctx.server_name]==nil then return false end
    if not key then return end
    local skey = server_name .. '_status_' .. key
    local val = ngx.shared.smart_cc:get(skey)
    if val == nil then
        ngx.shared.smart_cc:set(skey,0,expire_time)
    end
    ngx.shared.smart_cc:incr(skey,num)
end 

function logs.smart_get_cache(server_name,key)
    if not key then return end
    local skey = server_name .. '_status_' .. key
    local val = ngx.shared.smart_cc:get(skey)
    if val == nil then
        return 0
    end
    return val
end



-- 错误码统计
function logs.err_incr()
    -- 不统计401以下的错误码
    if ngx.status < 401 then return end
    -- 判断当前错误码
    local err_key = 'err_'
    if ngx.status == 502 then
        err_key = err_key .. '502'
    elseif ngx.status == 499 then
        err_key = err_key .. '499'
    else
        return
    end
    -- 智能CC
    logs.smart_cc_cache(logs.server_name,err_key,1,60)
    
    local key = err_key .. '_' .. logs.date_key
    Public.logs_incr(logs.server_name,key,1,logs.cycle)
    Public.logs_incr("global",key,1,logs.cycle)

end

-- 统计回源耗时
function logs.upstream_response_time()
    if BTWAF_RULES.smart_cc_list_count==0 then  return end
    if BTWAF_RULES.smart_cc_list[ngx.ctx.server_name]==nil then return false end
    if ngx.var.upstream_response_time==nil then return end
    if not ngx.var.upstream_response_time then return end
    if not tonumber(ngx.var.upstream_response_time) then return end
    local upstream_response_time = tonumber(ngx.var.upstream_response_time) * 1000
    if upstream_response_time==nil then return false end 
    if upstream_response_time>2000 and not ngx.ctx.is_api then 
        local timeout=ngx.shared.smart_cc:get(logs.server_name.."_timecount")
        if not timeout then 
            ngx.shared.smart_cc:set(logs.server_name.."_timecount",1,60)
        else 
            ngx.shared.smart_cc:incr(logs.server_name.."_timecount",1)
        end
    end
end

function logs.start()
    if ngx.var.request_uri=="/" then 
        local random=math.random(0,1)
        if random==0 then 
           return
        end 
    end
    if ngx.ctx.server_name=="127.0.0.1" then return false end
    logs.time = ngx.ctx.time
    if logs.time == nil then
        logs.time = Public.int(ngx.now())
    end
    
    logs.today = ngx.ctx.today
    if logs.today == nil then
        logs.today = ngx.today()
    end
    logs.hour = ngx.ctx.hour
    if logs.hour == nil then
        logs.hour = os.date("%H")
    end
    logs.minute = ngx.ctx.minute
    if logs.minute == nil then
        logs.minute = os.date("%M")
    end
    logs.server_name = ngx.ctx.server_name
    if logs.server_name == nil then
        logs.server_name = "未绑定域名"
    end
    logs.date_key=logs.today .. '_' ..  tonumber(logs.hour) .. '_' .. tonumber(logs.minute)
    logs.cycle = 360
    logs.request_incr()
    logs.err_incr()
end 


return logs