local workers={}


-- 获取缓存
-- @param string key
-- @return int
function workers.get_cache(server_name,key)
    if not key then return end
    local skey = server_name .. '_status_' .. key
    local res =  ngx.shared.smart_cc:get(skey)
    if res == nil then
        res = 0
    end
    return res
end


function workers.area_incr(server_name,key,value,expire)
    if not key then return end
    local skey = server_name .. '_' .. key
    local val = ngx.shared.smart_cc:get(skey)
    if val == nil then
        ngx.shared.smart_cc:set(skey,0,expire)
    end
    ngx.shared.smart_cc:incr(skey,value)
end

-- 设置缓存
-- @param string key
-- @param int value
-- @return void
function workers.set_cache(server_name,key,value)
    if not key then return end
    local skey = server_name .. '_status_' .. key
    ngx.shared.smart_cc:set(skey,value)
end

-- 重置缓存
-- @param string key
-- @return void
function workers.reset_cache(server_name,key)
    if not key then return end
   
    key = server_name..'_status_' .. key
    ngx.shared.smart_cc:set(key,0)
end

-- 更新网站状态统计
-- @return void
function workers.update_status_total(pre)
    if pre then return end
    if  BTWAF_RULES.smart_cc_list_count==0 then return false end
    local today_end_time = Public.get_today_end_time() - os.time()
    local all_qps = 0
    local all_ip = 0
    local all_pv = 0
    local all_uv = 0
    local all_err_499 = 0
    local all_err_502 = 0
    local all_err_504 = 0
    local all_send_bytes = 0
    local all_recv_bytes = 0
    local all_proxy_time = 0
    local all_proxy_count = 0
    --获取锁
    local lock_key = 'update_status_total'
    if not Public.is_lock(lock_key) then
        return
    end
    for server_name,_ in pairs(BTWAF_RULES.smart_cc_list) do
        local qps_total = workers.get_cache(server_name,'qps')
        workers.reset_cache(server_name,'qps')
        local err_499_total = workers.get_cache(server_name,'err_499')
        workers.reset_cache(server_name,'err_499')
        local err_502_total = workers.get_cache(server_name,'err_502')
        workers.reset_cache(server_name,'err_502')
        local err_504_total = workers.get_cache(server_name,'err_504')
        workers.reset_cache(server_name,'err_504')
        local proxy_time_total = workers.get_cache(server_name,'proxy_time')
        workers.reset_cache(server_name,'proxy_time')
        local proxy_count_total = workers.get_cache(server_name,'proxy_count')
        workers.reset_cache(server_name,'proxy_count')
        all_proxy_time = all_proxy_time + proxy_time_total
        all_proxy_count = all_proxy_count + proxy_count_total
        all_err_499 = all_err_499 + err_499_total
        all_err_502 = all_err_502 + err_502_total
        all_err_504 = all_err_504 + err_504_total
        workers.area_incr(server_name,'err_499',err_499_total,today_end_time)
        workers.area_incr(server_name,'err_502',err_502_total,today_end_time)
        workers.area_incr(server_name,'err_504',err_504_total,today_end_time)
        ngx.shared.smart_cc:set(server_name .. '_qps',qps_total)
        ngx.shared.smart_cc:set(server_name .. '_proxy_time',Public.round(proxy_time_total / proxy_count_total))
        ngx.shared.smart_cc:set(server_name .. '_proxy_count',proxy_count_total)
    end
    workers.area_incr('global','err_499',all_err_499,today_end_time)
    workers.area_incr('global','err_502',all_err_502,today_end_time)
    workers.area_incr('global','err_504',all_err_504,today_end_time)
    ngx.shared.smart_cc:set('global_qps',all_qps)
    ngx.shared.smart_cc:set('global_proxy_time',Public.round(all_proxy_time / all_proxy_count))
    ngx.shared.smart_cc:set('global_proxy_count',all_proxy_count)

    -- 释放锁
    Public.un_lock(lock_key)
end

-- 检测CC攻击情况并设置当前CC防御等级
-- @return void
function workers.check_cc_level(pre)
    if pre then return end
    if BTWAF_RULES.smart_cc_list_count==0 then 
        return
    end
    -- 获取锁
    local lock_key = 'check_cc_level_status'
    if not Public.is_lock(lock_key) then
        return
    end
    for server_name,_ in pairs(BTWAF_RULES.smart_cc_list) do
        -- 获取配置
        local smart_cc = Public.get_default_smart_cc_config()
        workers.check_site_cc_level(server_name,smart_cc,"db")
    end
    -- db:close()
    -- 释放锁
    -- Public.un_lock(lock_key)
end



-- 检测回源时间平均值
-- @param string server_name 网站名称
-- @param int cc_level 当前CC防护等级
-- @param object db 数据库连接对象
-- @return int 当前CC防护等级
function workers.check_proxy_time_avg(server_name,cc_level,smart_cc,db)
    -- 如果当前CC防护等级大于等于2，则不再检测
    if cc_level >= 3 then
        return cc_level
    end

    local proxy_time = workers.get_cache(server_name,'cc_proxy_time')
    workers.reset_cache(server_name,'cc_proxy_time')
    local proxy_count = workers.get_cache(server_name,'cc_proxy_count')
    workers.reset_cache(server_name,'cc_proxy_count')
    
    if proxy_count == 0 then
        if cc_level > 1 then
            cc_level = cc_level - 1
            workers.set_cc_level(server_name,"请求书为0，降级: ".. cc_level .. '级',cc_level,smart_cc.expire,db)
        end 
        return cc_level
    end
    local proxy_time_avg = proxy_time / proxy_count
    -- 平均回源时间大于2000毫秒,则提升一级CC防御等级
    if proxy_time_avg > smart_cc.max_avg_proxy_time then
        cc_level = cc_level + 1
        -- 设置CC防护等级
        workers.set_cc_level(server_name,"当前平均回源速度过慢，CC防护级别升为: ".. cc_level .. '级',cc_level,smart_cc.expire,db)
    else
        if cc_level > 1 then
            cc_level = cc_level - 1
            workers.set_cc_level(server_name,"请求书为0，降级: ".. cc_level .. '级',cc_level,smart_cc.expire,db)
        end 
    end
    return cc_level
end


-- 检查异常响应状态码
-- @param string server_name 网站名称
-- @param int cc_level 当前CC防护等级
-- @param object db 数据库连接对象
function workers.check_res_status(server_name,cc_level,smart_cc,db)
    -- 如果当前CC防护等级大于等于2，则不再检测
    if cc_level >= 4 then
        return cc_level
    end
    local res_status_499 = workers.get_cache(server_name,'err_499')
    local res_status_502 = workers.get_cache(server_name,'err_502')
    local res_status_504 = workers.get_cache(server_name,'err_504')
    local sec_status_499 = res_status_499 - workers.get_cache(server_name,'last_err_499')
    local sec_status_502 = res_status_502 - workers.get_cache(server_name,'last_err_502')
    local sec_status_504 = res_status_504 - workers.get_cache(server_name,'last_err_504')

    workers.set_cache(server_name,'last_err_499',res_status_499)
    workers.set_cache(server_name,'last_err_502',res_status_502)
    workers.set_cache(server_name,'last_err_504',res_status_504)
    -- 如果499/502/504状态码大于5，则提升一级CC防御等级
    if smart_cc.status_count_499==nil then
        smart_cc.status_count_499=5
    end
    if sec_status_499 > smart_cc.status_count_499 or sec_status_502 > smart_cc.max_err_count or sec_status_504 > smart_cc.max_err_count then
        cc_level = cc_level + 1
        workers.set_cc_level(server_name,"回源异常响应状态码过多，CC防护级别升为: ".. cc_level .. '级',cc_level,smart_cc.expire,db)
    else
        if cc_level > 1 then
            cc_level = cc_level - 1
            workers.set_cc_level(server_name,"回源异常响应状态码过少，降级: ".. cc_level .. '级',cc_level,smart_cc.expire,db)
        end
    end
    return cc_level
end


-- 设置CC防护等级
-- @param string server_name 网站名称
-- @param string reason 原因
-- @param int level 等级
-- @param int expire 过期时间 单位:秒
-- @param object db 数据库连接对象
-- @return void
function workers.set_cc_level(server_name,reason,level,expire,db)
    local now_time = os.time()
    local expire_time = now_time + expire
    local old_cc_level = workers.get_cache(server_name,'cc_level')
    workers.set_cache(server_name,'cc_level',level)
    workers.set_cache(server_name,'cc_level_time',os.time())
    workers.set_cache(server_name,'cc_level_expire',expire_time)

    if old_cc_level == level then
        return
    end
    Public.logs("["..server_name.."]",'[CC防护]','设置CC防御等级为: '..level," 描述:",reason)
end



-- 检测网站CC防护等级
-- @param string server_name 网站名称
-- @param table smart_cc 智能CC防护配置
-- @param object db 数据库连接对象
-- @return void
function workers.check_site_cc_level(server_name,smart_cc,db)
    local now_time = os.time()
    local cc_level = workers.get_cache(server_name,'cc_level')
    local cc_level_expire = workers.get_cache(server_name,'cc_level_expire')
    local qps = ngx.shared.smart_cc:get(server_name .. '_qps')
    local expire_sec = cc_level_expire - now_time

    -- 如果上一个策略时间没走完一半，则不检测
    if expire_sec > smart_cc.expire / 2 then
        return
    end

    if cc_level == nil or cc_level == 0 then
        cc_level = 1
    end

    if qps == nil then
        qps = 0
    end
    --小于10的QPS就不检查了 如果机器为2核心的话那么QPS就为5 
    if qps < smart_cc.max_qps then
        -- 检查当前防护级别是否<2，CC策略是否过期
        if cc_level < 2 or  expire_sec > 1 then
            return
        end
        -- 如果已过期，则降低一级CC防御等级
        cc_level = cc_level - 1
        workers.set_cc_level(server_name,'QPS小于'..smart_cc.max_qps..',CC防护级别降为: '.. cc_level .. '级',cc_level,0,db)
        return
    end

    local new_cc_level = 1
    -- 检测回源时间平均值
    new_cc_level =  workers.check_proxy_time_avg(server_name,cc_level,smart_cc,db)
    if new_cc_level > cc_level then
        return
    end
    
    -- 检测响应状态码
    new_cc_level = workers.check_res_status(server_name,new_cc_level,smart_cc,db)
    if new_cc_level > cc_level then
        return
    end
end





return workers
