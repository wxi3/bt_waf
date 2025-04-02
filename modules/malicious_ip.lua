--云端恶意IP库
local malicious_ip = {}
function malicious_ip.malicious_ip()
    if Config["btmalibrary"]~=nil and Config["btmalibrary"]==true and BTWAF_RULES.btmalibrary_malicious_count>0 then 
        return malicious_ip.btmalibrary()
    end
    if Config["malicious_ip"]==nil then 
        return false
    end
    if Config["malicious_ip"] ~= nil and Config["malicious_ip"] then
        local ip = ngx.ctx.ip
        if BTWAF_RULES.malicious_ip_count == 0 then
            return false
        end
        if BTWAF_RULES.malicious_ip[ip] ~= nil then
            local block_time = BTWAF_RULES.malicious_ip[ip]
            if ngx.time() < block_time then
                ngx.var.waf2monitor_blocked="云端恶意IP"
                Public.log_rule_hit(1,"云端恶意IP库",ngx.ctx.time, "云端恶意IP库", "匹配到云端恶意IP库"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                ngx.ctx.is_type="云端恶意IP"
				IpInfo.lan_ip('cc','堡塔云端恶意IP')
                return true
            end
        end
    end
    return false
end

function malicious_ip.btmalibrary()
    if Config["btmalibrary"] ~= nil and Config["btmalibrary"] then
        local ip = ngx.ctx.ip
        if BTWAF_RULES.malicious_ip_count > 0 then
            if BTWAF_RULES.malicious_ip[ip] ~= nil then
                local block_time = BTWAF_RULES.malicious_ip[ip]
                if ngx.time() < block_time then
                    ngx.var.waf2monitor_blocked="堡塔恶意IP情报库IP"
                    Public.log_rule_hit(1,"堡塔恶意IP情报库IP",ngx.ctx.time, "云端恶意IP库", "匹配到堡塔恶意IP情报库IP"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                    ngx.ctx.is_type="堡塔恶意IP情报库IP"
                    IpInfo.lan_ip('cc','堡塔恶意IP情报库IP')
                    return true
                end
            end
        end
        if BTWAF_RULES.btmalibrary_malicious_count > 0 then
            if BTWAF_RULES.btmalibrary_malicious[ip] ~= nil then
                local block_time = BTWAF_RULES.btmalibrary_malicious[ip]
                if ngx.time() < block_time then
                    ngx.var.waf2monitor_blocked="堡塔恶意IP情报库IP"
                    Public.log_rule_hit(1,"堡塔恶意IP情报库IP",ngx.ctx.time, "云端恶意IP库", "匹配到堡塔恶意IP情报库IP"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                    ngx.ctx.is_type="堡塔恶意IP情报库IP"
                    IpInfo.lan_ip('cc','堡塔恶意IP情报库IP')
                    return true
                end
            end
        end
    end
end

return malicious_ip