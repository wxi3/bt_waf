--[[
#-------------------------------------------------------------------
# 宝塔Linux面板
#-------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
#-------------------------------------------------------------------
# Author: lkq@bt.cn 
# Time :2024-12-9 11:11:11
#----------------------
]]--
local worker_pid = ngx.worker.pid()
if not ngx.shared.spider:get("works"..worker_pid) then 
    ngx.shared.spider:set("works"..worker_pid,1)
    ngx.timer.every(60,Public.flush_rule_hit_log)-- 60秒更新一次规则命中记录
    ngx.timer.every(60,Public.flush_spider)-- 60秒更新假蜘蛛IP
    ngx.timer.every(60,Public.insert_request_total)-- 60秒更新一次规则命中记录
end

local function btwaf_run()
    local time_str = ngx.localtime()
    ngx.ctx.white_rule=false
    ngx.ctx.proxy=false
    --获取网站域名
    ngx.ctx.today = ngx.today()
    ngx.ctx.hour  = tonumber(string.sub(time_str, 12, 13))
    ngx.ctx.minute = tonumber(string.sub(time_str, 15, 16))
	ngx.ctx.ip=""
    ngx.ctx.country = ""
    ngx.ctx.ip_province=""
    ngx.ctx.ip_city=""
    ngx.ctx.ip_tag=""
    ngx.ctx.time = ngx.time()
    ngx.ctx.rule=""
    ngx.ctx.server_name = Public.get_server_name_waf()
    if not Config['open']  then return false end
    if not Public.is_site_config('open')  then return false end
    ngx.ctx.uri = ngx.var.uri
    ngx.ctx.url_split = Public.get_request_uri()
    ngx.ctx.request_uri = ngx.var.request_uri
    ngx.ctx.method = ngx.req.get_method()
    -- --获取请求头信息

    ngx.ctx.request_header = ngx.req.get_headers(20000)

    ngx.ctx.url_token=ngx.md5(ngx.ctx.server_name..ngx.ctx.url_split)

    -- --设置UA
    if ngx.var.http_user_agent and ngx.var.http_user_agent~="" then
        ngx.ctx.ua = ngx.var.http_user_agent
    else
        ngx.ctx.ua = "btwaf_null"
		ngx.ctx.request_header['user-agent']=""
    end
    if ngx.var.http_referer and ngx.var.http_referer~="" then 
        ngx.ctx.referer=ngx.var.http_referer
    else 
        ngx.ctx.referer="btwaf_referer_null"
    end
    -- --获取客户端的IP
    local ip = IpInfo.get_client_ip_bylog()
    -- --获取args参数
    ngx.ctx.get_uri_args = ngx.req.get_uri_args(100000)
    --获取cookie的信息
    ngx.ctx.cookie = Public.getcookie()
    ngx.ctx.cycle = Config['cc']['cycle']
    ngx.ctx.endtime = Config['cc']['endtime']
    ngx.ctx.limit = Config['cc']['limit']
    ngx.ctx.retry = Config['retry']
    ngx.ctx.retry_time = Config['retry_time']
    ngx.ctx.retry_cycle = Config['retry_cycle']
    ngx.ctx.site_cc = Public.is_site_config('cc')
	ngx.ctx.is_cc_url=false
    if Config['cc']['is_cc_url']~=nil then 
        ngx.ctx.is_cc_url=Config['cc']['is_cc_url']
    end 
	ngx.ctx.spider_status=true
	ngx.ctx.not_spider=false
	ngx.ctx.crawler_html=false
	ngx.ctx.crawler_picture=false
	ngx.ctx.cc_ip_max_status=false
    ngx.ctx.timeout=false
    if Site_config[ngx.ctx.server_name] and ngx.ctx.site_cc then
        ngx.ctx.cycle = Site_config[ngx.ctx.server_name]['cc']['cycle']
        ngx.ctx.endtime = Site_config[ngx.ctx.server_name]['cc']['endtime']
        ngx.ctx.limit = Site_config[ngx.ctx.server_name]['cc']['limit']
		if Site_config[ngx.ctx.server_name]['cc']['is_cc_url']~=nil then 
            ngx.ctx.is_cc_url=Site_config[ngx.ctx.server_name]['cc']['is_cc_url']
		end
    end
    if Site_config[ngx.ctx.server_name] then
        if Site_config[ngx.ctx.server_name]['limiting']~=nil and Site_config[ngx.ctx.server_name]['limiting']['timeout']~=nil then 
            if Site_config[ngx.ctx.server_name]['limiting']['timeout']['open']~=nil then 
                ngx.ctx.timeout=Site_config[ngx.ctx.server_name]['limiting']['timeout']['open']
                if ngx.ctx.timeout then 
                    ngx.ctx.timeout_limiting=Site_config[ngx.ctx.server_name]['limiting']['timeout']
                end
            end
        end 
        if Site_config[ngx.ctx.server_name]['crawler']~=nil and Site_config[ngx.ctx.server_name]['crawler']['html']~=nil then 
            ngx.ctx.crawler_html=Site_config[ngx.ctx.server_name]['crawler']['html']
        end 
        if Site_config[ngx.ctx.server_name]['crawler']~=nil and Site_config[ngx.ctx.server_name]['crawler']['picture']~=nil then 
            ngx.ctx.crawler_picture=Site_config[ngx.ctx.server_name]['crawler']['picture']
        end 
		ngx.ctx.spider_status=Site_config[ngx.ctx.server_name]['spider_status']
		if Site_config[ngx.ctx.server_name]['not_spider']~=nil then
		    ngx.ctx.not_spider=Site_config[ngx.ctx.server_name]['not_spider']
		end 
		if Site_config[ngx.ctx.server_name]['cc']['cc_ip_max']~=nil then 
		    local cc_ip_max=Site_config[ngx.ctx.server_name]['cc']['cc_ip_max']
		    if cc_ip_max~=nil and cc_ip_max["open"]~=nil and  cc_ip_max["open"]==true then 
		        if cc_ip_max["ip_max"]~=nil and cc_ip_max["static"]~=nil then 
		            ngx.ctx.cc_ip_max_status=true
	            	ngx.ctx.cc_ip_max=tonumber(cc_ip_max["ip_max"])
                    ngx.ctx.cc_ip_max_static=cc_ip_max["static"]
		        end
		    end
		end
        ngx.ctx.retry = Site_config[ngx.ctx.server_name]['retry']
        ngx.ctx.retry_time = Site_config[ngx.ctx.server_name]['retry_time']
        ngx.ctx.retry_cycle = Site_config[ngx.ctx.server_name]['retry_cycle']
    end
    ngx.ctx.error_rule=nil
    if ngx.ctx.server_name == "未绑定域名" then
        ngx.exit(403)
    end
    if Database then 
        Database.btwaf_init_db()
    end
    Route.route()
    if BTWAF_OBJS.white_balck.ip_white() then 
        ngx.ctx.proxy=true
        ngx.ctx.white_rule=true return true end  
    BTWAF_OBJS.header.is_check_header()
    BTWAF_OBJS.white_balck.drop()
    BTWAF_OBJS.white_balck.ip_black()
    if BTWAF_OBJS.white_balck.ua_white() then  
        ngx.ctx.proxy=true
        ngx.ctx.white_rule=true return true end
	if BTWAF_OBJS.white_balck.url_white() then
        ngx.ctx.proxy=true 
        ngx.ctx.white_rule=true return true end
    BTWAF_OBJS.white_balck.ua_black()
	BTWAF_OBJS.white_balck.url_black()
	Route.cc()
	Public.static_watermark()
    if Public.is_static() then
        ngx.ctx.proxy=true
        return true
    end
    if Site_config[ngx.ctx.server_name]==nil then 
        ngx.ctx.proxy=true
        return false end
    if  IpInfo.reptile_entrance() then  
        BTWAF_OBJS.args.args()
        BTWAF_OBJS.post.post()
        BTWAF_OBJS.upload.post_data()
        BTWAF_OBJS.upload.post_data_chekc()
        ngx.ctx.white_rule=true
        return false
    else
        BTWAF_OBJS.args.url_find()
        BTWAF_OBJS.args.url_request_mode()
        BTWAF_OBJS.header.header_len_check(ngx.ctx.request_header)
        BTWAF_OBJS.cc.cc_uri_frequency()
        BTWAF_OBJS.white_balck.drop_abroad()
        BTWAF_OBJS.white_balck.drop_china()
        BTWAF_OBJS.city.reg_tions()
        BTWAF_OBJS.city.reg_city()
		BTWAF_OBJS.malicious_ip.malicious_ip()
		BTWAF_OBJS.readonly.readonly()
		if BTWAF_OBJS.customize.match_all() then
                ngx.ctx.proxy=true
                return true
        end
		BTWAF_OBJS.idc.idc()
        BTWAF_OBJS.header.header_lan(ngx.ctx.request_header)
        BTWAF_OBJS.user_agent.user_agent()
        BTWAF_OBJS.cc.cc()
        
        --if not IpInfo.is_load_spider() then 
        BTWAF_OBJS.smart_cc.start()
        BTWAF_OBJS.cc.cc3()
        --end
        BTWAF_OBJS.args.url()
        BTWAF_OBJS.cookie.cookie()
        BTWAF_OBJS.args.args()
        BTWAF_OBJS.scan_black.scan_black()
        BTWAF_OBJS.nday.ThinkPHP_RCE5_0_23()
        BTWAF_OBJS.nday.ThinkPHP_3_log()
        BTWAF_OBJS.nday.error_transfer_encoding()
        BTWAF_OBJS.post.post()
        BTWAF_OBJS.upload.post_data()
        BTWAF_OBJS.upload.post_data_chekc()
        Public.limit_users()
		BTWAF_OBJS.limit_user.start()
        if Site_config[ngx.ctx.server_name] then
            BTWAF_OBJS.args.php_path()
            BTWAF_OBJS.args.url_ext()
            BTWAF_OBJS.args.url_path()
            BTWAF_OBJS.args.url_tell()
            BTWAF_OBJS.args.url_rule_ex()
            BTWAF_OBJS.nday.loadcms()
        end
    end 
    ngx.ctx.white_rule=false
    ngx.ctx.proxy=true
    
end 

local ok,error = pcall(function()
	return btwaf_run()
end)

if not ok then
    --10分钟记录一次错误信息
   if not ngx.shared.spider:get("btwaf_access") then 
        Public.logs(error)
        ngx.shared.spider:set("btwaf_access",1,360)
    end
end
