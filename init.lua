--[[
#-------------------------------------------------------------------
# 宝塔Linux面板
#-------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
#-------------------------------------------------------------------
# Author: lkq@bt.cn 
# Version 9.5.7 2024-12-20
# Time:2024-12-20 11:11:11
# Description: waf init
#-------------------------------------------------------------------
]]--
BTWAF_OBJS = {}
BTWAF_OBJS.version ="2024-12-20 9.5.8"
BTWAF_RULES = {}
BTWAF_CMS_OBJS={}
BTWAF_RUN_PATH = "/www/server/btwaf"
WF_UNIT_TEST_PATH = BTWAF_RUN_PATH..'/test/t/'
BTWAF_MODULE_PATH = BTWAF_RUN_PATH .. "/modules"
BTWAF_PUBLIC_PATH = BTWAF_RUN_PATH .. "/public"
BTWAF_LIB = BTWAF_RUN_PATH .. "/lib"
BTWAF_INC = BTWAF_RUN_PATH .. "/inc"
BTWAF_RULE_PATH = BTWAF_RUN_PATH .. "/rule/"
BTWAF_HTML = BTWAF_RUN_PATH .. "/html"
BTWAF_NDAY = BTWAF_RUN_PATH .. "/nday"
BTWAF_DB = BTWAF_RUN_PATH .. "/totla_db"
BTWAF_WEBSHELL_TOTAL = BTWAF_RUN_PATH .. "/webshell_total"
BTWAF_CMS_PATH=BTWAF_INC.."/cms"
BTWAF_LOG="/www/wwwlogs/btwaf"

-- -- -- 设置环境变量
package.path =WF_UNIT_TEST_PATH .. "/?.lua;"..BTWAF_MODULE_PATH .. "/?.lua;" .. BTWAF_PUBLIC_PATH .. "/?.lua;" .. BTWAF_LIB .. "/?.lua;"..BTWAF_CMS_PATH.."/?.lua"
package.cpath = BTWAF_INC .. "/?.so;".. package.cpath
Json = require "cjson"
Public = require "public"
Database = require "database"
IpInfo = require "ipinfo"
Logs = require "log"
Route = require "route"
local ipmatcher = require "ipmatcher"
Check = require "request_check"
Workers = require "workers"
Dns=require "resolver"
DB = nil
DbReport=nil

AES_OBJ= require "aes"
String_OBJ= require "resty_string"

--默认系统为X86
WAF_SYSTEM="x86"
--判断是否为ARM的系统
local arch_info = io.popen("uname -m"):read("*a")
if string.find(arch_info, "aarch64") then
    WAF_SYSTEM="arm"
end

--时间全局变量
Today=ngx.today()
Hour=os.date("%H")
Minute = os.date("%M")


WAF_CPU_CORES = Public.get_num_procs()

Config = Json.decode(Public.read_file_body(BTWAF_RUN_PATH .. '/config.json'))
Site_config = Json.decode(Public.read_file_body(BTWAF_RUN_PATH .. '/site.json'))

BTWAF_RULES.city_html = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'city.html')
BTWAF_RULES.ip_html = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'ip.html')
BTWAF_RULES.url_html = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'url.html')
BTWAF_RULES.aes_gcm = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'aes_gcm.html')
BTWAF_RULES.aes_cbc = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'aes_cbc.html')
BTWAF_RULES.aes_ofb = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'aes_ofb.html')
BTWAF_RULES.aes_ctr = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'aes_ctr.html')
BTWAF_RULES.aes_gcm_customize = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'aes_gcm_customize.html')
BTWAF_RULES.aes_cbc_customize = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'aes_cbc_customize.html')
BTWAF_RULES.aes_ofb_customize = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'aes_ofb_customize.html')
BTWAF_RULES.aes_ctr_customize = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'aes_ctr_customize.html')
BTWAF_RULES.timeout_html = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'timeout.html')
BTWAF_RULES.timeout_user_html = Public.read_file_body(Config["reqfile_path"] .. '/' .. 'timeout_user.html')

BTWAF_RULES.get_html = Public.read_file_body(Config["reqfile_path"] .. '/' .. Config["get"]["reqfile"])
BTWAF_RULES.post_html = Public.read_file_body(Config["reqfile_path"] .. '/' .. Config["post"]["reqfile"])
BTWAF_RULES.cookie_html = Public.read_file_body(Config["reqfile_path"] .. '/' .. Config["cookie"]["reqfile"])
BTWAF_RULES.user_agent_html = Public.read_file_body(Config["reqfile_path"] .. '/' .. Config["user-agent"]["reqfile"])
BTWAF_RULES.other_html = Public.read_file_body(Config["reqfile_path"] .. '/' .. Config["other"]["reqfile"])
BTWAF_RULES.cnlist = Json.decode(Public.read_file_body(BTWAF_RUN_PATH .. '/rule/cn.json'))
BTWAF_RULES.lanlist = Json.decode(Public.read_file_body(BTWAF_RUN_PATH .. '/rule/lan.json'))
BTWAF_RULES.scan_black_rules = Public.read_file('scan_black')
BTWAF_RULES.ip_black_rules = Public.read_file('ip_black')
BTWAF_RULES.ip_white_rules = Public.read_file('ip_white')
BTWAF_RULES.url_white_senior = Public.read_file('url_white_senior')
BTWAF_RULES.url_white_rules = Public.read_file('url_white')
BTWAF_RULES.url_request = Public.read_file('url_request_mode')
BTWAF_RULES.reg_tions_rules = Public.read_file('reg_tions')
BTWAF_RULES.reg_city_rules = Public.read_file('reg_city')
BTWAF_RULES.get_spider = Public.read_file('get_spider')
BTWAF_RULES.not_spider = Public.read_file('not_spider')
BTWAF_RULES.cc_uri_white_rules = Public.read_file('cc_uri_white')
BTWAF_RULES.url_black_rules = Public.read_file('url_black')
BTWAF_RULES.user_agent_rules = Public.select_rule(Public.read_file('user_agent'))
BTWAF_RULES.cookie_rules = Public.select_rule(Public.read_file('cookie'))
BTWAF_RULES.args_rules = Public.select_rule_args(Public.read_file('args'))
BTWAF_RULES.url_rules = Public.select_rule(Public.read_file('url'))
BTWAF_RULES.captcha_num2 = Json.decode(Public.read_file_body(BTWAF_INC..'/captcha/num2.json'))
BTWAF_RULES.nday_info = Json.decode(Public.read_file_body(BTWAF_INC..'/nday/nday.json'))
BTWAF_RULES.nday_regular = Json.decode(Public.read_file_body(BTWAF_INC..'/nday/regular.json'))
BTWAF_RULES.ip_white_v6 = Public.read_file('ip_white_v6')
BTWAF_RULES.ip_black_v6 = Public.read_file('ip_black_v6')
BTWAF_RULES.limit_user = Public.read_file('limit')

--弱密码检测默认不开
BTWAF_RULES.password = Public.read_file('password')

BTWAF_RULES.body_character=Config['body_character_string']
BTWAF_RULES.body_character_len=0
if BTWAF_RULES.body_character then 
    BTWAF_RULES.body_character_len=Public.is_len(Config['body_character_string'])
end
--启动XSS解析引擎
io.popen("nohup bash /www/server/panel/plugin/btwaf/xss_decode.sh restart &> /dev/null &"):read("*a")

--共享IP库
BTWAF_RULES.malicious_ip = Public.read_file('malicious_ip')
BTWAF_RULES.malicious_ip_count=Public.is_len(BTWAF_RULES.malicious_ip)

--共享IP库
BTWAF_RULES.btmalibrary_malicious = Public.read_file('btmalibrary_malicious')
BTWAF_RULES.btmalibrary_malicious_count=Public.is_len(BTWAF_RULES.btmalibrary_malicious)

BTWAF_RULES.rule_hit_list = Public.read_file("rule_hit_list")

BTWAF_RULES.limit_user_count = 0
for _, v in ipairs(BTWAF_RULES.limit_user) do
    BTWAF_RULES.limit_user_count = 1
    break
end 

--设置IPV6白名单
local ipv6_w = {}
BTWAF_RULES.ipv6_white_count = 0
for _, v in ipairs(BTWAF_RULES.ip_white_v6) do
    --判断长度是否大于6
    BTWAF_RULES.ipv6_white_count = BTWAF_RULES.ipv6_white_count + 1
    table.insert(ipv6_w, v[1])

end
BTWAF_RULES.ipv6_white = ipmatcher.new(ipv6_w)
--设置IPV6黑名单
local ipv6_b = {}
BTWAF_RULES.ipv6_black_count = 0
for _, v in ipairs(BTWAF_RULES.ip_black_v6) do
    --判断长度是否大于6
    BTWAF_RULES.ipv6_black_count = BTWAF_RULES.ipv6_black_count + 1
        table.insert(ipv6_b, v[1])
end
BTWAF_RULES.ipv6_black = ipmatcher.new(ipv6_b)


local function load_modules()
    for _, filename in pairs(Public.listdir(BTWAF_MODULE_PATH)) do
        local mod_name = string.match(filename, "(.*)%.lua")
        if BTWAF_OBJS[mod_name] == nil then
            BTWAF_OBJS[mod_name] = {}
            BTWAF_OBJS[mod_name] = require(mod_name)
        end
    end
end
load_modules()

--自定义规则
BTWAF_RULES.customize = Public.read_file("customize")
BTWAF_RULES.customize_count = Public.read_file("customize_count")
BTWAF_RULES.customize_allsite_count = Public.len(BTWAF_RULES.customize["allsite"])
BTWAF_RULES.customize_groups_table = Public.get_ip_ranges_from_customize(BTWAF_RULES.customize["rules"])


-- 载入支付宝、微信支付的IP、减少支付回调导致的问题
BTWAF_RULES.pay = Public.read_file('pay')
local pay_w = {}
BTWAF_RULES.ip_pay_count = 0
for _, v in ipairs(BTWAF_RULES.pay) do
    --判断长度是否大于6
    BTWAF_RULES.ip_pay_count = BTWAF_RULES.ip_pay_count + 1
    table.insert(pay_w, v)
end
BTWAF_RULES.ip_pay = ipmatcher.new(pay_w)

--各个全局配置
BTWAF_RULES.body_size=800000
if Config['http_config']~=nil and Config['http_config']['body_size']~=nil then 
    BTWAF_RULES.body_size=Config['http_config']['body_size']
end 
BTWAF_RULES.base64=true
if Config['http_config']~=nil and Config['http_config']['base64']~=nil then 
    BTWAF_RULES.base64=Config['http_config']['base64']
end 
BTWAF_RULES.get_count=1000
if Config['http_config']~=nil and Config['http_config']['get_count']~=nil then 
    BTWAF_RULES.get_count=Config['http_config']['get_count']
end 
BTWAF_RULES.post_count=1000
if Config['http_config']~=nil and Config['http_config']['post_count']~=nil then 
    BTWAF_RULES.post_count=Config['http_config']['post_count']
end 
BTWAF_RULES.system_black=false
if Config['system_black']~=nil and  Config['system_black'] then 
    BTWAF_RULES.system_black=Config['system_black']
end 

--智能CC开启的列表
BTWAF_RULES.smart_cc_list = {}
BTWAF_RULES.smart_cc_list_count=0
for server_name,val in pairs(Site_config) do
    if val['smart_cc']~=nil and val['smart_cc']['open']~=nil and val['smart_cc']['open']==true then
        BTWAF_RULES.smart_cc_list[server_name] =true
        BTWAF_RULES.smart_cc_list_count=BTWAF_RULES.smart_cc_list_count+1
    end
    if val['crawler']~=nil and val['crawler']['picture']~=nil and val['crawler']['picture']==true then 
        local pid_path=BTWAF_RUN_PATH.."/picture/"..server_name
        if not Public.isdir(pid_path) then 
            Public.mkdir(pid_path) 
            local www_uid=Public.getUIDByUsername("www")
    		if www_uid==nil then 
    			Public.chown(pid_path,1000,1000)
    		else
    			Public.chown(pid_path,www_uid,www_uid)
    		end
        end
    end 
end


--加载蜘蛛IP进入到内存中
local load_spider={}
load_spider=IpInfo.load_spider()
BTWAF_RULES.load_spider_count = Public.arrlen(load_spider)
BTWAF_RULES.load_spider = ipmatcher.new(load_spider)


Public.load_cms_rule()