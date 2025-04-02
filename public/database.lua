local database={}
-- local totla_log_db=""
-- local DB=nil

function database.btwaf_init_db()
	database.btwaf_DbReport_init()
    if DB  then return false end
    local ok ,sqlite3 = pcall(function()
        			return  require "lsqlite3"
        		end)
	if not ok then
	    return false
    end
    local path =BTWAF_DB.."/"
	if not Public.isdir(path) then Public.mkdir(path) end
	if not Public.isdir(BTWAF_RUN_PATH..'/totla_db/http_log') then 
		Public.mkdir(BTWAF_RUN_PATH..'/totla_db/http_log')
		local www_uid=Public.getUIDByUsername("www")
		if www_uid==nil then 
			Public.chown(BTWAF_RUN_PATH..'/totla_db/http_log',1000,1000)
		else
			Public.chown(BTWAF_RUN_PATH..'/totla_db/http_log',www_uid,www_uid)
		end
	end
	local db_path = path.."totla_db.db"
	if DB == nil or not DB:isopen() then
		DB = sqlite3.open(db_path)
	end
	if DB==nil then return false end 
	local table_name = "totla_db"
	local stmt = DB:prepare("SELECT COUNT(*) FROM sqlite_master where type='table' and name=?")
	local rows = 0
	if stmt ~= nil then
		stmt:bind_values(table_name)
		stmt:step()
		rows = stmt:get_uvalues()
		stmt:finalize()
	end
	if stmt == nil or rows == 0 then
		DB:exec([[PRAGMA synchronous = 0]])
		DB:exec([[PRAGMA page_size = 4096]])
		DB:exec([[PRAGMA journal_mode = wal]])
		DB:exec([[PRAGMA journal_size_limit = 1073741824]])
        DB:exec[[
			CREATE TABLE btwaf_msg (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				server_name TEXT,
				time INTEGER,
				time_localtime TEXT,
		)]]
		DB:exec[[
			CREATE TABLE totla_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				time INTEGER,
				time_localtime TEXT,
				server_name TEXT,
				ip TEXT,
				ip_city TEXT,
				ip_country TEXT,
				ip_subdivisions TEXT,
				ip_continent TEXT,
				ip_longitude TEXT,
				ip_latitude TEXT,
				type TEXT,
				uri TEXT,
				user_agent TEXT,
				filter_rule TEXT,
				incoming_value TEXT,
			    value_risk TEXT,
				http_log TEXT,
				http_log_path INTEGER
			)]]
            DB:exec([[CREATE INDEX id_inx ON totla_log(id)]])
            DB:exec([[CREATE INDEX time_inx ON totla_log(time)]])
            DB:exec([[CREATE INDEX time_localtime_inx ON totla_log(time_localtime)]])
            DB:exec([[CREATE INDEX server_name_inx ON totla_log(server_name)]])
            DB:exec([[CREATE INDEX ip_ipx ON totla_log(ip)]])
            DB:exec([[CREATE INDEX type_inx ON totla_log(type)]])
            DB:exec([[CREATE INDEX filter__inx ON totla_log(filter_rule)]])
            DB:exec([[CREATE INDEX ip_country_inx ON totla_log(ip_country)]])
            DB:exec[[
			CREATE TABLE blocking_ip (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
			    time INTEGER,
				time_localtime TEXT,
				server_name TEXT,
				ip TEXT,
				ip_city TEXT,
				ip_country TEXT,
				ip_subdivisions TEXT,
				ip_continent TEXT,
				ip_longitude TEXT,
				ip_latitude TEXT,
				type TEXT,
				uri TEXT,
				user_agent TEXT,
				filter_rule TEXT,
				incoming_value TEXT,
			    value_risk TEXT,
				http_log TEXT,
				http_log_path INTEGER,
				blockade TEXT,
				blocking_time INTEGER,
				is_status INTEGER
			)]]
            DB:exec([[CREATE INDEX id_ip ON blocking_ip(id)]])
            DB:exec([[CREATE INDEX time_ip ON blocking_ip(time)]])
            DB:exec([[CREATE INDEX time_localtime_ip ON blocking_ip(time_localtime)]])
            DB:exec([[CREATE INDEX server_name_ip ON blocking_ip(server_name)]])
            DB:exec([[CREATE INDEX ip_ip ON blocking_ip(ip)]])
            DB:exec([[CREATE INDEX blocking_ip ON blocking_ip(blocking_time)]])
            DB:exec([[CREATE INDEX is_statu_ip ON blocking_ip(is_status)]])
			-- local www_uid=Public.getUIDByUsername("www")
			-- if www_uid==nil then 
			-- 	Public.chown(db_path,1000,1000)
			-- else
			-- 	Public.chown(db_path,www_uid,www_uid)
			-- end
	end
end

function database.btwaf_DbReport_init()
	if DbReport  then return false end
	local ok ,sqlite3 = pcall(function()
		return  require "lsqlite3"
		end)
	if not ok then
		return false
	end
	local path =BTWAF_DB.."/"
	local db_path = path.."total_report.db"
	if DbReport == nil or not DbReport:isopen() then
		DbReport = sqlite3.open(db_path)
	end
	if DbReport==nil then return false end 
	local table_name = "request_total"
	local stmt = DbReport:prepare("SELECT COUNT(*) FROM sqlite_master where type='table' and name=?")
	local rows = 0
	if stmt ~= nil then
		stmt:bind_values(table_name)
		stmt:step()
		rows = stmt:get_uvalues()
		stmt:finalize()
	end
	if stmt == nil or rows == 0 then
		DbReport:exec([[PRAGMA synchronous = 0]])
		DbReport:exec([[PRAGMA page_size = 4096]])
		DbReport:exec([[PRAGMA journal_mode = wal]])
		DbReport:exec([[PRAGMA journal_size_limit = 1073741824]])
        DbReport:exec[[
		CREATE TABLE request_total (id INTEGER  PRIMARY KEY AUTOINCREMENT,
		date DATE,
		hour INT (3) DEFAULT (0),
		minute INT (3) DEFAULT (0),
		server_name VARCHAR (64),
		request INT (11) DEFAULT (0),
		err_502 INT (11) DEFAULT (0),
		err_499 INT (11) DEFAULT (0),
		sec_request INT (11) DEFAULT (0),
		proxy_count INT (11) DEFAULT (0)
		)]]
		DbReport:exec([[CREATE INDEX date_new ON request_total(date)]])
	end
	
end 


function database.ReportInsert()

	local today,hour,minute = Public.get_pre_minute() -- 获取上一分钟
	for k,_ in pairs(Site_config) do
		database.get_site_req_total_sql(k,today,hour,minute)
	end
	database.get_site_req_total_sql("global",today,hour,minute)
	
end


function database.get_site_req_total_sql(server_name,today,hour,minute)
	if server_name ==nil  then
        return nil
    end
	if server_name=="127.0.0.1" then return false end 
	if server_name=="未绑定域名" then return false end
	local date_key = today .. '_' .. hour .. '_' .. minute
	local req_key = 'req_' .. date_key
	local request = Public.logs_get(server_name,req_key)
	local err_502 = Public.logs_get(server_name,'err_502_' .. date_key)
	local err_499 = Public.logs_get(server_name,'err_499_' .. date_key)
    local sec_request = Public.int(request / 60)
	--到后端的次数
	local proxy_count = Public.logs_get(server_name,"proxy_count"..req_key)

	-- 如果都是0 则不存储了
	if request == 0 and err_502 == 0 and err_499 == 0 and sec_request == 0 and proxy_count == 0 then
		return
	end

	if DbReport==nil then return false end
	--写入到数据库
	local stmt=DbReport:prepare[[insert into request_total(date,hour,minute,server_name,request,err_502,err_499,sec_request,proxy_count) values(:date,:hour,:minute,:server_name,:request,:err_502,:err_499,:sec_request,:proxy_count)]]
	if stmt == nil then
		Public.logs("统计插入失败")
		return
	end
	DbReport:exec([[BEGIN TRANSACTION]])
	stmt:bind_names{
		date=today,
		hour=hour,
		minute=minute,
		server_name=server_name,
		request=request,
		err_502=err_502,
		err_499=err_499,
		sec_request=sec_request,
		proxy_count=proxy_count
	}
	stmt:step()
	stmt:reset()
	stmt:finalize()
	DbReport:exec([[COMMIT]])

end


function database.totla_log_insert(is_log,server_name,ip,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,blockade,blocking_time)
	
	if filter_rule==nil then filter_rule='目录保护' end
	database.btwaf_init_db()
	if DB==nil then return false end 
    local stmt2=""
	if is_log=='log' then 
		stmt2 = DB:prepare[[INSERT INTO totla_log(
    		time,time_localtime,server_name,ip, ip_city,ip_country,ip_subdivisions,ip_continent,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path) 
    		VALUES(:time,:time_localtime,:server_name,:ip,:ip_city,:ip_country,:ip_subdivisions,:ip_continent,:ip_longitude, :ip_latitude,:type,:uri,:user_agent,:filter_rule,:incoming_value,:value_risk,:http_log,:http_log_path)]]
        if stmt2 == nil then 
			Public.logs("数据库写入失败totla_log")
			DB=nil
			return
		end
	elseif is_log=='ip' then 
	        stmt2 = DB:prepare[[INSERT INTO blocking_ip(
    		time,time_localtime,server_name,ip, ip_city,ip_country,ip_subdivisions,ip_continent,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,blockade,blocking_time,is_status) 
    		VALUES(:time,:time_localtime,:server_name,:ip,:ip_city,:ip_country,:ip_subdivisions,:ip_continent,:ip_longitude,:ip_latitude,:type,:uri,:user_agent,:filter_rule,:incoming_value,:value_risk,:http_log,:http_log_path,:blockade,:blocking_time,:is_status)]]
	    if stmt2 == nil then  
			Public.logs("数据库写入失败blocking_ip")
			DB=nil
			return
		end
	end
	DB:exec([[BEGIN TRANSACTION]])
	local get_ip_position=IpInfo.get_ip_position_data(ip)
    local ip_city=''
    local ip_country='未知位置'
    local ip_subdivisions=''
    local  ip_continent=''
    local ip_longitude=''
    local ip_latitude=''
	if get_ip_position=="3" then
	    ip_city=''
        ip_country='未知位置'
        ip_subdivisions=''
        ip_continent=''
        ip_longitude=''
        ip_latitude=''
    elseif 	get_ip_position=="2" then 
        if Public.is_internal_ip(ip) then
            ip_city=''
            ip_country='内网地址'
            ip_subdivisions=''
            ip_continent=''
            ip_longitude=''
            ip_latitude=''
        else
            ip_city=''
            ip_country='未知位置'
            ip_subdivisions=''
            ip_continent=''
            ip_longitude=''
            ip_latitude=''
        end
    else
        if get_ip_position['country'] then 
            if get_ip_position['country']['city'] then 
                ip_city=get_ip_position['country']['city']
            else
                 ip_city=''
            end 
        end
        if get_ip_position['country'] then 
            if get_ip_position['country']['country'] then 
                ip_country=get_ip_position['country']['country']
            else
                ip_country=''
            end 
        end
        
        if get_ip_position['country'] then 
            if get_ip_position['country']['province'] then 
                ip_subdivisions=get_ip_position['country']['province']
            else
                ip_subdivisions=''
            end
        end
        ip_continent=''
        if get_ip_position['country'] then 
            if get_ip_position['country']['longitude'] then 
                ip_longitude=get_ip_position['country']['longitude']
            else
                ip_longitude=''
            end 
            
        end
        if get_ip_position['country'] then 
            if get_ip_position['country']['latitude'] then 
                ip_latitude=get_ip_position['country']['latitude']
            else
                ip_latitude=''
            end 
        end
    end
	local random_token="BT_WAF_ACCESS_random"
    if Config['access_token']~=nil then 
        random_token=Config['access_token']
    end
    local http_log_path=1
    local http_log_body=""
    if ngx.req.get_method()=='POST' then
        http_log_path=1
        http_log_body=BTWAF_RUN_PATH..'/totla_db/http_log/'..ngx.md5(http_log..random_token)..'.log'
    else
        http_log_path=1
        http_log_body=BTWAF_RUN_PATH..'/totla_db/http_log/'..ngx.md5(http_log..random_token)..'.log'
    end 
        -- 如果 incoming_value 太长了
    if incoming_value~=nil and #incoming_value>210 then 
        incoming_value=incoming_value:sub(1, 200)
    end 
    if user_agent~=nil and  #user_agent>210 then 
        user_agent=user_agent:sub(1,200)
    end 
    
    if is_log=='log' then 
    	stmt2:bind_names{
    		time=os.time(),
    		time_localtime=ngx.localtime(),
    		server_name=server_name,
    	    ip=ip,
    	    ip_city=ip_city,
    	    ip_country=ip_country,
    	    ip_subdivisions=ip_subdivisions,
    	    ip_continent=ip_continent,
    	    ip_longitude=ip_longitude,
    	    ip_latitude=ip_latitude,
    	    type=type,
    	    uri=uri,
    	    user_agent=user_agent,
    	    filter_rule=filter_rule,
    	    incoming_value=incoming_value,
    	    value_risk=value_risk,
    	    http_log=http_log_body,
    	    http_log_path=http_log_path
    	}
    elseif is_log=='ip' then 
        stmt2:bind_names{
    		time=os.time(),
    		time_localtime=ngx.localtime(),
    		server_name=server_name,
    	    ip=ip,
    	    ip_city=ip_city,
    	    ip_country=ip_country,
    	    ip_subdivisions=ip_subdivisions,
    	    ip_continent=ip_continent,
    	    ip_longitude=ip_longitude,
    	    ip_latitude=ip_latitude,
    	    type=type,
    	    uri=uri,
    	    user_agent=user_agent,
    	    filter_rule=filter_rule,
    	    incoming_value=incoming_value,
    	    value_risk=value_risk,
    	    http_log=http_log_body,
    	    http_log_path=http_log_path,
    	    blockade=blockade,
    	    blocking_time=blocking_time,
    	    is_status=true
	    }
    end 
    
	stmt2:step()
	stmt2:reset()
	stmt2:finalize()
	DB:execute([[COMMIT]])
	if http_log_path==1 then 
    	local filename = http_log_body
    	local fp = io.open(filename,'wb')
    	if fp == nil then return false end
    	local logtmp = {http_log}
    	local logstr = Json.encode(logtmp)
    	fp:write(logstr)
    	fp:flush()
    	fp:close()
    end
end



return database