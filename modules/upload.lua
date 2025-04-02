local upload={}
local multipart=require "multipart"
local bt_engine =require "bt_engine"
local php_engine =require "php_engine"

function upload.gusb_string(table)
	local ret={"-","]","@","#","&","_","{","}"}
	local ret2={}
	if Public.arrlen(table)==0 then return table end 
	for _,v in pairs(table) do
		for _,v2 in pairs(ret) do 
			if ngx.re.find(v[0],v2,"jo") then 
				v[0]=ngx.re.gsub(v[0],v2,'baota',"jo")
			end
		end
		v[0]=string.gsub(v[0],'%[','baota')
		v[0]=string.gsub(v[0],'%(','baota')
		v[0]=string.gsub(v[0],'%)','baota')
		v[0]=string.gsub(v[0],'%+','baota')
		v[0]=string.gsub(v[0],'%$','baota')
		v[0]=string.gsub(v[0],'%?','baota')
	end
	return table
end 


function upload.get_boundary()
    local header = ngx.ctx.request_header["content-type"]
    if not header then return nil end
    if type(header) == "table" then
        return Public.return_message(200,'content-type ERROR')
    end
	if header then
    	if ngx.re.find(header,[[multipart]],'ijo') then
    		if not ngx.re.match(header,'^multipart/form-data; boundary=',"jo") then 
    				return Public.return_message(200,'content-type ERROR')
    		end
    	   local multipart_data=ngx.re.match(header,'^multipart/form-data; boundary=.+',"jo")
    	   if not multipart_data then return Public.return_message(200,"Btwaf  Boundary  Error") end
    	    if ngx.re.match(multipart_data[0],'""',"jo") then 
    	        return Public.return_message(200,"Btwaf  Boundary Double Quotation Mark Error")
    	    end 
    		local check_file=ngx.re.gmatch(multipart_data[0],[[=]],'ijo')
	        local ret={}
	        while true do
    		    local m, err = check_file()
    	      	if m then 
    	      		table.insert(ret,m)
    	      	else
    	      		break
    	      	end 
	        end
	        if type(ret)~='table' then return false end 
	        if(Public.arrlen(ret)>=2) then
	            return Public.return_message(200,"multipart/form-data ERROR")
	        end
    		return header
    	else
    		return false
    	end 
    end 
end


function upload.ReadFileHelper4(str)
	if type(str)~='string' then return str end
	local res = string.gsub(str, "@", "")
	return ngx.unescape_uri(res)
end

function  upload.return_error2(rule,rule2)
    ngx.ctx.is_type="http包非法"
	ngx.ctx.error_rule = 'from-data 请求异常,拒绝访问,如有误报请点击误报'..' >> '..rule..' >> '..rule2
	IpInfo.write_log('upload','from-data 请求异常,拒绝访问,如有误报请点击误报')
    local check_html = [[<html><meta charset="utf-8" /><title>from-data请求error</title><div>宝塔WAF提醒您,from-data 请求异常,拒绝访问,如有误报请点击误报</div></html>]]
		ngx.header.content_type = "text/html;charset=utf8"
		ngx.header.Cache_Control = "no-cache"
		ngx.say(check_html)
		ngx.exit(200)
end 


function upload.disable_upload_ext(ext)
	local server_name =ngx.ctx.server_name
	if not ext then return false end
	if type(ext)=='string' then 
		ext = string.lower(ext)
		if ngx.re.match(ext,'\\.user\\.ini',"jo") or ngx.re.match(ext,'\\.htaccess',"jo") or ngx.re.match(ext,'\\.php',"jo") or ngx.re.match(ext,'\\.jsp',"jo") then 
		    ngx.ctx.is_type='webshell防御'
	        IpInfo.lan_ip('upload','上传非法文件被系统拦截,并且被封锁IP')
		    return true
		end
	end 
	if not Site_config[server_name] then return false end 
	local disa=Site_config[server_name]['disable_upload_ext']
	local ret={}
	for _,k  in ipairs(disa) do table.insert(ret,"\\."..k)	end
	if BTWAF_OBJS.request_check.is_ngx_match(ret,ext,'post') then
	    ngx.ctx.is_type='webshell防御'
		IpInfo.lan_ip('upload','上传非法PHP文件被系统拦截,并且被封锁IP2'..' >> '..ext)
		return true
	end
end


function upload.return_error(int_age)
    ngx.ctx.is_type='http包非法'
	IpInfo.lan_ip('upload','http包非法,并且被封锁IP,如果自定义了from-data可能会导致误报。如果大量出现当前问题。请在全局设置->恶意文件上传防御->From-data协议 关闭此功能'..int_age)
end 


function upload.disable_upload_ext2(ext)
	local server_name =ngx.ctx.server_name

	if not ext then return false end
    if type(ext)~='table' then return false end 
	for i,k in pairs(ext) do 
	    for i2,k2 in pairs(k) do
	       local check_file=ngx.re.gmatch(k2,[[filename=]],'ijo')
	       local ret={}
	       while true do
    		    local m, err = check_file()
    	      	if m then 
    	      		table.insert(ret,m)
    	      	else
    	      		break
    	      	end 
	       end
            if Public.arrlen(ret)>1 then 
                upload.return_error(1)
            end
    	    if not ngx.re.match(k2,[[filename=""]],'ijo') and  not ngx.re.match(k2,[[filename=".+"]],'ijo') then 
				upload.return_error(2)
    	    else 
    	        k2 = string.lower(k2)
    	        if Site_config[server_name] ==nil then return false end 
	        	local disa=Site_config[server_name]['disable_upload_ext']
				local ret_disa={}
	        	for _,k  in ipairs(disa) do  table.insert(ret_disa,"\\."..k) end
            	if BTWAF_OBJS.request_check.is_ngx_match(ret_disa,k2,'post') then
            	    ngx.ctx.is_type='恶意上传'
            		IpInfo.lan_ip('upload','上传非法PHP文件被系统拦截,并且被封锁IP3'..' >> '..k2)
            		return true
            	end
    	    end
    	 end 
	end 
end

function  upload.from_data(data,data2,data3)
	if Public.arrlen(data) ==0 then return false end 
	local count=0
	for k,v in pairs(data) do
	    if ngx.re.match(v[0],'filename=',"jo") then 
	        if not ngx.re.match(v[0],'Content-Disposition: form-data; name="[^"]+"; filename=""\r*$','ijo') then 
	            if not ngx.re.match(v[0],'Content-Disposition: form-data; name="[^"]+"; filename="[^"]+"\r*$','ijo') then 
	                ngx.ctx.is_type='恶意上传'
	                upload.return_error2(v[0],'4.5')
	            end
	        end
	        count=count+1
	        upload.disable_upload_ext(v[0])
	    end
	    if Config['from_data'] then 
			if not ngx.re.match(v[0],'filename=',"jo") and  not ngx.re.match(v[0],'Content-Disposition: form-data; name="[^"]+"\r*$','ijo')  then 
			    ngx.ctx.is_type='http包非法'
				if not ngx.re.match(v[0],[[Content-Disposition: form-data; name=""]],'ijo') then 
					upload.return_error2(v[0],'5')
				end
			end
		end
	end
    local len_count=Public.arrlen(data2)+Public.arrlen(data3)
	if count ~=len_count then
		   ngx.ctx.is_type='http包非法'
	       upload.return_error2('','6')
	 end 
end


function upload.disable_upload_ext3(ext,check)
	local server_name =ngx.ctx.server_name

	if not ext then return false end
    if type(ext)~='table' then return false end 
    for i2,k2 in pairs(ext) do
		local check_file=ngx.re.gmatch(k2,[[(\W)filename=]],'ijo')
		local ret={}
      	while true do
    	    local m, err = check_file()
          	if m then 
          		table.insert(ret,m)
          	else
          		break
          	end 
        end
        if Public.arrlen(ret)>1 then 
            upload.return_error(6)
        end
        if check==1 then
             if Public.arrlen(ret)==0 then 
            	if not k2 then return false end 
				if ngx.re.match(k2,[[Content-Disposition: form-data; name=".+\\"\r]],"jo") then 
					upload.return_error2('','0.1')
                end
				local kkkkk=ngx.re.match(k2,[[Content-Disposition:.{200}]],'ijo')
			    if not kkkkk then 
                	if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r]],'ijom') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;name=]],'ijo')  or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;\s*\r*\n*n\s*\r*\n*a\s*\r*\n*m\s*\r*\n*e\s*\r*\n*=]],'ijo') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\s*;]],'ijo') then 
                		k2=string.gsub(k2,'\r','')
                		if ngx.re.match(k2,[[filename=]],'ijo') then 
                		    ngx.ctx.is_type='恶意上传'
                		    return IpInfo.lan_ip('upload','非法上传请求已被系统拦截,并且被封锁IP1') 
                		end 
						if not ngx.re.match(k2,[[Content-Disposition: form-data; name=""]],'ijo') and not  ngx.re.match(k2,'^Content-Disposition: form-data; name=".+"','ijo') then 
							return upload.return_error2('','1')
						end
                	end
                else
                    k2=kkkkk[0]
                    if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r]],'ijom') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;name=]],'ijo')  or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;\s*\r*\n*n\s*\r*\n*a\s*\r*\n*m\s*\r*\n*e\s*\r*\n*=]],'ijo') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\s*;]],'ijo') then 
                		k2=string.gsub(k2,'\r','')
                		if ngx.re.match(k2,[[filename=]],'ijo') then 
                		    ngx.ctx.is_type='恶意上传'
                		    return IpInfo.lan_ip('upload','非法上传请求已被系统拦截,并且被封锁IP2') 
                		end
                		return upload.return_error2('','2')
                	end
                end
                if k2 then 
                	k2=string.gsub(k2,'\r','')
            		if ngx.re.match(k2,[[filename=]],'ijo') then 
            		    ngx.ctx.is_type='恶意上传'
            		    return IpInfo.lan_ip('upload','非法上传请求已被系统拦截,并且被封锁IP3') 
            	    end 
                end
            	if ngx.re.match(k2,[[Content-Disposition: form-data; name="(.+)"\r]],'ijos') then 
            	    local tttt=ngx.re.match(k2,[[Content-Disposition: form-data; name="(.+)"\r\s]],'ijos')
                    if tttt==nil then return false end 
                    if #tttt[0] >200 then return false end
                    if tttt[1] ==nil then return false end 
                    tttt[1]=string.gsub(tttt[1],'\n','')
		            tttt[1]=string.gsub(tttt[1],'\t','')
		            tttt[1]=string.gsub(tttt[1],'\r','')
		            if ngx.re.match(tttt[1],'name=','ijo') then return upload.return_error2(tttt[1],tttt[1]) end
            	end
            	if ngx.re.match(k2,[[\r\r(.+)\r\r]],'ijos') then 
            	    local tttt=ngx.re.match(k2,[[\r\r(.+)\r\r]],'ijos')
                    if tttt==nil then return false end 
                    if #tttt[0] >200 then return false end 
                    if tttt[1] ==nil then return false end 
                    tttt[1]=string.gsub(tttt[1],'\n','')
		            tttt[1]=string.gsub(tttt[1],'\t','')
		            tttt[1]=string.gsub(tttt[1],'\r','')
		            if ngx.re.match(tttt[1],'name=','ijo') then return upload.return_error2(tttt[1],tttt[1]) end
            	end
			else
				if not k2 then return false end 
				k2=string.gsub(k2,'\r','')
				local k3=""
				local kkkkk=ngx.re.match(k2,[[Content-Disposition:.{500}]],'ijo')
				if not kkkkk then 
				    k3=ngx.re.match(k2,[[Content-Disposition:.+Content-Type:]],'ijo')
				    ngx.ctx.is_type='恶意上传'
				    if not k3 then return IpInfo.lan_ip('upload','非法上传请求已被系统拦截,并且被封锁IP4') end 
				    
				    if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=""Content-Type:]],'ijo') and not  ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:]],'ijo') then 
				        ngx.ctx.is_type='恶意上传'
            	        return IpInfo.lan_ip('upload','非法上传请求已被系统拦截,并且被封锁IP5')
            	    end 
				else
				    k3=ngx.re.match(kkkkk[0],[[Content-Disposition:.+Content-Type:]],'ijo')
				    if not k3 then  return false end 
					if not ngx.re.match(k3[0],[[Content-Disposition: form-data; name=".+"; filename=""Content-Type:]],'ijo') and not  ngx.re.match(k3[0],[[Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:]],'ijo') then
					    ngx.ctx.is_type='恶意上传'
            	        return IpInfo.lan_ip('upload','非法上传请求已被系统拦截,并且被封锁IP7')
            	    end
				end
				if Site_config[server_name] ==nil then return false end 
            	local disa=Site_config[server_name]['disable_upload_ext']
				local ret_disa={}
	        	for _,k  in ipairs(disa) do  table.insert(ret_disa,"\\."..k) end
            	if BTWAF_OBJS.request_check.is_ngx_match(ret_disa,k3,'post') then
            	    ngx.ctx.is_type='恶意上传'
            		IpInfo.lan_ip('upload','上传非法PHP文件被系统拦截,并且被封锁IP4')
            	end
            	if #k3[0] >500 then 
        	       local ret10={}
            	   local tmp10 = ngx.re.gmatch(k3[0],'form-data',"jo")
            	   while true do local m, err = tmp10() if m then  table.insert(ret10,m) else break end  end
                   if tonumber(Public.arrlen(ret10)) >1 then return false end 
                   if ngx.re.match(k3[0],'--$') then return false end
                   return Public.return_message(200,'error1->The upload file name is too long')
        	   	end
            	local tmp8 = ngx.re.gmatch(k3[0],'\"',"jo")
            	local tmp9 = ngx.re.gmatch(k3[0],'=',"jo")
            	local tmp10 = ngx.re.gmatch(k3[0],';',"jo")
                local ret8={}
                local ret9={}
                local ret10={}
                while true do local m, err = tmp8() if m then  table.insert(ret8,m) else break end  end
                while true do local m, err = tmp9() if m then  table.insert(ret9,m) else break end  end
                while true do local m, err = tmp10() if m then  table.insert(ret10,m) else break end  end
                if tonumber(Public.arrlen(ret9))~=2 and tonumber(Public.arrlen(ret8))~=4 and tonumber(Public.arrlen(ret10))~=2 then
                    upload.return_error2('','10')
                end
             end
            
        else 
            if Public.arrlen(ret)==0 then
                return false
            else 
                local kkkkk=ngx.re.match(k2,[[Content-Disposition:.{500}]],'ijo')
				local k3=""
				if not kkkkk then 
				    k3=ngx.re.match(k2,[[Content-Disposition:.+Content-Type:]],'ijo')
				    if not k3 then return upload.return_error(7) end 
				    if ngx.re.match(k2,[[Content-Disposition: form-data; name=".+\\"]]) then 
                       upload.return_error2('','10.33')
                    end
				    if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=""Content-Type:]],'ijo') and not  ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:]],'ijo') then 
				        ngx.ctx.is_type='恶意上传'
            	        return IpInfo.lan_ip('upload','非法上传请求已被系统拦截,并且被封锁IP5')
            	    end 
				else
    				if ngx.re.match(kkkkk[0],[[Content-Disposition: form-data; name=".+\\"]],"jo") then 
                       upload.return_error2('','10.33')
                    end
				    k3=ngx.re.match(kkkkk[0],[[Content-Disposition:.+Content-Type:]],"jo")
				    if not k3 then 
				        return false
				    end 
					if not ngx.re.match(k3[0],[[Content-Disposition: form-data; name=".+"; filename=""Content-Type:]],'ijo') and not  ngx.re.match(k3[0],[[Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:]],'ijo') then
						ngx.ctx.is_type='恶意上传'
            	        return IpInfo.lan_ip('upload','非法上传请求已被系统拦截,并且被封锁IP7')
            	    end
				end
				k3=k3[0]
        	    if not ngx.re.match(k3,[[filename=""Content-Type]],'ijo') and  not ngx.re.match(k3,[[filename=".+"Content-Type]],'ijo') then 
        			upload.return_error(8)
        	    else
        	    	local check_filename=ngx.re.match(k3,[[filename="(.+)"Content-Type]],'ijo')
        	        if check_filename then 
        	            if check_filename[1] then
        	                if ngx.re.match(check_filename[1],'name=','ijo') then return upload.return_error(9) end 
        	                if ngx.re.match(check_filename[1],'php','ijo') then return upload.return_error(10) end 
        	                if ngx.re.match(check_filename[1],'jsp','ijo') then return upload.return_error(11) end 
        	            end 
        	        end
        	        if #k3 >=500 then 
        	           ngx.ctx.is_type='文件名过长'
                       IpInfo.bt_ip_filterwrite_log('upload','上传的文件名太长了,被系统拦截')
                       return Public.return_message(200,'The uploaded file name is too long')
        	        end
        	        k3 = string.lower(k3)
        	        if Site_config[server_name] ==nil then return false end 
                	local disa=Site_config[server_name]['disable_upload_ext']
                	if BTWAF_OBJS.request_check.is_ngx_match(disa,k3,'post') then
						ngx.ctx.is_type='恶意上传'
                		IpInfo.lan_ip('upload','上传非法PHP文件被系统拦截,并且被封锁IP1'..' >> '..k3)
                		return true
                	end
        	    end
            end 
        end 
	 end
end

function upload.data_in_php(data)
	return false
end

function upload.post_data()
-- 	if not config['post']['open'] or not is_site_config('post') then return false end
    if  not  Config['file_upload'] or  not  Config['file_upload']['open'] then return false end 
	if ngx.ctx.method ~= "POST" then return false end
	local content_length=tonumber(ngx.ctx.request_header['content-length'])
	if not content_length then return false end
	if content_length >108246867 then return false end 
	local boundary = upload.get_boundary()
	if boundary then
		ngx.req.read_body()
		local data = ngx.req.get_body_data()
		if not data then 
		   data=ngx.req.get_body_file()
		   if data==nil then return false end 
            data=Public.read_file_body(data) 
		end
		if not data then return false end
		local data233=string.gsub(data,'\r','')
		local tmp4 = ngx.re.gmatch(data,[[Content-Disposition.+]],'ijo')
		local tmp5 = ngx.re.gmatch(data,[[Content-Disposition: form-data; name=".+"; filename=".+"\r\nContent-Type:]],'ijo')
		local tmp6 = ngx.re.gmatch(data,[[Content-Disposition: form-data; name=".+"; filename=""\r\nContent-Type:]],'ijo')
		local ret3={}
		while true do local m, err = tmp4() if m then table.insert(ret3,m) else break end  end
		local ret5={}
		while true do local m, err = tmp5() if m then  table.insert(ret5,m) else break end end
	    local ret6={}
		while true do  local m, err = tmp6() if m then  table.insert(ret6,m) else break end  end
		upload.from_data(ret3,ret5,ret6)
		local tmp2 = ngx.re.gmatch(data,[[Content-Disposition.+filename=.+]],'ijo')
		local tmp3 = ngx.re.gmatch(data,[[Content-Disposition.+\s*f\r*\n*o\r*\n*r\r*\n*m\r*\n*-\r*\n*d\r*\n*a\r*\n*t\r*\n*a\r*\n*\s*;\r*\n*\s*n\r*\n*a\r*\n*m\r*\n*e=\r*\n*.+;\s*f\n*\s*\r*i\n*\s*\r*l\n*\s*\r*e\n*\s*\r*n\n*\s*\r*a\n*\s*\r*m\n*\s*\r*e\n*\s*\r*=.+\n*\s*\r*]],'ijo')
		local ret={}
		while true do local m, err = tmp2() if m then  table.insert(ret,m) else break end  end
		local ret2={}
		while true do local m, err = tmp3() if m then  table.insert(ret2,m) else break end  end
		upload.disable_upload_ext2(ret2)
	    if Public.arrlen(ret)==0 and Public.arrlen(ret2)>0 then 
	        upload.return_error(3)
	    end
	    ret=upload.gusb_string(ret)
		for k,v in pairs(ret) do 
			upload.disable_upload_ext(v)
		end
		local tmp2=ngx.re.match(data,[[Content-Type:[^\+]{100}]],'ijo')
		if tmp2 and tmp2[0] then 
			upload.data_in_php(tmp2[0])
		end
		local av=ngx.re.match(boundary,"=.+","jo")
		if not av then 
			IpInfo.write_log('upload','content_type_null')
			Public.return_html(Config['post']['status'],BTWAF_RULES.post_html)
		end
		local header_data=ngx.re.gsub(av[0],'=','')
		if #header_data>200 then 
		    upload.return_error(5)
		end
	    data=string.gsub(data,'\n','')
		data=string.gsub(data,'\t','')
		local tmp_pyload2 = ngx.re.match(data,'Content-Disposition:.+\r--','ijo')
 		if tmp_pyload2==nil then return false end 
 		local tmpe_data2=Public.split2(tmp_pyload2[0],header_data)
		if Public.arrlen(tmpe_data2)>0 then
			if Config['from_data'] then 
	    		upload.disable_upload_ext3(tmpe_data2,1)
	    	end
		end
		data=string.gsub(data,'\r','')
		local tmp_pyload = ngx.re.match(data,'Content-Disposition:.+Content-Type:','ijo')
         if tmp_pyload==nil then return false end 
		local tmpe_data=Public.split2(tmp_pyload[0],header_data)
		if Public.arrlen(tmpe_data)>0 then 
			if Config['from_data'] then
				upload.disable_upload_ext3(tmpe_data,2)
			end
		end 
	end
	return false
end


function upload.return_post_data2()
	if ngx.ctx.method ~= "POST" then return false end
	local content_length=tonumber(ngx.ctx.request_header['content-length'])
	if not content_length then return false end
	local boundary = upload.get_boundary()
	if boundary then
		ngx.req.read_body()
		local data = ngx.req.get_body_data()
		if not data then 
		   data=ngx.req.get_body_file()
			if data==nil then return false end
            data=Public.read_file_body(data) 
		end
		if not data then return false end
		local tmp2 = ngx.re.gmatch(data,[[Content-Disposition.+filename=]],'ijo')
		local ret={}
		while true do
		    local m, err = tmp2()
	      	if m then 
	      		table.insert(ret,m)
	      	else
	      		break
	      	end 
	    end
	    ret=upload.gusb_string(ret)
	    if Public.arrlen(ret)>=1 then  
		    for _,v in pairs(ret) do 
				if not ngx.re.match(v[0],'ContentbaotaDisposition: formbaotadata; name=".+"; filename=','ijo') and not ngx.re.match(v[0],'ContentbaotaDisposition: formbaotadata; name=”.+”; filename=','ijo') then 
					upload.return_error(12)
				end
		    end
	    end
	    if Public.arrlen(ret)==1 then 
	    	return 1 
	    else
	    	return 2 
	    end
	end
	return 3
end


function upload.ReadFileHelper(str)
	if type(str)~='string' then return str end
	local res = string.gsub(str, "\r", "")
	res = string.gsub(res, "\n", "")
   return res
end

function upload.table_key(tbl, key)
    if tbl == nil then
        return false
    end
    for k, v in pairs(tbl) do
        if k == key then
            return true
        end
    end
    return false
end



function upload.chsize(char)
	if not char then
		print("not char")
		return 0
	elseif char > 240 then
		return 4
	elseif char > 225 then
		return 3
	elseif char > 192 then
		return 2
	else
		return 1
	end
end

function upload.utf8sub(str, startChar, numChars)
	local startIndex = 1
	while startChar > 1 do
		local char = string.byte(str, startIndex)
		startIndex = startIndex + upload.chsize(char)
		startChar = startChar - 1
	end

	local currentIndex = startIndex

	while numChars > 0 and currentIndex <= #str do
		local char = string.byte(str, currentIndex)
		currentIndex = currentIndex + upload.chsize(char)
		numChars = numChars -1
	end
	return str:sub(startIndex, currentIndex - 1)
end

function upload.is_substitution(data)
    data=ngx.re.sub(data,"\\+",'\\+')
    return data
end

function  upload.post_data_chekc()
    if  not  Config['file_upload'] or  not  Config['file_upload']['open'] then return false end 
	local content_length=tonumber(ngx.ctx.request_header['content-length'])
	if not content_length then return false end
	if content_length >108246867 then return false end
	if ngx.ctx.method =="POST" then
		local return_post_data=upload.return_post_data2()
		if not return_post_data then return false end 
		if return_post_data==3 then return false end 
				ngx.req.read_body()
		local request_args2=ngx.req.get_body_data()
		if not request_args2 then 
		    request_args2=ngx.req.get_body_file()
			if request_args2==nil then return false end 
		    request_args2=Public.read_file_body(request_args2)
		end
		if not request_args2  then return false end
		if not ngx.ctx.request_header['content-type'] then return false end
		if type(ngx.ctx.request_header['content-type']) ~= "string" then 
			if type(ngx.ctx.request_header['content-type']) ~= "string" then 
				upload.return_error(13)
			end
		end
        local p, err = multipart.new(request_args2, ngx.var.http_content_type)
        if not p then
           return false 
        end
        if not ngx.re.match(upload.ReadFileHelper(p['body']),upload.is_substitution(upload.ReadFileHelper(p['boundary2']))..'--$','ijo') then
           	return Public.return_message(200,"btwaf is from-data error")
        end
        local site_count=0
        local array = {}
        while true do
            local part_body, name, mime, filename,is_filename,header_data = p:parse_part()
		    if header_data then 
               local header_data_check=ngx.re.gmatch(header_data,[[Content-Disposition: form-data]],'ijo')
               local ret={}
	            while true do
        		    local m, err = header_data_check()
        	      	if m then 
        	      		table.insert(ret,m)
        	      	else
        	      		break
        	      	end 
	            end
	            if Public.arrlen(ret)>1 then 
	                return Public.return_message(200,"btwaf is from-data error2")
	            end 
            end 
            if not is_filename then
              break
            end
            site_count=site_count+1
			if is_filename then 
                local filename_data=ngx.re.match(is_filename,'filename.+','ijo')
                if filename_data then
					ngx.ctx.is_type='webshell防御'
                    if ngx.re.match(filename_data[0],'php','ijo') then return IpInfo.lan_ip('upload','上传非法PHP文件被系统拦截,并且被封锁IP13')  end 
        	        if ngx.re.match(filename_data[0],'\\.jsp','ijo') then return IpInfo.lan_ip('upload','上传非法PHP文件被系统拦截,并且被封锁IP14')  end
					if  Config['from_data'] then 
						if not ngx.re.match(is_filename,'^Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:','ijo') and not ngx.re.match(is_filename,'^Content-Disposition: form-data; name=".+"; filename=""Content-Type:','ijo') then 
							  	ngx.ctx.is_type='恶意上传'
							  	ngx.var.waf2monitor_blocked="恶意上传文件"
							  	if not ngx.re.match(is_filename,'^Content-Disposition: form-data; name="filename"$',"ijo") and not ngx.re.match(is_filename,'^Content-Disposition: form-data; name=".+"$',"ijo") then 
							        return upload.return_error(20)
							  end 
						end
					end
				end
				if(#is_filename)>1000 then 
				    ngx.var.waf2monitor_blocked="恶意上传"
					ngx.ctx.is_type="文件名过长"
                    IpInfo.lan_ip('upload','非法上传文件名长度超过1000被系统拦截,并封锁IP15') 
                end 

            end
            if filename ~=nil then 
				ngx.ctx.is_type='webshell防御'
        	    if ngx.re.match(filename,'php','ijo') then return IpInfo.lan_ip('upload','上传非法PHP文件被系统拦截,并且被封锁IP15')  end 
        	    if ngx.re.match(filename,'\\.jsp','ijo') then return IpInfo.lan_ip('upload','上传非法PHP文件被系统拦截,并且被封锁IP16')  end
				if ngx.re.match(filename,'name=','ijo') then return upload.return_error(15) end 
				if (#filename)>=1000 then
				    ngx.var.waf2monitor_blocked="恶意上传文件"
        	        IpInfo.lan_ip('upload','非法上传文件名长度超过1000被系统拦截,并封锁IP15') 
        	    end 
            end
            if name ==nil then 
              if part_body then
                    if #part_body>30 then 
                        array[upload.utf8sub(part_body,1,30)]=part_body
                    else
                        array[part_body]=part_body
                    end
              end
            else
               if #name >300 then 
                  upload.return_error(16)
               end
               
               if filename ==nil then
                   if upload.table_key(array,name) then
                        for i=1, 1000 do
                            if not upload.table_key(array,name..'_'..i) then 
                                 if #name>30 then 
                                    array[upload.utf8sub(name,1,30)..'_'..i]=part_body 
                                 else
                                     array[name..'_'..i]=part_body 
                                 end 
                                 
                                 break
                            end 
                        end 
                    else
                        if #name >30 then 
                            array[upload.utf8sub(name,1,30)]=part_body
                        else 
                            array[name]=part_body
                        end 
                   end
	               if type(part_body)=='string' then
    					if (#part_body) >=400000 then
							ngx.ctx.is_type="参数过长"
    						IpInfo.write_log('sql',name..'     参数值长度超过40w已被系统拦截')
    						Public.return_html(Config['post']['status'],BTWAF_RULES.post_html)
    						return true
    					end
	    			end
                else
                    if type(part_body) =='string' and  part_body ~=nil then 
					    if ngx.re.find(part_body,[["php"]],'ijo') or ngx.re.find(part_body,[['php']],'ijo') or  ngx.re.find(part_body,[[<\?]],'ijo') or  ngx.re.find(part_body,[[phpinfo\(]],'ijo') or ngx.re.find(part_body,[[\$_SERVER]],'ijo') or ngx.re.find(part_body,[[<\?php]],'ijo') or ngx.re.find(part_body,[[fputs]],'ijo') or ngx.re.find(part_body,[[file_put_contents]],'ijo') or ngx.re.find(part_body,[[file_get_contents]],'ijo') or ngx.re.find(part_body,[[eval\(]],'ijo') or ngx.re.find(part_body,[[\$_POST]],'ijo')  or ngx.re.find(part_body,[[\$_GET]],'ijo') or ngx.re.find(part_body,[[base64_decode\(]],'ijo') or ngx.re.find(part_body,[[\$_REQUEST]],'ijo') or ngx.re.find(part_body,[[assert\(]],'ijo') or ngx.re.find(part_body,[[copy\(]],'ijo') or ngx.re.find(part_body,[[create_function\(]],'ijo') or ngx.re.find(part_body,[[preg_replace\(]],'ijo') or ngx.re.find(part_body,[[preg_filter\(]],'ijo') or ngx.re.find(part_body,[[system\(]],'ijo') or ngx.re.find(part_body,[[header_register_callback\(]],'ijo') or ngx.re.find(part_body,[[curl_init\(]],'ijo') or ngx.re.find(part_body,[[curl_error\(]],'ijo') or ngx.re.find(part_body,[[fopen\(]],'ijo')  or ngx.re.find(part_body,[[stream_context_create\(]],'ijo') or ngx.re.find(part_body,[[fsockopen\(]],'ijo')  then
					        local php_version=7
					        if  Site_config[ngx.ctx.server_name]['php']~=nil then 
					            php_version=tonumber(Site_config[ngx.ctx.server_name]['php'])
							end
				            if php_engine.php_detected(part_body,php_version)==1 then 
				                ngx.var.waf2monitor_blocked="webshell防御"
				                ngx.ctx.is_type='webshell防御'
				                IpInfo.lan_ip('upload','webshell防御.拦截木马上传,并被封锁IP')
				            end 
				        end 
                    end 
               end
            end
        end
        if site_count==0 then
        	if  Config['from_data'] then 
        		return upload.return_error2('','4') 
        	end
        end
        if Public.count_sieze(array)>=3000 then
            ngx.ctx.is_type='POST参数'
			ngx.ctx.error_rule = '参数太多POST传递的参数数量超过800,拒绝访问,如有误报请点击误报'
		    IpInfo.write_log('sql','参数太多POST传递的参数数量超过800,拒绝访问,如有误报请点击误报')
		    Public.return_html_data('网站防火墙','您的请求带有不合法参数，已被网站管理员设置拦截','网站防火墙提醒您multipart/from-data传递的参数数量超过800,拒绝访问','点击误报')
		end
		if array['_method']  and array['method'] and array['server[REQUEST_METHOD]'] then
		    ngx.ctx.is_type='ThinkPHP攻击'
		    ngx.var.waf2monitor_blocked="ThinkPHP攻击"
			IpInfo.lan_ip('php','拦截ThinkPHP 5.x RCE 攻击')
		end
		if array['_method']  and array['method'] and array['server[]'] and array['get[]'] then
		    ngx.ctx.is_type='ThinkPHP攻击'
		    ngx.var.waf2monitor_blocked="ThinkPHP攻击"
			IpInfo.lan_ip('php','拦截ThinkPHP 5.x RCE 攻击,并且被封锁IP')
		end
		if array['_method'] and ngx.re.match(array['_method'],'construct','ijo') then
		    ngx.ctx.is_type='ThinkPHP攻击'
		    ngx.var.waf2monitor_blocked="ThinkPHP攻击"
			IpInfo.lan_ip('php','拦截ThinkPHP 5.x RCE 攻击,并且被封锁IP')
		end
       BTWAF_OBJS.request_check.args_urlencoded(Public.process_json_args(array))
	   for i,v in pairs(array) do 
            if ngx.re.match(i,'\\\\$','ijo') then 
                ngx.ctx.is_type='恶意上传'
                ngx.var.waf2monitor_blocked="恶意上传"
                return IpInfo.lan_ip('upload','非法上传请求已被系统拦截,并且被封锁IP11') 
            end 
        end 
	end
end


return upload