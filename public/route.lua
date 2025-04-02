local route={}



function route.get_btwaf_captcha_base64()
	local ip=ngx.ctx.ip
	local token = ngx.md5(ngx.ctx.ip..'base64')
	local count,_ = ngx.shared.btwaf:get(token)
	if count then
		if ngx.ctx.retry<10 then ngx.ctx.retry=10 end
		if count > ngx.ctx.retry then
			local safe_count,_ = ngx.shared.drop_sum:get(ip)
			if not safe_count then
				ngx.shared.drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.drop_sum:incr(ip,1)
			end
			local lock_time = (Config['retry_time'] * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.drop_ip:set(ngx.ctx.ip,ngx.ctx.retry+1,lock_time)
			ngx.ctx.is_type='cc'
			ngx.var.waf2monitor_blocked="人机验证封锁IP|验证码验证-达到验证次数阈值已封锁IP"
			IpInfo.lan_ip('cc','防火墙获取验证码接口遭到该IP攻击:  '..ngx.ctx.cycle..'秒内累计超过'..Config['retry']..'次请求,封锁' .. lock_time .. '秒')
		else
			ngx.var.waf2monitor_blocked="验证码验证接口"
			ngx.shared.btwaf:incr(token,1)
		end
	else
		ngx.shared.btwaf:set(token,1,Config['retry_cycle'])
	end
	ngx.var.waf2monitor_blocked="返回验证码"
	math.randomseed(tostring(os.time()):reverse():sub(1, 6))
	local n1 = math.random(1,200)
	ngx.shared.btwaf:set(ip..'__captcha',BTWAF_RULES.captcha_num2[tostring(n1)],180)
	local file_name=BTWAF_INC..'/captcha/'..n1..'_'..BTWAF_RULES.captcha_num2[tostring(n1)]..'.png'
	local data=Public.re_png(file_name)
	return Public.get_return_state(true,ngx.encode_base64(data))
end

function route.toASCII2(str,type)
    local temp_1=''
    for i = 1, #str do
        local temp_2=string.byte(string.sub(str,i,i))
        if temp_1=='' then 
            if type==1 then temp_1=string.char(temp_2+1) else temp_1=string.char(temp_2) end 
        else
            if type==1 then temp_1=temp_1..string.char(temp_2+1) else temp_1=temp_1..string.char(temp_2) end
        end 
    end
    return temp_1
end 


--@name获取Ua中的系统信息
--@param string Ua
--@return table 返回系统信息
function route.getUAField(t)
	local tab={}
	local android=string.find(t,"Android")
    local iphone=string.find(t,"Mac")
	local windows=string.find(t,"Windows")
 	if android  then
		tab["platform"]="android"
    		tab["ismobiledevice"]="true"
	end
	if iphone then
		local ipho = string.find(t,"iPhone")
		local mac = string.find(t,"Macintosh")
		if ipho then
			tab["platform"]="iOS"
			tab["ismobiledevice"]="iphone"
		end
		if mac then
			tab["platform"]="Mac"
			tab["ismobiledevice"]="PC"
		end
	end
    if windows  then
		tab["platform"]="Windows"
		tab["ismobiledevice"]="flase"
	end
	if Public.arrlen(tab) == 0 then
		tab["platform"]="Other"
		tab["ismobiledevice"]="flase"
	end
	return tab
end

function route.toASCII(str,type)
    local temp_1=''
    for i = 1, #str do
        local temp_2=string.byte(string.sub(str,i,i))
        if temp_1=='' then 
            if type==1 then temp_1=temp_2+1 else temp_1=temp_2 end 
        else
            if type==1 then temp_1=temp_1..temp_2+1 else temp_1=temp_1..temp_2 end
        end 
    end
    return temp_1
end 


function route.send_Verification()
	local ip=ngx.ctx.ip
	local request_header=ngx.ctx.request_header
	local token = ngx.md5(ip)
	local count,_ = ngx.shared.btwaf:get(token)
	if count then
		if ngx.ctx.retry<10 then ngx.ctx.retry=10 end
		if count > ngx.ctx.retry then
			local safe_count,_ = ngx.shared.drop_sum:get(ip)
			if not safe_count then
				ngx.shared.drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.drop_sum:incr(ip,1)
			end
			local lock_time = (Config['retry_time'] * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.drop_ip:set(ip,ngx.ctx.retry+1,lock_time)
			ngx.var.waf2monitor_blocked="人机验证封锁IP|人机验证-达到验证次数阈值已封锁IP"
			ngx.ctx.is_type='cc'
			IpInfo.lan_ip('cc','人机验证页面遭到该IP攻击:  '..Config['retry_cycle']..'秒内累计超过'..ngx.ctx.retry..'次请求,封锁' .. lock_time .. '秒')
		else
			ngx.shared.btwaf:incr(token,1)
		end
	else
		ngx.shared.btwaf:set(token,1,Config['retry_cycle'])
	end

	if not request_header['user-agent'] then request_header['user-agent']='Mozilla/5.0 (Windows NT 10.0; Win64; x64)' end
	local ua_type=route.getUAField(request_header['user-agent'])
	if ua_type["platform"] == "android" or ua_type["platform"]=="iOS" then 
		local jsbody= string.format([[
<html>
	<head>
		<title>宝塔防火墙</title>
		<style>
			body{font-family:Tahoma,Verdana,Arial,sans-serif;}.head_title{margin-top:0;font-family:"微软雅黑";font-size:50px;font-weight:lighter;}p{font-family:"微软雅黑";font-size:16px;font-weight:lighter;color:#666666;}.btn{width:90vw;height:11.5vw;line-height:11.5vw;text-align:center;font-size:4vw;background:#20a53a;box-shadow:inset 0 1px 2px #30ad42;color:#fff;text-shadow:#00851a 0 -1px 0;font-family:"微软雅黑";border:0;cursor:pointer;transition:all 500ms;margin-top:3vw;}.btn:hover{color:#fff;background-color:#008e1c;border-color:#398439;}.inp_captcha{float:left;padding:10px;width:58vw;box-sizing:border-box;padding-left:2vw;height:12vw;font-size:5vw;border:2px solid #c0c0c0;outline:none;border-right:0;}.inp_captcha:focus{border:2px solid #20a53a;border-right:0;padding-left:3vw;}.yzm{float:left;width:30vw;height:12vw;line-height:12vw;font-size:4vw;color:#333;border-radius:2px;border:2px solid #c0c0c0;box-sizing:border-box;}.form{margin:0 auto;overflow:hidden;margin-top:3.5vw;}.captcha-box{margin-top:20vw;padding:0 5vw;}#errmsg{font-size: 4vw;}
		</style>
	</head>
	<body>
		<script>
			if (window != top) {
				location.href = location.href
			}
		</script>
		<div align="center" class="captcha-box">
			<div class="tit">
				<img src="data:image/jpg;base64,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" alt="" style="width:30vw;padding-bottom:10px"/>
			</div>
			<p style="font-weight: 400;font-size: 4.8vw;margin-bottom:1.5vw ">此为人机校验，请输入验证码继续访问</p>
			<p style="margin:0"><font color="red" id="errmsg"></font></p>
			<form class="form" action="#" onsubmit="return false" method="POST">
				<input id="value" class="inp_captcha" name="captcha" type="text" />
				<img class="yzm" id="yzm" onclick="showCaptcha()" alt="验证码图片">
				<button type="submit" class="btn" onclick="mfwaf_auth()" type="button">提交</button>
			</form>
		</div>
		<script>
			document.onkeydown=function(e){var theEvent=window.event||e;var code=theEvent.keyCode||theEvent.which||theEvent.charCode;if(code==13){var value=document.getElementById("value").value;var c="/Verification_auth_btwaf?captcha="+value;mfajax2("GET",c)}};function showCaptcha(){var t=(new Date()).valueOf();var b="/get_btwaf_captcha_base64?captcha="+t;mfajax("GET",b)}showCaptcha();function mfajax(a,b,c){var xmlHttp=new XMLHttpRequest();xmlHttp.onreadystatechange=function(){if(xmlHttp.readyState==4&&xmlHttp.status==200){var data=JSON.parse(xmlHttp.responseText);if(data.status==true){yzm.src="data:image/png;base64,"+data.msg}else{if(data.status){location.href=location.href}else{errmsg.innerHTML="验证码输入错误，请重新输入"}}}else{if(xmlHttp.readyState==4&&xmlHttp.status==404){if(a=="GET"){errmsg.innerHTML="无法获取验证码"}else{errmsg.innerHTML="此IP可能已经被屏蔽，请明天或稍后再试"}}}};xmlHttp.open(a,b,true);xmlHttp.send(c)}function mfajax2(a,b,c){var xmlHttp=new XMLHttpRequest();xmlHttp.onreadystatechange=function(){if(xmlHttp.readyState==4&&xmlHttp.status==200){var data=JSON.parse(xmlHttp.responseText);if(data.status==true){location.href=location.href}else{if(data.status){location.href=location.href}else{errmsg.innerHTML="验证码输入错误，请重新输入"}}}else{if(xmlHttp.readyState==4&&xmlHttp.status==404){if(a=="GET"){errmsg.innerHTML="无法获取验证码"}else{errmsg.innerHTML="此IP可能已经被屏蔽，请明天或稍后再试"}}}};xmlHttp.open(a,b,true);xmlHttp.send(c)}function mfwaf_auth(){var value=document.getElementById("value").value;var c="/Verification_auth_btwaf?captcha="+value;mfajax2("GET",c)};
		</script>
	</body>
	</html>
	]])
		ngx.header.content_type = "text/html;charset=utf8"
		ngx.header.Cache_Control = "no-cache"
		ngx.say(jsbody)
		ngx.exit(500)
	else
		local jsbody22 = string.format([[
	<html><head><title>宝塔防火墙</title>
	<style>body{font-family:Tahoma,Verdana,Arial,sans-serif}.head_title{margin-top:0;font-family:"微软雅黑";font-size:50px;font-weight:lighter}p{font-family:"微软雅黑";font-size:16px;font-weight:lighter;color:#666}.btn{float:left;width:63px;height:40px;background:#20a53a;box-shadow:inset 0 1px 2px #30ad42;color:#fff;text-shadow:#00851a 0 -1px 0;font-family:"微软雅黑";font-size:16px;border:0;cursor:pointer;outline:0;border-top-right-radius:2px;border-bottom-right-radius:2px;transition:all 500ms}.btn:hover{color:#fff;background-color:#008e1c;border-color:#398439}.inp_captcha{float:left;margin-left:10px;padding:10px;width:200px;height:40px;font-size:20px;border-top-left-radius:2px;border-bottom-left-radius:2px;border:1px solid #c0c0c0;outline:0;border-right:0}.inp_captcha:focus{border:1px solid #20a53a;border-right:0}.yzm{float:left;width:130px;height:40px;border-radius:2px}.form{margin:0 auto;width:415px;height:40px}</style>
	</head><body>
	<script>if (window != top) {location.href = location.href;}</script>
	<div align="center" class="captcha-box" style="margin-top:150px"><div class="tit">
	<img src="data:image/jpg;base64,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" alt="" style="width:130px;padding-bottom:10px"/>
	</div>
	<p style="font-weight: 400;font-size: 17px">此为人机校验，请输入验证码来继续访问 (PS: 如需关闭此功能请在防火墙中关闭增强模式 )：</p><p><font color="red" id="errmsg"></font></p>
	<form class="form" action="#" onsubmit="return false" method="POST"><img class="yzm" id="yzm" onclick="showCaptcha()" alt="验证码图片"><input id="value" class="inp_captcha" name="captcha" type="text" /><button type="submit" class="btn" onclick="mfwaf_auth()" type="button">提交</button></form>
	</div>
	<script>document.onkeydown=function(e){var theEvent=window.event||e;var code=theEvent.keyCode||theEvent.which||theEvent.charCode;if(code==13){var value=document.getElementById("value").value;var c="/Verification_auth_btwaf?captcha="+value;mfajax2("GET",c);theEvent.preventDefault();theEvent.stopPropagation();}};function showCaptcha(){var t=(new Date()).valueOf();var b="/get_btwaf_captcha_base64?captcha="+t;mfajax("GET",b)}showCaptcha();function mfajax(a,b,c){var xmlHttp=new XMLHttpRequest();xmlHttp.onreadystatechange=function(){if(xmlHttp.readyState==4&&xmlHttp.status==200){var data=JSON.parse(xmlHttp.responseText);if(data.status==true){yzm.src="data:image/png;base64,"+data.msg}else{if(data.status){location.href=location.href}else{errmsg.innerHTML="验证码输入错误，请重新输入"}}}else{if(xmlHttp.readyState==4&&xmlHttp.status==404){if(a=="GET"){errmsg.innerHTML="无法获取验证码"}else{errmsg.innerHTML="此IP可能已经被屏蔽，请明天或稍后再试"}}}};xmlHttp.open(a,b,true);xmlHttp.send(c)}function mfajax2(a,b,c){var xmlHttp=new XMLHttpRequest();xmlHttp.onreadystatechange=function(){if(xmlHttp.readyState==4&&xmlHttp.status==200){var data=JSON.parse(xmlHttp.responseText);if(data.status==true){location.href=location.href}else{if(data.status){location.href=location.href}else{errmsg.innerHTML="验证码输入错误，请重新输入"}}}else{if(xmlHttp.readyState==4&&xmlHttp.status==404){if(a=="GET"){errmsg.innerHTML="无法获取验证码"}else{errmsg.innerHTML="此IP可能已经被屏蔽，请明天或稍后再试"}}}};xmlHttp.open(a,b,true);xmlHttp.send(c)}function mfwaf_auth(){var value=document.getElementById("value").value;var c="/Verification_auth_btwaf?captcha="+value;mfajax2("GET",c)};</script>
	</body></html>
		]])
		ngx.header.content_type = "text/html;charset=utf8"
		ngx.header.Cache_Control = "no-cache"
		ngx.say(jsbody22)
		ngx.exit(403)
	 end
end 


function route.send_check_heml(cache_token)
	local ip=ngx.ctx.ip
	local request_header=ngx.ctx.request_header
	local server_name=ngx.ctx.server_name
	local check_key = tostring(math.random(1000,99999999))
	ngx.shared.btwaf:set(cache_token .. '_key',check_key,60)
	local vargs = '&btwaf='
	local sargs = string.gsub(ngx.ctx.request_uri,'.?btwaf=.*','')
	if not string.find(sargs,'?',1,true) then vargs = '?btwaf=' end
	local safe_count = ngx.shared.drop_sum:get(ip..ngx.ctx.today)
	if not safe_count then
		ngx.shared.drop_sum:set(ip..ngx.ctx.today,1,ngx.ctx.endtime)
		safe_count = 1
	else
		ngx.shared.drop_sum:incr(ip..ngx.ctx.today,1)
		safe_count = safe_count +1
	end
	if ngx.ctx.retry<10 then ngx.ctx.retry=10 end 
	if safe_count >= ngx.ctx.retry then
		local safe_count2,_ = ngx.shared.drop_sum:get(ip)
		if not safe_count2 then safe_count2=1 end
		local retry_time = Site_config[server_name]['retry_time']
		local lock_time = (retry_time * safe_count2)
		if lock_time > 86400 then lock_time = 86400 end
		ngx.ctx.is_type='cc'
		local msg='跳转验证-累计超过'.. ngx.ctx.retry ..'次验证失败,封锁' .. lock_time .. '秒'
		if ngx.ctx.is_url_type~=nil then 
		    msg=ngx.ctx.is_url_type..' 累计超过'.. ngx.ctx.retry ..'次验证失败,封锁' .. lock_time .. '秒'..'  (PS:URL级CC防御只在当前页面验证、不影响其他页面)'
		end 
		ngx.var.waf2monitor_blocked="人机验证封锁IP|跳转验证-达到验证次数阈值已封锁IP"

		IpInfo.write_log('cc',msg)
		IpInfo.write_drop_ip('cc',lock_time,msg)
	end
	local check_html = [[<html><meta charset="utf-8" /><title>检测中</title><div>跳转中</div></html>
<script> window.location.href ="]] .. sargs .. vargs .. check_key .. [["; </script>]]
	ngx.header.content_type = "text/html;charset=utf8"
	
	local token=''
    if request_header['user-agent']~=nil then 
    	token=ngx.md5(ip..request_header['user-agent']..server_name..'btwaf'..ngx.ctx.today)
    else
    	token=ngx.md5(ip..server_name..'btwaf'..ngx.ctx.today)
    end 
    local jwt_value=ngx.md5(os.time()..ip)
    ngx.shared.btwaf_data:set(jwt_value,ngx.md5(ip..request_header['user-agent']),7200)
    ngx.status = 403
    ngx.shared.btwaf:set(token,jwt_value,7200)
    ngx.header.Set_Cookie =token.."="..jwt_value..';'
	ngx.header.Cache_Control = "no-cache"
	ngx.say(check_html)
	ngx.exit(403)
end

function route.send_check_cookie(cache_token)
	local ip=ngx.ctx.ip
	local request_header=ngx.ctx.request_header
	local server_name=ngx.ctx.server_name
	local token=''
    if request_header['user-agent']~=nil then 
    	token=ngx.md5(ip..request_header['user-agent']..server_name..'btwaf'..ngx.ctx.today)
    else
    	token=ngx.md5(ip..server_name..'btwaf'..ngx.ctx.today)
    end 
    if ngx.ctx.cookie~=nil and  ngx.ctx.cookie:get(token)~=nil then
		if ngx.shared.btwaf:get(token)==nil then
			local jwt_value=ngx.md5(os.time()..ip)
			ngx.shared.btwaf:set(token,jwt_value,7200)
		end
	end
	local safe_count = ngx.shared.drop_sum:get(ip..ngx.ctx.today)
	if not safe_count then
		ngx.shared.drop_sum:set(ip..ngx.ctx.today,1,ngx.ctx.endtime)
		safe_count = 1
	else
		ngx.shared.drop_sum:incr(ip..ngx.ctx.today,1)
		safe_count = safe_count +1
	end
	if ngx.ctx.retry<10 then ngx.ctx.retry=10 end 
	if safe_count >= ngx.ctx.retry then
		local safe_count2,_ = ngx.shared.drop_sum:get(ip)
		if not safe_count2 then safe_count2=1 end
		local retry_time = Site_config[server_name]['retry_time']
		local lock_time = (retry_time * safe_count2)
		if lock_time > 86400 then lock_time = 86400 end
		ngx.ctx.is_type='cc'
		
		local msg=""
		if ngx.ctx.is_url_type then 
			msg='URL级别防御-累计超过'.. ngx.ctx.retry ..'次验证失败,封锁' .. lock_time .. '秒'
		else 
			msg='跳转验证-累计超过'.. ngx.ctx.retry ..'次验证失败,封锁' .. lock_time .. '秒'
		end 
		ngx.var.waf2monitor_blocked="人机验证封锁IP|跳转验证-达到验证次数阈值已封锁IP"
		if ngx.ctx.is_url_type~=nil then 
		    msg=ngx.ctx.is_url_type..' 累计超过'.. ngx.ctx.retry ..'次验证失败,封锁' .. lock_time .. '秒'..'  (PS:URL级CC防御只在当前页面验证、不影响其他页面)'
		end 
		IpInfo.write_log('cc',msg)
		IpInfo.write_drop_ip('cc',lock_time,msg)
	end
	local check_html = [[<html><meta charset="utf-8" /><title></title><div></div></html>
<script> window.location.href ="]] .. ngx.ctx.request_uri .. [["; </script>]]
	ngx.header.content_type = "text/html;charset=utf8"
	
	local token=''
	local expires = ngx.cookie_time(os.time()+7200)
    if request_header['user-agent']~=nil then 
    	token=ngx.md5(ip..request_header['user-agent']..server_name..'btwaf'..ngx.ctx.today)
    else
    	token=ngx.md5(ip..server_name..'btwaf'..ngx.ctx.today)
    end 
    local jwt_value=ngx.md5(os.time()..ip)
    ngx.var.waf2monitor_blocked="人机验证"
    ngx.shared.btwaf_data:set(jwt_value,ngx.md5(ip..request_header['user-agent']),7200)
    ngx.status = 403
    ngx.shared.btwaf:set(token,jwt_value,7200)
    ngx.header.Set_Cookie =token.."="..jwt_value..'; expires='..expires..'; path=/;'
	ngx.header.Cache_Control = "no-cache"
	ngx.say(check_html)
	ngx.exit(403)
end

function route.send_Verification_renji(type)
	local ip=ngx.ctx.ip
	local request_header=ngx.ctx.request_header
	local server_name=ngx.ctx.server_name
    if type=='code' then 
        route.send_Verification()
    end 
    if type=='btwaf' then 
        local cache_token = ngx.md5(ip .. '_' .. server_name)
        route.send_check_cookie(cache_token)
    end
	local token = ngx.md5(ip..ngx.ctx.today)
	local count,_ = ngx.shared.btwaf:get(token)
	local token2 =ngx.md5(ip..ngx.ctx.today..ngx.ctx.ua..type)
	local count2,_ = ngx.shared.btwaf:get(token)
	if count and count2 then
	    if ngx.ctx.retry<10 then ngx.ctx.retry=10 end
		if count2 > ngx.ctx.retry then
			local safe_count,_ = ngx.shared.drop_sum:get(ip)
			if not safe_count then
				ngx.shared.drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.drop_sum:incr(ip,1)
			end
			local lock_time = (Config['retry_time'] * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.drop_ip:set(ip,ngx.ctx.retry+1,lock_time)
			IpInfo.bt_ip_filter(ip,lock_time)
			ngx.ctx.is_type='cc'
			local msg="人机验证"
			if type=="browser" then msg="浏览器验证" end 
			if type=="code" then msg="验证码验证" end 
			if type=="renji" then msg="人机验证" end 
			if type=="huadong" then msg="滑动验证" end 
			ngx.var.waf2monitor_blocked="人机验证封锁IP|"..msg.."-达到验证次数阈值已封锁IP"

			IpInfo.lan_ip('cc',msg..Config['retry_cycle']..'秒内累计超过'..ngx.ctx.retry..'验证失败,封锁' .. lock_time .. '秒')
		else
			ngx.shared.btwaf:incr(token,1)
			ngx.shared.btwaf:incr(token2,1)
		end
	else
		ngx.shared.btwaf:set(token,1,Config['retry_cycle'])
		ngx.shared.btwaf:set(token2,1,Config['retry_cycle'])
	end
    if type=='renji' then
    	if not request_header['user-agent'] then request_header['user-agent']='Mozilla/5.0 (Windows NT 10.0; Win64; x64)' end
        local ua_type=route.getUAField(request_header['user-agent'])
    	if ua_type["platform"] == "android" or ua_type["platform"]=="iOS" then 
    		local jsbody = string.format([[
    <!DOCTYPE html><html>
      <head>
        <meta charset="UTF-8" />
        <title>人机验证</title>
        <meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no">
        <style>.verifyBox{position:fixed;top:0;right:0;bottom:0;left:0;text-align:center;white-space:nowrap;overflow:auto}.verifyBox:after{content:'';display:inline-block;height:100vh;vertical-align:middle}.verifyContent{display:inline-block;vertical-align:middle;text-align:center;white-space:normal}.loading{width:150px;height:15px;margin:0 auto;}.loading span{display:inline-block;width:15px;height:100%s;margin-right:5px;border-radius:50%s;background:#151515;-webkit-animation:load 1.5s ease infinite}.loading span:last-child{margin-right:0px}@-webkit-keyframes load{0%s{opacity:1}100%s{opacity:0}}.loading span:nth-child(1){-webkit-animation-delay:0.13s}.loading span:nth-child(2){-webkit-animation-delay:0.26s}.loading span:nth-child(3){-webkit-animation-delay:0.39s}.loading span:nth-child(4){-webkit-animation-delay:0.52s}.loading span:nth-child(5){-webkit-animation-delay:0.65s}h1{font-size:1.5em;color:#404040;text-align:center}</style>
      </head>
      <body>
      <div class="verifyBox">
        <div class="verifyContent">
            <div class="loading">
                <span></span>
                <span></span>
                <span></span>
                <span></span>
                <span></span>
            </div>
            <h1>宝塔防火墙正在检查您的访问</h1>
            <p id="bt-info">正在进行人机识别，请稍等……</p>
            <p>本站受宝塔防御系统保护</p>
        </div>
    </div>
        <script type="text/javascript" src="/renji_296d626f_%s.js?id=%s"></script>
      </body>
    </html>]],'%','%','%','%',ngx.md5(ip),os.time())
    		ngx.header.content_type = "text/html;charset=utf8"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(jsbody)
    		ngx.exit(403)
    	else
    		local jsbody22 = string.format([[
    <!DOCTYPE html><html>
      <head>
        <meta charset="UTF-8" />
        <title>人机验证</title>
        <meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no">
        <style>.verifyBox{position:fixed;top:0;right:0;bottom:0;left:0;text-align:center;white-space:nowrap;overflow:auto}.verifyBox:after{content:'';display:inline-block;height:100vh;vertical-align:middle}.verifyContent{display:inline-block;vertical-align:middle;text-align:center;white-space:normal}.loading{width:150px;height:15px;margin:0 auto;}.loading span{display:inline-block;width:15px;height:100%s;margin-right:5px;border-radius:50%s;background:#151515;-webkit-animation:load 1.5s ease infinite}.loading span:last-child{margin-right:0px}@-webkit-keyframes load{0%s{opacity:1}100%s{opacity:0}}.loading span:nth-child(1){-webkit-animation-delay:0.13s}.loading span:nth-child(2){-webkit-animation-delay:0.26s}.loading span:nth-child(3){-webkit-animation-delay:0.39s}.loading span:nth-child(4){-webkit-animation-delay:0.52s}.loading span:nth-child(5){-webkit-animation-delay:0.65s}h1{font-size:1.5em;color:#404040;text-align:center}</style>
      </head>
      <body>
      <div class="verifyBox">
        <div class="verifyContent">
            <div class="loading">
                <span></span>
                <span></span>
                <span></span>
                <span></span>
                <span></span>
            </div>
            <h1>宝塔防火墙正在检查您的访问</h1>
            <p id="bt-info">正在进行人机识别，请稍等……</p>
            <p>本站受宝塔防御系统保护</p>
        </div>
    </div>
        <script type="text/javascript" src="/renji_296d626f_%s.js?id=%s"></script>
      </body>
    </html>]],'%','%','%','%',ngx.md5(ip),os.time())
    		ngx.header.content_type = "text/html;charset=utf8"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(jsbody22)
    		ngx.exit(403)
    	end
    elseif type=='huadong' then 
        if not request_header['user-agent'] then request_header['user-agent']='Mozilla/5.0 (Windows NT 10.0; Win64; x64)' end
    	local ua_type=route.getUAField(request_header['user-agent'])
    	if ua_type["platform"] == "android" or ua_type["platform"]=="iOS" then 
    		local jsbody= string.format([[
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no">
    <title>滑动验证</title>
    <style>.slideBox{position:fixed;top:0;right:0;bottom:0;left:0;text-align:center;font-size:0;white-space:nowrap;overflow:auto}.slideBox:after{content:'';display:inline-block;height:100vh;vertical-align:middle}.slider{display:inline-block;vertical-align:middle;text-align:center;font-size:13px;white-space:normal}.slider::before{content:'人机身份验证，请完成以下操作';font-size: 16px;display: inline-block;margin-bottom: 30px;}</style>
</head>
<body>
    <div class="slideBox"><div class="slider"></div></div>
    <script type="text/javascript" src="/huadong_296d626f_%s.js?id=%s"></script>
</body>
</html>]],ngx.md5(ip),os.time())
    		ngx.header.content_type = "text/html;charset=utf8"
    		ngx.say(jsbody)
    		ngx.exit(403)
    	else
    		local jsbody22 = string.format([[<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no">
    <title>滑动验证</title>
    <style>.slideBox{position:fixed;top:0;right:0;bottom:0;left:0;text-align:center;font-size:0;white-space:nowrap;overflow:auto}.slideBox:after{content:'';display:inline-block;height:100vh;vertical-align:middle}.slider{display:inline-block;vertical-align:middle;text-align:center;font-size:13px;white-space:normal}.slider::before{content:'人机身份验证，请完成以下操作';font-size: 16px;display: inline-block;margin-bottom: 30px;}</style>
</head>
<body>
    <div class="slideBox"><div class="slider"></div></div>
    <script type="text/javascript" src="/huadong_296d626f_%s.js?id=%s"></script>
</body>
</html>]],ngx.md5(ip),os.time())
    		ngx.header.content_type = "text/html;charset=utf8"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(jsbody22)
    		ngx.exit(403)
    	end
    elseif type=='browser' then 
local jsbody= string.format([[
        <!DOCTYPE html>
<html>
      <head>
        <meta charset="UTF-8" />
        <title>Browser authentication</title>
        <meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no">
        <style>.verifyBox{position:fixed;top:0;right:0;bottom:0;left:0;text-align:center;white-space:nowrap;overflow:auto}.verifyBox:after{content:'';display:inline-block;height:100vh;vertical-align:middle}.verifyContent{display:inline-block;vertical-align:middle;text-align:center;white-space:normal}.loading{width:150px;height:15px;margin:0 auto;}.loading span{display:inline-block;width:15px;height:100%s;margin-right:5px;border-radius:50%s;background:#151515;-webkit-animation:load 1.5s ease infinite}.loading span:last-child{margin-right:0px}@-webkit-keyframes load{0%s{opacity:1}100%s{opacity:0}}.loading span:nth-child(1){-webkit-animation-delay:0.13s}.loading span:nth-child(2){-webkit-animation-delay:0.26s}.loading span:nth-child(3){-webkit-animation-delay:0.39s}.loading span:nth-child(4){-webkit-animation-delay:0.52s}.loading span:nth-child(5){-webkit-animation-delay:0.65s}h1{font-size:1.5em;color:#404040;text-align:center}</style>
        <style></style>
      </head>
      <body>
          <div class="verifyBox">
            <div class="verifyContent">
                <div class="loading">
                    <span></span>
                    <span></span>
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
                <h1>BT.CN firewall is checking your browser access</h1>
                <p id="bt-info">Browser recognition in progress, please wait……</p>
                <p>This station is protected by the BT.CN defense system</p>
            </div>
        </div>
        <p><code id="time"/></p>
        <p><span id="details"/></p>
        <script src="/Rxizm32rm3CPpyyW_fingerprint2daasdsaaa.js?id=%s%s"></script>
        <script>
        var options={preprocessor:null,audio:{timeout:1000,excludeIOS11:true},fonts:{swfContainerId:'fingerprintjs2',swfPath:'flash/compiled/FontList.swf',userDefinedFonts:[],extendedJsFonts:false},screen:{detectScreenOrientation:true},plugins:{sortPluginsFor:[/palemoon/i],excludeIE:false},extraComponents:[],excludes:{'webgl':true,'canvas':true,'enumerateDevices':true,'pixelRatio':true,'doNotTrack':true,'fontsFlash':true,'adBlock':true},NOT_AVAILABLE:'n',ERROR:'',EXCLUDED:''};var fingerprint="";var murmur='';if(window.requestIdleCallback){requestIdleCallback(function(){Fingerprint2.get(options,function(components){var values=components.map(function(component){return component.value});murmur=Fingerprint2.x64hash128(values.join(''),31);sendWafValida()})})}else{setTimeout(function(){Fingerprint2.get(options,function(components){var values=components.map(function(component){return component.value});murmur=Fingerprint2.x64hash128(values.join(''),31);sendWafValida()})},500)};function sendWafValida(){var key='%s',value='%s',newWord='',newVal='';for(var i=0;i<murmur.length;i++){var _mur=String.fromCharCode(murmur.charAt(i).charCodeAt()-1);newWord+=_mur}for(var j=0;j<value.length;j++){var _val=String.fromCharCode(value.charAt(j).charCodeAt()+1);newVal+=_val};var url='/Rxizm32rm3CPpyyW_yanzheng_ip.php?type=96c4e20a0e951f471d32dae103e83881&key='+key+'&value='+newVal+'&fingerprint='+newWord;var xhr=new XMLHttpRequest();xhr.open('post',url);xhr.onreadystatechange=function(){if(xhr.readyState===4&&xhr.status===200){setTimeout(function(){location.reload()},3000)}};xhr.send()};
        </script>
    </body>
</html>]],'%','%','%','%',ngx.md5(ip),os.time(),ngx.md5(ip),ngx.md5(request_header['user-agent']))
        	ngx.header.content_type = "text/html;charset=utf8"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(jsbody)
    		ngx.exit(403)
	end 
end 



function route.Verification_auth_btwaf()
	local ip=ngx.ctx.ip
	local uri_request_args=ngx.ctx.get_uri_args
	local request_header=ngx.ctx.request_header
	local server_name=ngx.ctx.server_name
	local token = ngx.md5(ip..'auth')
	local count,_ = ngx.shared.btwaf:get(token)
	if count then
	    if ngx.ctx.retry<10 then ngx.ctx.retry=10 end 
		if count > ngx.ctx.retry then
			local safe_count,_ = ngx.shared.drop_sum:get(ip)
			if not safe_count then
				ngx.shared.drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.drop_sum:incr(ip,1)
			end
			local lock_time = (Config['retry_time'] * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.drop_ip:set(ip,ngx.ctx.retry+1,lock_time)
			ngx.var.waf2monitor_blocked="人机验证封锁IP|达到验证次数阈值已封锁IP"
			ngx.ctx.is_type='cc'
			IpInfo.lan_ip('cc','防火墙验证码接口遭到该IP攻击:  '..ngx.ctx.cycle..'秒内累计超过'..ngx.ctx.retry..'次请求,封锁' .. lock_time .. '秒')
		else
			ngx.var.waf2monitor_blocked="验证码验证失败"
			ngx.shared.btwaf:incr(token,1)
		end
	else
		ngx.shared.btwaf:set(token,1,Config['retry_cycle'])
	end
	local num2=ngx.shared.btwaf:get(ip..'__captcha')
	if num2 ==nil then  return Public.get_return_state(false,'验证码已经过期') end
	if uri_request_args['captcha'] then
		if num2 ==string.lower(uri_request_args['captcha']) then
            local token=''
            if request_header['user-agent']~=nil then 
            	token=ngx.md5(ip..request_header['user-agent']..server_name..'code'..ngx.ctx.today)
            else
            	token=ngx.md5(ip..server_name..'code'..ngx.ctx.today)
            end 
			ngx.var.waf2monitor_blocked="验证码验证成功"
            local jwt_value=ngx.md5(os.time()..ip)
            ngx.shared.btwaf:set(token,jwt_value,7200)
            ngx.header.Set_Cookie =token.."="..jwt_value..';'
			return Public.get_return_state(true,'验证成功')
		else
			return Public.get_return_state(false,'验证码错误')
		end 
	end
	return Public.get_return_state(false,'请填写验证码')
end

function route.yanzhengip(type)
	local ip=ngx.ctx.ip
	local uri_request_args=ngx.ctx.get_uri_args
	local request_header=ngx.ctx.request_header
	local server_name=ngx.ctx.server_name
    if type=="browser" then 
        if uri_request_args['key'] ==nil or uri_request_args['value']==nil or uri_request_args['type']==nil or uri_request_args['fingerprint']==nil then
            route.send_Verification_renji(type)
        end
        local fingerprint=route.toASCII2(uri_request_args['fingerprint'],1)
        if uri_request_args['key'] == ngx.md5(ip) and uri_request_args['value']==route.toASCII2(ngx.md5(request_header['user-agent']),1) and uri_request_args['type']=='96c4e20a0e951f471d32dae103e83881' then 
            local token=''
            if request_header['user-agent']~=nil then 
            	token=ngx.md5(ip..request_header['user-agent']..server_name..type..ngx.ctx.today)
            else
            	token=ngx.md5(ip..server_name..type..ngx.ctx.today)
            end 
            ngx.shared.btwaf_data:set(fingerprint,ngx.md5(ip..request_header['user-agent']),7200)
            
            local expires = ngx.cookie_time(os.time()+7200)
            ngx.shared.btwaf:set(token,fingerprint,7200)
            ngx.var.waf2monitor_blocked="人机验证成功"
            ngx.header.Set_Cookie =token.."="..fingerprint.."; expires=" .. expires .. "; httponly; path=/"
            ngx.header.content_type = "application/json;"
            ngx.header.Cache_Control = "no-cache"
            ngx.status = 200
            ngx.say(fingerprint)
            ngx.exit(200)
        else 
            route.send_Verification_renji(type)
        end
    elseif type=='renji' then 
        if uri_request_args['key'] ==nil or uri_request_args['value']==nil or uri_request_args['type']==nil then
            route.send_Verification_renji(type)
        end
        if uri_request_args['key'] == ngx.md5(ip) and uri_request_args['value']==ngx.md5(route.toASCII(ngx.md5(request_header['user-agent']),0)) and uri_request_args['type']=='96c4e20a0e951f471d32dae103e83881' then 
            local token=''
            if request_header['user-agent']~=nil then 
            	token=ngx.md5(ip..request_header['user-agent']..server_name..type..ngx.ctx.today)
            else
            	token=ngx.md5(ip..server_name..type..ngx.ctx.today)
            end 
            local jwt_value=ngx.md5(os.time()..ip)
            ngx.var.waf2monitor_blocked="人机验证成功"
            ngx.shared.btwaf_data:set(jwt_value,ngx.md5(ip..request_header['user-agent']),7200)
            local expires = ngx.cookie_time(os.time()+7200)
            ngx.shared.btwaf:set(token,jwt_value,7200)
            ngx.header.Set_Cookie =token.."="..jwt_value.."; expires=" .. expires .. "; httponly; path=/"
            ngx.header.content_type = "application/json;"
            ngx.header.Cache_Control = "no-cache"
            ngx.status = 200
            ngx.say(token)
            ngx.exit(200)
        else 
            route.send_Verification_renji(type)
        end
    elseif type=='huadong' then 
        if uri_request_args['key'] ==nil or uri_request_args['value']==nil or uri_request_args['type']==nil then
            route.send_Verification_renji(type)
        end
        if uri_request_args['key'] == ngx.md5(ip) and uri_request_args['value']==ngx.md5(route.toASCII(ngx.md5(request_header['user-agent']),1)) and uri_request_args['type']=='ad82060c2e67cc7e2cc47552a4fc1242' then 
            local token=''
            if request_header['user-agent']~=nil then 
            	token=ngx.md5(ip..request_header['user-agent']..server_name..type..ngx.ctx.today)
            else
            	token=ngx.md5(ip..server_name..type..ngx.ctx.today)
            end 
            ngx.var.waf2monitor_blocked="人机验证成功"
            local jwt_value=ngx.md5(os.time()..ip)
            ngx.shared.btwaf_data:set(jwt_value,ngx.md5(ip..request_header['user-agent']),7200)
            local expires = ngx.cookie_time(os.time()+7200)
            ngx.shared.btwaf:set(token,jwt_value,7200)
            ngx.header.Set_Cookie =token.."="..jwt_value.."; expires=" .. expires .. "; httponly"
            ngx.header.content_type = "application/json;"
            ngx.header.Cache_Control = "no-cache"
            ngx.status = 200
            ngx.say(token)
            ngx.exit(200)
        else 
            route.send_Verification_renji(type)
        end
    end
end

function route.get_btwaf_drop_ip()
	local data =  ngx.shared.drop_ip:get_keys(0)
	return data
end
function route.add_temporary_ip()
    local uri_request_args=ngx.ctx.get_uri_args
	if not uri_request_args['ip'] or not Public.is_ipaddr(uri_request_args['ip']) then return Public.get_return_state(false,'格式错误') end
	if not uri_request_args['timeout'] or tonumber(uri_request_args['timeout'])==nil then return Public.get_return_state(false,'超时时间错误') end
    local ip=uri_request_args['ip']
    local timeout=tonumber(uri_request_args['timeout'])
    if ngx.shared.drop_ip:get(ip) then return Public.get_return_state(false,'ip已经在封锁列表中') end 
    ngx.shared.drop_ip:set(ip,timeout)
    return Public.get_return_state(true,'添加成功')
end 



function route.remove_btwaf_drop_ip()
	local uri_request_args=ngx.ctx.get_uri_args
	if not uri_request_args['ip'] or not Public.is_ipaddr(uri_request_args['ip']) then return Public.get_return_state(true,'格式错误') end
	local token2 = ngx.md5(uri_request_args['ip'] .. '_' ..'return_cc_url')
	local token3 = ngx.md5(uri_request_args['ip'] .. '_' ..'header_cc')
	ngx.shared.btwaf_data:delete(token3)
    ngx.shared.btwaf:delete(token2)
    ngx.shared.btwaf:delete(ngx.md5(uri_request_args['ip']))
	ngx.shared.drop_ip:delete(uri_request_args['ip'])
	ngx.shared.btwaf:delete(ngx.md5(uri_request_args['ip']))
	ngx.shared.btwaf:delete(ngx.md5(uri_request_args['ip']..ngx.ctx.today))
	ngx.shared.btwaf:delete(ngx.md5(uri_request_args['ip']..'base64'))
	ngx.shared.btwaf_data:delete(uri_request_args['ip'])
	ngx.shared.btwaf_data:delete(uri_request_args['ip']..'_san')
    ngx.shared.drop_sum:delete(uri_request_args['ip'])
    ngx.shared.drop_sum:delete(uri_request_args['ip']..ngx.ctx.today)
	return Public.get_return_state(true,uri_request_args['ip'] .. '已解封')
end


function route.clean_btwaf_drop_ip()
	local data = route.get_btwaf_drop_ip()
	for _,value in ipairs(data)
	do
	    ngx.shared.btwaf:delete(ngx.md5(value..ngx.ctx.today))
	    ngx.shared.btwaf:delete(ngx.md5(value..'base64'))
	    ngx.shared.btwaf:delete(ngx.md5(value))
	    ngx.shared.btwaf_data:delete(value)
	    ngx.shared.btwaf:delete(ngx.md5(value))
		ngx.shared.drop_ip:delete(value)
		local token2 = ngx.md5(value .. '_' ..'return_cc_url')
		local token3 = ngx.md5(value .. '_' ..'header_cc')
		ngx.shared.btwaf_data:delete(token3)
		ngx.shared.btwaf:delete(token2)
		ngx.shared.btwaf_data:delete(value..'_san')
		ngx.shared.drop_sum:delete(value)
        ngx.shared.drop_sum:delete(value..ngx.ctx.today)
	end
	return Public.get_return_state(true,'已解封所有IP')
end

function route.clean_spider_status()
	for i,v in pairs(Site_config) do
	    ngx.shared.spider:delete(i.."spider_no")
	    ngx.shared.spider:delete(i.."spider")
	end 
end

function route.yanzhengjs(type)
	local ip=ngx.ctx.ip
	local request_header=ngx.ctx.request_header
    if type=='renji' then 
    		local jsbody22='var cx=cx||function(p,j){var h={},m=h.lib={},n=m.Base=function(){function a(){}return{extend:function(d){a.prototype=this;var c=new a;d&&c.mixIn(d);c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.$super.extend(this)}}}(),b=m.WordArray=n.extend({init:function(a,d){a=this.words=a||[];this.sigBytes=d!=j?d:4*a.length},toString:function(a){return(a||q).stringify(this)},concat:function(a){var d=this.words,c=a.words,g=this.sigBytes,a=a.sigBytes;this.clamp();if(g%4)for(var f=0;f<a;f++)d[g+f>>>2]|=(c[f>>>2]>>>24-8*(f%4)&255)<<24-8*((g+f)%4);else if(65535<c.length)for(f=0;f<a;f+=4)d[g+f>>>2]=c[f>>>2];else d.push.apply(d,c);this.sigBytes+=a;return this},clamp:function(){var a=this.words,d=this.sigBytes;a[d>>>2]&=4294967295<<32-8*(d%4);a.length=p.ceil(d/4)},clone:function(){var a=n.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var d=[],c=0;c<a;c+=4)d.push(4294967296*p.random()|0);return b.create(d,a)}}),i=h.enc={},q=i.Hex={stringify:function(a){for(var d=a.words,a=a.sigBytes,c=[],g=0;g<a;g++){var f=d[g>>>2]>>>24-8*(g%4)&255;c.push((f>>>4).toString(16));c.push((f&15).toString(16))}return c.join("")},parse:function(a){for(var d=a.length,c=[],g=0;g<d;g+=2)c[g>>>3]|=parseInt(a.substr(g,2),16)<<24-4*(g%8);return b.create(c,d/2)}},k=i.Latin1={stringify:function(a){for(var d=a.words,a=a.sigBytes,c=[],g=0;g<a;g++)c.push(String.fromCharCode(d[g>>>2]>>>24-8*(g%4)&255));return c.join("")},parse:function(a){for(var d=a.length,c=[],g=0;g<d;g++)c[g>>>2]|=(a.charCodeAt(g)&255)<<24-8*(g%4);return b.create(c,d)}},l=i.Utf8={stringify:function(a){try{return decodeURIComponent(escape(k.stringify(a)))}catch(d){throw Error("Malformed UTF-8 data");}},parse:function(a){return k.parse(unescape(encodeURIComponent(a)))}},e=m.BufferedBlockAlgorithm=n.extend({reset:function(){this._data=b.create();this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=l.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var d=this._data,c=d.words,g=d.sigBytes,f=this.blockSize,o=g/(4*f),o=a?p.ceil(o):p.max((o|0)-this._minBufferSize,0),a=o*f,g=p.min(4*a,g);if(a){for(var e=0;e<a;e+=f)this._doProcessBlock(c,e);e=c.splice(0,a);d.sigBytes-=g}return b.create(e,g)},clone:function(){var a=n.clone.call(this);a._data=this._data.clone();return a},_minBufferSize:0});m.Hasher=e.extend({init:function(){this.reset()},reset:function(){e.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);this._doFinalize();return this._hash},clone:function(){var a=e.clone.call(this);a._hash=this._hash.clone();return a},blockSize:16,_createHelper:function(a){return function(d,c){return a.create(c).finalize(d)}},_createHmacHelper:function(a){return function(d,c){return r.HMAC.create(a,c).finalize(d)}}});var r=h.algo={};return h}(Math);(function(){var p=cx,j=p.lib.WordArray;p.enc.Base64={stringify:function(h){var m=h.words,j=h.sigBytes,b=this._map;h.clamp();for(var h=[],i=0;i<j;i+=3)for(var q=(m[i>>>2]>>>24-8*(i%4)&255)<<16|(m[i+1>>>2]>>>24-8*((i+1)%4)&255)<<8|m[i+2>>>2]>>>24-8*((i+2)%4)&255,k=0;4>k&&i+0.75*k<j;k++)h.push(b.charAt(q>>>6*(3-k)&63));if(m=b.charAt(64))for(;h.length%4;)h.push(m);return h.join("")},parse:function(h){var h=h.replace(/\\s/g,""),m=h.length,n=this._map,b=n.charAt(64);b&&(b=h.indexOf(b),-1!=b&&(m=b));for(var b=[],i=0,q=0;q<m;q++)if(q%4){var k=n.indexOf(h.charAt(q-1))<<2*(q%4),l=n.indexOf(h.charAt(q))>>>6-2*(q%4);b[i>>>2]|=(k|l)<<24-8*(i%4);i++}return j.create(b,i)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();(function(p){function j(e,b,a,d,c,g,f){e=e+(b&a|~b&d)+c+f;return(e<<g|e>>>32-g)+b}function h(e,b,a,d,c,g,f){e=e+(b&d|a&~d)+c+f;return(e<<g|e>>>32-g)+b}function m(e,b,a,d,c,g,f){e=e+(b^a^d)+c+f;return(e<<g|e>>>32-g)+b}function n(e,b,a,d,c,g,f){e=e+(a^(b|~d))+c+f;return(e<<g|e>>>32-g)+b}var b=cx,i=b.lib,q=i.WordArray,i=i.Hasher,k=b.algo,l=[];(function(){for(var e=0;64>e;e++)l[e]=4294967296*p.abs(p.sin(e+1))|0})();k=k.MD5=i.extend({_doReset:function(){this._hash=q.create([1732584193,4023233417,2562383102,271733878])},_doProcessBlock:function(e,b){for(var a=0;16>a;a++){var d=b+a,c=e[d];e[d]=(c<<8|c>>>24)&16711935|(c<<24|c>>>8)&4278255360}for(var d=this._hash.words,c=d[0],g=d[1],f=d[2],o=d[3],a=0;64>a;a+=4)16>a?(c=j(c,g,f,o,e[b+a],7,l[a]),o=j(o,c,g,f,e[b+a+1],12,l[a+1]),f=j(f,o,c,g,e[b+a+2],17,l[a+2]),g=j(g,f,o,c,e[b+a+3],22,l[a+3])):32>a?(c=h(c,g,f,o,e[b+(a+1)%16],5,l[a]),o=h(o,c,g,f,e[b+(a+6)%16],9,l[a+1]),f=h(f,o,c,g,e[b+(a+11)%16],14,l[a+2]),g=h(g,f,o,c,e[b+a%16],20,l[a+3])):48>a?(c=m(c,g,f,o,e[b+(3*a+5)%16],4,l[a]),o=m(o,c,g,f,e[b+(3*a+8)%16],11,l[a+1]),f=m(f,o,c,g,e[b+(3*a+11)%16],16,l[a+2]),g=m(g,f,o,c,e[b+(3*a+14)%16],23,l[a+3])):(c=n(c,g,f,o,e[b+3*a%16],6,l[a]),o=n(o,c,g,f,e[b+(3*a+7)%16],10,l[a+1]),f=n(f,o,c,g,e[b+(3*a+14)%16],15,l[a+2]),g=n(g,f,o,c,e[b+(3*a+5)%16],21,l[a+3]));d[0]=d[0]+c|0;d[1]=d[1]+g|0;d[2]=d[2]+f|0;d[3]=d[3]+o|0},_doFinalize:function(){var b=this._data,i=b.words,a=8*this._nDataBytes,d=8*b.sigBytes;i[d>>>5]|=128<<24-d%32;i[(d+64>>>9<<4)+14]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360;b.sigBytes=4*(i.length+1);this._process();b=this._hash.words;for(i=0;4>i;i++)a=b[i],b[i]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360}});b.MD5=i._createHelper(k);b.HmacMD5=i._createHmacHelper(k)})(Math);(function(){var p=cx,j=p.lib,h=j.Base,m=j.WordArray,j=p.algo,n=j.EvpKDF=h.extend({cfg:h.extend({keySize:4,hasher:j.MD5,iterations:1}),init:function(b){this.cfg=this.cfg.extend(b)},compute:function(b,i){for(var h=this.cfg,k=h.hasher.create(),l=m.create(),e=l.words,j=h.keySize,h=h.iterations;e.length<j;){a&&k.update(a);var a=k.update(b).finalize(i);k.reset();for(var d=1;d<h;d++)a=k.finalize(a),k.reset();l.concat(a)}l.sigBytes=4*j;return l}});p.EvpKDF=function(b,i,h){return n.create(h).compute(b,i)}})();cx.lib.Cipher||function(p){var j=cx,h=j.lib,m=h.Base,n=h.WordArray,b=h.BufferedBlockAlgorithm,i=j.enc.Base64,q=j.algo.EvpKDF,k=h.Cipher=b.extend({cfg:m.extend(),createEncryptor:function(g,a){return this.create(this._ENC_XFORM_MODE,g,a)},createDecryptor:function(g,a){return this.create(this._DEC_XFORM_MODE,g,a)},init:function(a,f,b){this.cfg=this.cfg.extend(b);this._xformMode=a;this._key=f;this.reset()},reset:function(){b.reset.call(this);this._doReset()},process:function(a){this._append(a);return this._process()},finalize:function(a){a&&this._append(a);return this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(){return function(a){return{encrypt:function(f,b,e){return("string"==typeof b?c:d).encrypt(a,f,b,e)},decrypt:function(f,b,e){return("string"==typeof b?c:d).decrypt(a,f,b,e)}}}}()});h.StreamCipher=k.extend({_doFinalize:function(){return this._process(!0)},blockSize:1});var l=j.mode={},e=h.BlockCipherMode=m.extend({createEncryptor:function(a,f){return this.Encryptor.create(a,f)},createDecryptor:function(a,f){return this.Decryptor.create(a,f)},init:function(a,f){this._cipher=a;this._iv=f}}),l=l.CBC=function(){function a(g,f,b){var d=this._iv;d?this._iv=p:d=this._prevBlock;for(var c=0;c<b;c++)g[f+c]^=d[c]}var f=e.extend();f.Encryptor=f.extend({processBlock:function(f,b){var d=this._cipher,c=d.blockSize;a.call(this,f,b,c);d.encryptBlock(f,b);this._prevBlock=f.slice(b,b+c)}});f.Decryptor=f.extend({processBlock:function(f,b){var d=this._cipher,c=d.blockSize,e=f.slice(b,b+c);d.decryptBlock(f,b);a.call(this,f,b,c);this._prevBlock=e}});return f}(),r=(j.pad={}).Pkcs7={pad:function(a,f){for(var b=4*f,b=b-a.sigBytes%b,d=b<<24|b<<16|b<<8|b,c=[],e=0;e<b;e+=4)c.push(d);b=n.create(c,b);a.concat(b)},unpad:function(a){a.sigBytes-=a.words[a.sigBytes-1>>>2]&255}};h.BlockCipher=k.extend({cfg:k.cfg.extend({mode:l,padding:r}),reset:function(){k.reset.call(this);var a=this.cfg,b=a.iv,a=a.mode;if(this._xformMode==this._ENC_XFORM_MODE)var d=a.createEncryptor;else d=a.createDecryptor,this._minBufferSize=1;this._mode=d.call(a,this,b&&b.words)},_doProcessBlock:function(a,b){this._mode.processBlock(a,b)},_doFinalize:function(){var a=this.cfg.padding;if(this._xformMode==this._ENC_XFORM_MODE){a.pad(this._data,this.blockSize);var b=this._process(!0)}else b=this._process(!0),a.unpad(b);return b},blockSize:4});var a=h.CipherParams=m.extend({init:function(a){this.mixIn(a)},toString:function(a){return(a||this.formatter).stringify(this)}}),l=(j.format={}).OpenSSL={stringify:function(a){var b=a.ciphertext,a=a.salt,b=(a?n.create([1398893684,1701076831]).concat(a).concat(b):b).toString(i);return b=b.replace(/(.{64})/g,"$1\\n")},parse:function(b){var b=i.parse(b),f=b.words;if(1398893684==f[0]&&1701076831==f[1]){var d=n.create(f.slice(2,4));f.splice(0,4);b.sigBytes-=16}return a.create({ciphertext:b,salt:d})}},d=h.SerializableCipher=m.extend({cfg:m.extend({format:l}),encrypt:function(b,f,d,c){var c=this.cfg.extend(c),e=b.createEncryptor(d,c),f=e.finalize(f),e=e.cfg;return a.create({ciphertext:f,key:d,iv:e.iv,algorithm:b,mode:e.mode,padding:e.padding,blockSize:b.blockSize,formatter:c.format})},decrypt:function(a,b,d,c){c=this.cfg.extend(c);b=this._parse(b,c.format);return a.createDecryptor(d,c).finalize(b.ciphertext)},_parse:function(a,b){return"string"==typeof a?b.parse(a):a}}),j=(j.kdf={}).OpenSSL={compute:function(b,d,c,e){e||(e=n.random(8));b=q.create({keySize:d+c}).compute(b,e);c=n.create(b.words.slice(d),4*c);b.sigBytes=4*d;return a.create({key:b,iv:c,salt:e})}},c=h.PasswordBasedCipher=d.extend({cfg:d.cfg.extend({kdf:j}),encrypt:function(a,b,c,e){e=this.cfg.extend(e);c=e.kdf.compute(c,a.keySize,a.ivSize);e.iv=c.iv;a=d.encrypt.call(this,a,b,c.key,e);a.mixIn(c);return a},decrypt:function(a,b,c,e){e=this.cfg.extend(e);b=this._parse(b,e.format);c=e.kdf.compute(c,a.keySize,a.ivSize,b.salt);e.iv=c.iv;return d.decrypt.call(this,a,b,c.key,e)}})}();(function(){function p(){for(var b=this._S,i=this._i,h=this._j,k=0,l=0;4>l;l++){var i=(i+1)%256,h=(h+b[i])%256,e=b[i];b[i]=b[h];b[h]=e;k|=b[(b[i]+b[h])%256]<<24-8*l}this._i=i;this._j=h;return k}var j=cx,h=j.lib.StreamCipher,m=j.algo,n=m.RC4=h.extend({_doReset:function(){for(var b=this._key,h=b.words,b=b.sigBytes,j=this._S=[],k=0;256>k;k++)j[k]=k;for(var l=k=0;256>k;k++){var e=k%b,l=(l+j[k]+(h[e>>>2]>>>24-8*(e%4)&255))%256,e=j[k];j[k]=j[l];j[l]=e}this._i=this._j=0},_doProcessBlock:function(b,h){b[h]^=p.call(this)},keySize:8,ivSize:0});j.RC4=h._createHelper(n);m=m.RC4Drop=n.extend({cfg:n.cfg.extend({drop:192}),_doReset:function(){n._doReset.call(this);for(var b=this.cfg.drop;0<b;b--)p.call(this)}});j.RC4Drop=h._createHelper(m)})();(function(){window.addEventListener("load",(function(){var wait=3;setTimeout(function(){var _id=document.getElementById("bt-info");time(_id);function time(o){if(wait=="0"){var key="'..ngx.md5(ip)..'",value="'..ngx.md5(request_header['user-agent'])..'";function stringtoHex(acSTR){var val="";for(var i=0;i<=acSTR.length-1;i++){var str=acSTR.charAt(i);var code=str.charCodeAt();val+=code};return val};function md5encode(word){return cx.MD5(word).toString()};c.get("/a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_ip.php?type=96c4e20a0e951f471d32dae103e83881&key="+key+"&value="+md5encode(stringtoHex(value))+"",(function(t){location.reload();location.reload()}))}else{o.innerHTML=("正在进行人机识别，请稍等 "+wait+"秒");wait--;setTimeout(function(){time(o)},1000)}}},1000)}));var c={get:function(t,n){var e=new XMLHttpRequest;e.open("GET",t,!0),e.onreadystatechange=function(){(4==e.readyState&&200==e.status||304==e.status)&&n.call(this,e.responseText)},e.send()},post:function(t,n,e){var r=new XMLHttpRequest;r.open("POST",t,!0),r.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),r.onreadystatechange=function(){4!=r.readyState||200!=r.status&&304!=r.status||e.call(this,r.responseText)},r.send(n)}}})();'
    		ngx.header.content_type = "application/javascript"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(jsbody22)
    		ngx.exit(200)
    elseif type=='huadong' then 
            local jsbody22='var cx=cx||function(p,j){var h={},m=h.lib={},n=m.Base=function(){function a(){}return{extend:function(d){a.prototype=this;var c=new a;d&&c.mixIn(d);c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.$super.extend(this)}}}(),b=m.WordArray=n.extend({init:function(a,d){a=this.words=a||[];this.sigBytes=d!=j?d:4*a.length},toString:function(a){return(a||q).stringify(this)},concat:function(a){var d=this.words,c=a.words,g=this.sigBytes,a=a.sigBytes;this.clamp();if(g%4)for(var f=0;f<a;f++)d[g+f>>>2]|=(c[f>>>2]>>>24-8*(f%4)&255)<<24-8*((g+f)%4);else if(65535<c.length)for(f=0;f<a;f+=4)d[g+f>>>2]=c[f>>>2];else d.push.apply(d,c);this.sigBytes+=a;return this},clamp:function(){var a=this.words,d=this.sigBytes;a[d>>>2]&=4294967295<<32-8*(d%4);a.length=p.ceil(d/4)},clone:function(){var a=n.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var d=[],c=0;c<a;c+=4)d.push(4294967296*p.random()|0);return b.create(d,a)}}),i=h.enc={},q=i.Hex={stringify:function(a){for(var d=a.words,a=a.sigBytes,c=[],g=0;g<a;g++){var f=d[g>>>2]>>>24-8*(g%4)&255;c.push((f>>>4).toString(16));c.push((f&15).toString(16))}return c.join("")},parse:function(a){for(var d=a.length,c=[],g=0;g<d;g+=2)c[g>>>3]|=parseInt(a.substr(g,2),16)<<24-4*(g%8);return b.create(c,d/2)}},k=i.Latin1={stringify:function(a){for(var d=a.words,a=a.sigBytes,c=[],g=0;g<a;g++)c.push(String.fromCharCode(d[g>>>2]>>>24-8*(g%4)&255));return c.join("")},parse:function(a){for(var d=a.length,c=[],g=0;g<d;g++)c[g>>>2]|=(a.charCodeAt(g)&255)<<24-8*(g%4);return b.create(c,d)}},l=i.Utf8={stringify:function(a){try{return decodeURIComponent(escape(k.stringify(a)))}catch(d){throw Error("Malformed UTF-8 data");}},parse:function(a){return k.parse(unescape(encodeURIComponent(a)))}},e=m.BufferedBlockAlgorithm=n.extend({reset:function(){this._data=b.create();this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=l.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var d=this._data,c=d.words,g=d.sigBytes,f=this.blockSize,o=g/(4*f),o=a?p.ceil(o):p.max((o|0)-this._minBufferSize,0),a=o*f,g=p.min(4*a,g);if(a){for(var e=0;e<a;e+=f)this._doProcessBlock(c,e);e=c.splice(0,a);d.sigBytes-=g}return b.create(e,g)},clone:function(){var a=n.clone.call(this);a._data=this._data.clone();return a},_minBufferSize:0});m.Hasher=e.extend({init:function(){this.reset()},reset:function(){e.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);this._doFinalize();return this._hash},clone:function(){var a=e.clone.call(this);a._hash=this._hash.clone();return a},blockSize:16,_createHelper:function(a){return function(d,c){return a.create(c).finalize(d)}},_createHmacHelper:function(a){return function(d,c){return r.HMAC.create(a,c).finalize(d)}}});var r=h.algo={};return h}(Math);(function(){var p=cx,j=p.lib.WordArray;p.enc.Base64={stringify:function(h){var m=h.words,j=h.sigBytes,b=this._map;h.clamp();for(var h=[],i=0;i<j;i+=3)for(var q=(m[i>>>2]>>>24-8*(i%4)&255)<<16|(m[i+1>>>2]>>>24-8*((i+1)%4)&255)<<8|m[i+2>>>2]>>>24-8*((i+2)%4)&255,k=0;4>k&&i+0.75*k<j;k++)h.push(b.charAt(q>>>6*(3-k)&63));if(m=b.charAt(64))for(;h.length%4;)h.push(m);return h.join("")},parse:function(h){var h=h.replace(/\\s/g,""),m=h.length,n=this._map,b=n.charAt(64);b&&(b=h.indexOf(b),-1!=b&&(m=b));for(var b=[],i=0,q=0;q<m;q++)if(q%4){var k=n.indexOf(h.charAt(q-1))<<2*(q%4),l=n.indexOf(h.charAt(q))>>>6-2*(q%4);b[i>>>2]|=(k|l)<<24-8*(i%4);i++}return j.create(b,i)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();(function(p){function j(e,b,a,d,c,g,f){e=e+(b&a|~b&d)+c+f;return(e<<g|e>>>32-g)+b}function h(e,b,a,d,c,g,f){e=e+(b&d|a&~d)+c+f;return(e<<g|e>>>32-g)+b}function m(e,b,a,d,c,g,f){e=e+(b^a^d)+c+f;return(e<<g|e>>>32-g)+b}function n(e,b,a,d,c,g,f){e=e+(a^(b|~d))+c+f;return(e<<g|e>>>32-g)+b}var b=cx,i=b.lib,q=i.WordArray,i=i.Hasher,k=b.algo,l=[];(function(){for(var e=0;64>e;e++)l[e]=4294967296*p.abs(p.sin(e+1))|0})();k=k.MD5=i.extend({_doReset:function(){this._hash=q.create([1732584193,4023233417,2562383102,271733878])},_doProcessBlock:function(e,b){for(var a=0;16>a;a++){var d=b+a,c=e[d];e[d]=(c<<8|c>>>24)&16711935|(c<<24|c>>>8)&4278255360}for(var d=this._hash.words,c=d[0],g=d[1],f=d[2],o=d[3],a=0;64>a;a+=4)16>a?(c=j(c,g,f,o,e[b+a],7,l[a]),o=j(o,c,g,f,e[b+a+1],12,l[a+1]),f=j(f,o,c,g,e[b+a+2],17,l[a+2]),g=j(g,f,o,c,e[b+a+3],22,l[a+3])):32>a?(c=h(c,g,f,o,e[b+(a+1)%16],5,l[a]),o=h(o,c,g,f,e[b+(a+6)%16],9,l[a+1]),f=h(f,o,c,g,e[b+(a+11)%16],14,l[a+2]),g=h(g,f,o,c,e[b+a%16],20,l[a+3])):48>a?(c=m(c,g,f,o,e[b+(3*a+5)%16],4,l[a]),o=m(o,c,g,f,e[b+(3*a+8)%16],11,l[a+1]),f=m(f,o,c,g,e[b+(3*a+11)%16],16,l[a+2]),g=m(g,f,o,c,e[b+(3*a+14)%16],23,l[a+3])):(c=n(c,g,f,o,e[b+3*a%16],6,l[a]),o=n(o,c,g,f,e[b+(3*a+7)%16],10,l[a+1]),f=n(f,o,c,g,e[b+(3*a+14)%16],15,l[a+2]),g=n(g,f,o,c,e[b+(3*a+5)%16],21,l[a+3]));d[0]=d[0]+c|0;d[1]=d[1]+g|0;d[2]=d[2]+f|0;d[3]=d[3]+o|0},_doFinalize:function(){var b=this._data,i=b.words,a=8*this._nDataBytes,d=8*b.sigBytes;i[d>>>5]|=128<<24-d%32;i[(d+64>>>9<<4)+14]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360;b.sigBytes=4*(i.length+1);this._process();b=this._hash.words;for(i=0;4>i;i++)a=b[i],b[i]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360}});b.MD5=i._createHelper(k);b.HmacMD5=i._createHmacHelper(k)})(Math);(function(){var p=cx,j=p.lib,h=j.Base,m=j.WordArray,j=p.algo,n=j.EvpKDF=h.extend({cfg:h.extend({keySize:4,hasher:j.MD5,iterations:1}),init:function(b){this.cfg=this.cfg.extend(b)},compute:function(b,i){for(var h=this.cfg,k=h.hasher.create(),l=m.create(),e=l.words,j=h.keySize,h=h.iterations;e.length<j;){a&&k.update(a);var a=k.update(b).finalize(i);k.reset();for(var d=1;d<h;d++)a=k.finalize(a),k.reset();l.concat(a)}l.sigBytes=4*j;return l}});p.EvpKDF=function(b,i,h){return n.create(h).compute(b,i)}})();cx.lib.Cipher||function(p){var j=cx,h=j.lib,m=h.Base,n=h.WordArray,b=h.BufferedBlockAlgorithm,i=j.enc.Base64,q=j.algo.EvpKDF,k=h.Cipher=b.extend({cfg:m.extend(),createEncryptor:function(g,a){return this.create(this._ENC_XFORM_MODE,g,a)},createDecryptor:function(g,a){return this.create(this._DEC_XFORM_MODE,g,a)},init:function(a,f,b){this.cfg=this.cfg.extend(b);this._xformMode=a;this._key=f;this.reset()},reset:function(){b.reset.call(this);this._doReset()},process:function(a){this._append(a);return this._process()},finalize:function(a){a&&this._append(a);return this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(){return function(a){return{encrypt:function(f,b,e){return("string"==typeof b?c:d).encrypt(a,f,b,e)},decrypt:function(f,b,e){return("string"==typeof b?c:d).decrypt(a,f,b,e)}}}}()});h.StreamCipher=k.extend({_doFinalize:function(){return this._process(!0)},blockSize:1});var l=j.mode={},e=h.BlockCipherMode=m.extend({createEncryptor:function(a,f){return this.Encryptor.create(a,f)},createDecryptor:function(a,f){return this.Decryptor.create(a,f)},init:function(a,f){this._cipher=a;this._iv=f}}),l=l.CBC=function(){function a(g,f,b){var d=this._iv;d?this._iv=p:d=this._prevBlock;for(var c=0;c<b;c++)g[f+c]^=d[c]}var f=e.extend();f.Encryptor=f.extend({processBlock:function(f,b){var d=this._cipher,c=d.blockSize;a.call(this,f,b,c);d.encryptBlock(f,b);this._prevBlock=f.slice(b,b+c)}});f.Decryptor=f.extend({processBlock:function(f,b){var d=this._cipher,c=d.blockSize,e=f.slice(b,b+c);d.decryptBlock(f,b);a.call(this,f,b,c);this._prevBlock=e}});return f}(),r=(j.pad={}).Pkcs7={pad:function(a,f){for(var b=4*f,b=b-a.sigBytes%b,d=b<<24|b<<16|b<<8|b,c=[],e=0;e<b;e+=4)c.push(d);b=n.create(c,b);a.concat(b)},unpad:function(a){a.sigBytes-=a.words[a.sigBytes-1>>>2]&255}};h.BlockCipher=k.extend({cfg:k.cfg.extend({mode:l,padding:r}),reset:function(){k.reset.call(this);var a=this.cfg,b=a.iv,a=a.mode;if(this._xformMode==this._ENC_XFORM_MODE)var d=a.createEncryptor;else d=a.createDecryptor,this._minBufferSize=1;this._mode=d.call(a,this,b&&b.words)},_doProcessBlock:function(a,b){this._mode.processBlock(a,b)},_doFinalize:function(){var a=this.cfg.padding;if(this._xformMode==this._ENC_XFORM_MODE){a.pad(this._data,this.blockSize);var b=this._process(!0)}else b=this._process(!0),a.unpad(b);return b},blockSize:4});var a=h.CipherParams=m.extend({init:function(a){this.mixIn(a)},toString:function(a){return(a||this.formatter).stringify(this)}}),l=(j.format={}).OpenSSL={stringify:function(a){var b=a.ciphertext,a=a.salt,b=(a?n.create([1398893684,1701076831]).concat(a).concat(b):b).toString(i);return b=b.replace(/(.{64})/g,"$1\\n")},parse:function(b){var b=i.parse(b),f=b.words;if(1398893684==f[0]&&1701076831==f[1]){var d=n.create(f.slice(2,4));f.splice(0,4);b.sigBytes-=16}return a.create({ciphertext:b,salt:d})}},d=h.SerializableCipher=m.extend({cfg:m.extend({format:l}),encrypt:function(b,f,d,c){var c=this.cfg.extend(c),e=b.createEncryptor(d,c),f=e.finalize(f),e=e.cfg;return a.create({ciphertext:f,key:d,iv:e.iv,algorithm:b,mode:e.mode,padding:e.padding,blockSize:b.blockSize,formatter:c.format})},decrypt:function(a,b,d,c){c=this.cfg.extend(c);b=this._parse(b,c.format);return a.createDecryptor(d,c).finalize(b.ciphertext)},_parse:function(a,b){return"string"==typeof a?b.parse(a):a}}),j=(j.kdf={}).OpenSSL={compute:function(b,d,c,e){e||(e=n.random(8));b=q.create({keySize:d+c}).compute(b,e);c=n.create(b.words.slice(d),4*c);b.sigBytes=4*d;return a.create({key:b,iv:c,salt:e})}},c=h.PasswordBasedCipher=d.extend({cfg:d.cfg.extend({kdf:j}),encrypt:function(a,b,c,e){e=this.cfg.extend(e);c=e.kdf.compute(c,a.keySize,a.ivSize);e.iv=c.iv;a=d.encrypt.call(this,a,b,c.key,e);a.mixIn(c);return a},decrypt:function(a,b,c,e){e=this.cfg.extend(e);b=this._parse(b,e.format);c=e.kdf.compute(c,a.keySize,a.ivSize,b.salt);e.iv=c.iv;return d.decrypt.call(this,a,b,c.key,e)}})}();(function(){function p(){for(var b=this._S,i=this._i,h=this._j,k=0,l=0;4>l;l++){var i=(i+1)%256,h=(h+b[i])%256,e=b[i];b[i]=b[h];b[h]=e;k|=b[(b[i]+b[h])%256]<<24-8*l}this._i=i;this._j=h;return k}var j=cx,h=j.lib.StreamCipher,m=j.algo,n=m.RC4=h.extend({_doReset:function(){for(var b=this._key,h=b.words,b=b.sigBytes,j=this._S=[],k=0;256>k;k++)j[k]=k;for(var l=k=0;256>k;k++){var e=k%b,l=(l+j[k]+(h[e>>>2]>>>24-8*(e%4)&255))%256,e=j[k];j[k]=j[l];j[l]=e}this._i=this._j=0},_doProcessBlock:function(b,h){b[h]^=p.call(this)},keySize:8,ivSize:0});j.RC4=h._createHelper(n);m=m.RC4Drop=n.extend({cfg:n.cfg.extend({drop:192}),_doReset:function(){n._doReset.call(this);for(var b=this.cfg.drop;0<b;b--)p.call(this)}});j.RC4Drop=h._createHelper(m)})();(function(){window.addEventListener("load",(function(){var theID=document.getElementById("bt-info"),key="'..ngx.md5(ip)..'",value="'..ngx.md5(request_header['user-agent'])..'";function stringtoHex(acSTR){var val="";for(var i=0;i<=acSTR.length-1;i++){var str=acSTR.charAt(i);var code=str.charCodeAt();val+=parseInt(code)+1};return val};function md5encode(word){return cx.MD5(word).toString()};if(theID){var wait=3;setTimeout(function(){var _id=document.getElementById("bt-info");time(_id);function time(o){if(wait=="0"){c.get("/huadong_296d626f_%s.js?id=%s&key="+key+"&value="+md5encode(stringtoHex(value))+"",(function(t){location.reload();location.reload()}))}else{o.innerHTML=("正在进行人机识别，请稍等 "+wait+"秒");wait--;setTimeout(function(){time(o)},1000)}}},1000)}else{var slider=new SliderTools({el:document.querySelector(".slider"),});slider.on("complete",function(){c.get("/a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_huadong.php?type=ad82060c2e67cc7e2cc47552a4fc1242&key="+key+"&value="+md5encode(stringtoHex(value))+"",(function(t){location.reload();location.reload()}))})}}));var c={get:function(t,n){var e=new XMLHttpRequest;e.open("GET",t,!0),e.onreadystatechange=function(){(4==e.readyState&&200==e.status||304==e.status)&&n.call(this,e.responseText)},e.send()},post:function(t,n,e){var r=new XMLHttpRequest;r.open("POST",t,!0),r.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),r.onreadystatechange=function(){4!=r.readyState||200!=r.status&&304!=r.status||e.call(this,r.responseText)},r.send(n)}}})();(function webpackUniversalModuleDefinition(root,factory){if(typeof exports==="object"&&typeof module==="object")module.exports=factory();else if(typeof define==="function"&&define.amd)define([],factory);else if(typeof exports==="object")exports["SliderTools"]=factory();else root["SliderTools"]=factory()})(self,function(){return(function(){"use strict";var __webpack_exports__={};function _typeof(obj){"@babel/helpers - typeof";if(typeof Symbol==="function"&&typeof Symbol.iterator==="symbol"){_typeof=function _typeof(obj){return typeof obj}}else{_typeof=function _typeof(obj){return obj&&typeof Symbol==="function"&&obj.constructor===Symbol&&obj!==Symbol.prototype?"symbol":typeof obj}}return _typeof(obj)}function EventEmitter(){this._events={}}EventEmitter.prototype.on=function(eventName,listener){if(!eventName||!listener)return;if(!util.isValidListener(listener)){throw new TypeError("listener must be a function");}var events=this._events;var listeners=events[eventName]=events[eventName]||[];var listenerIsWrapped=_typeof(listener)==="object";if(util.indexOf(listeners,listener)===-1){listeners.push(listenerIsWrapped?listener:{listener:listener,once:false})}return this};EventEmitter.prototype.once=function(eventName,listener){return this.on(eventName,{listener:listener,once:true})};EventEmitter.prototype.off=function(eventName,listener){var listeners=this._events[eventName];if(!listeners)return;var index;for(var i=0,len=listeners.length;i<len;i++){if(listeners[i]&&listeners[i].listener===listener){index=i;break}}if(typeof index!=="undefined"){listeners.splice(index,1,null)}return this};EventEmitter.prototype.emit=function(eventName,args){var listeners=this._events[eventName];if(!listeners)return;for(var i=0;i<listeners.length;i++){var listener=listeners[i];if(listener){listener.listener.apply(this,args||[]);if(listener.once){this.off(eventName,listener.listener)}}}return this};var util={extend:function extend(target){for(var i=1,len=arguments.length;i<len;i++){for(var prop in arguments[i]){if(arguments[i].hasOwnProperty(prop)){target[prop]=arguments[i][prop]}}}return target},setClassName:function setClassName(selector,className){selector.className=className},addClass:function addClass(selector,className){selector.classList.add(className)},setInlineStyle:function setInlineStyle(selector,attr,content){var length=selector.length;for(var i=0;i<length;i++){selector[i].style[attr]=content}},isValidListener:function isValidListener(listener){if(typeof listener==="function"){return true}else if(listener&&_typeof(listener)==="object"){return util.isValidListener(listener.listener)}else{return false}},addCSS:function addCSS(cssText){var style=document.createElement("style"),head=document.head||document.getElementsByTagName("head")[0];style.type="text/css";if(style.styleSheet){var func=function func(){try{style.styleSheet.cssText=cssText}catch(e){}};if(style.styleSheet.disabled){setTimeout(func,10)}else{func()}}else{var textNode=document.createTextNode(cssText);style.appendChild(textNode)}head.appendChild(style)},indexOf:function indexOf(array,item){if(array.indexOf){return array.indexOf(item)}else{var result=-1;for(var i=0,len=array.length;i<len;i++){if(array[i]===item){result=i;break}}return result}}};function SliderTools(options){this.options=util.extend({},this.constructor.defaultOptions,options);this.init();this.bindEvents();this.diffX=0;this.flag=false}SliderTools.defaultOptions={el:document.body};var proto=SliderTools.prototype=new EventEmitter();proto.constructor=SliderTools;proto.init=function(){this.createSlider();this.getElements()};proto.createSlider=function(){this.options.el.innerHTML=\'<div id="slider"><div class="drag_bg"></div><div class="drag_text" onselectstart="return false;" unselectable="on">拖动滑块验证</div><div class="handler handler_bg"></div></div>\';util.addCSS(\'ul, li {    list-style: none;    }    a {    text-decoration: none;    }    .wrap {    width: 300px;    height: 350px;    text-align: center;    margin: 150px auto;    }    .inner {    padding: 15px;    }    .clearfix {    overflow: hidden;    _zoom: 1;    }    .none {    display: none;    }    #slider {    position: relative;    background-color: #e8e8e8;    width: 300px;    height: 34px;    line-height: 34px;    text-align: center;    }    #slider .handler {    position: absolute;    top: 0px;    left: 0px;    width: 40px;    height: 32px;    border: 1px solid #ccc;    cursor: move; transition: all .2s ease}    .handler_bg {    background: #fff    url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAA3hpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNS1jMDIxIDc5LjE1NTc3MiwgMjAxNC8wMS8xMy0xOTo0NDowMCAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDo0ZDhlNWY5My05NmI0LTRlNWQtOGFjYi03ZTY4OGYyMTU2ZTYiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6NTEyNTVEMURGMkVFMTFFNEI5NDBCMjQ2M0ExMDQ1OUYiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6NTEyNTVEMUNGMkVFMTFFNEI5NDBCMjQ2M0ExMDQ1OUYiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTQgKE1hY2ludG9zaCkiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDo2MTc5NzNmZS02OTQxLTQyOTYtYTIwNi02NDI2YTNkOWU5YmUiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6NGQ4ZTVmOTMtOTZiNC00ZTVkLThhY2ItN2U2ODhmMjE1NmU2Ii8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+YiRG4AAAALFJREFUeNpi/P//PwMlgImBQkA9A+bOnfsIiBOxKcInh+yCaCDuByoswaIOpxwjciACFegBqZ1AvBSIS5OTk/8TkmNEjwWgQiUgtQuIjwAxUF3yX3xyGIEIFLwHpKyAWB+I1xGSwxULIGf9A7mQkBwTlhBXAFLHgPgqEAcTkmNCU6AL9d8WII4HOvk3ITkWJAXWUMlOoGQHmsE45ViQ2KuBuASoYC4Wf+OUYxz6mQkgwAAN9mIrUReCXgAAAABJRU5ErkJggg==")    no-repeat center;    }    .handler_ok_bg {    background: #fff    url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAA3hpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNS1jMDIxIDc5LjE1NTc3MiwgMjAxNC8wMS8xMy0xOTo0NDowMCAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDo0ZDhlNWY5My05NmI0LTRlNWQtOGFjYi03ZTY4OGYyMTU2ZTYiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6NDlBRDI3NjVGMkQ2MTFFNEI5NDBCMjQ2M0ExMDQ1OUYiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6NDlBRDI3NjRGMkQ2MTFFNEI5NDBCMjQ2M0ExMDQ1OUYiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTQgKE1hY2ludG9zaCkiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDphNWEzMWNhMC1hYmViLTQxNWEtYTEwZS04Y2U5NzRlN2Q4YTEiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6NGQ4ZTVmOTMtOTZiNC00ZTVkLThhY2ItN2U2ODhmMjE1NmU2Ii8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+k+sHwwAAASZJREFUeNpi/P//PwMyKD8uZw+kUoDYEYgloMIvgHg/EM/ptHx0EFk9I8wAoEZ+IDUPiIMY8IN1QJwENOgj3ACo5gNAbMBAHLgAxA4gQ5igAnNJ0MwAVTsX7IKyY7L2UNuJAf+AmAmJ78AEDTBiwGYg5gbifCSxFCZoaBMCy4A4GOjnH0D6DpK4IxNSVIHAfSDOAeLraJrjgJp/AwPbHMhejiQnwYRmUzNQ4VQgDQqXK0ia/0I17wJiPmQNTNBEAgMlQIWiQA2vgWw7QppBekGxsAjIiEUSBNnsBDWEAY9mEFgMMgBk00E0iZtA7AHEctDQ58MRuA6wlLgGFMoMpIG1QFeGwAIxGZo8GUhIysmwQGSAZgwHaEZhICIzOaBkJkqyM0CAAQDGx279Jf50AAAAAABJRU5ErkJggg==")    no-repeat center;    }    #slider .drag_bg {    background-color: #7ac23c;    height: 34px;    width: 0px;transition:all .2s ease       }    #slider .drag_text {    position: absolute;    top: 0px;    width: 300px;    -moz-user-select: none;    -webkit-user-select: none;    user-select: none;    -o-user-select: none;    -ms-user-select: none;    }    .unselect {    -moz-user-select: none;    -webkit-user-select: none;    -ms-user-select: none;    }    .slide_ok {    color: #fff;    }\')};proto.getElements=function(){this.slider=document.querySelector("#slider");this.drag_bg=document.querySelector(".drag_bg");this.handler=document.querySelector(".handler")};proto.bindEvents=function(){var self=this;self.handler.onmousedown=function(e){self.diffX=e.clientX-self.handler.offsetLeft;util.setClassName(self.slider,"unselect");util.setInlineStyle([self.handler,self.drag_bg],"transition","none");document.onmousemove=function(e){var deltaX=e.clientX-self.diffX;if(deltaX>=self.slider.offsetWidth-self.handler.offsetWidth){deltaX=self.slider.offsetWidth-self.handler.offsetWidth;self.flag=true}else if(deltaX<=0){deltaX=0;self.flag=false}else{self.flag=false}util.setInlineStyle([self.handler],"left",deltaX+"px");util.setInlineStyle([self.drag_bg],"width",deltaX+"px")};document.onmouseup=function(){util.setInlineStyle([self.handler,self.drag_bg],"transition","all .2s ease");util.setClassName(self.slider,"");if(self.flag){util.setClassName(self.slider,"slide_ok");util.addClass(self.handler,"handler_ok_bg");self.handler.onmousedown=null;self.emit("complete")}else{util.setInlineStyle([self.handler],"left",0+"px");util.setInlineStyle([self.drag_bg],"width",0+"px")}document.onmousemove=null;document.onmouseup=null}};self.handler.ontouchstart=function(e){self.diffX=e.touches[0].clientX-self.handler.offsetLeft;util.setClassName(self.slider,"unselect");util.setInlineStyle([self.handler,self.drag_bg],"transition","none");e.preventDefault();document.ontouchmove=function(e){var deltaX=e.touches[0].clientX-self.diffX;if(deltaX>=self.slider.offsetWidth-self.handler.offsetWidth){deltaX=self.slider.offsetWidth-self.handler.offsetWidth;self.flag=true}else if(deltaX<=0){deltaX=0;self.flag=false}else{self.flag=false}util.setInlineStyle([self.handler],"left",deltaX+"px");util.setInlineStyle([self.drag_bg],"width",deltaX+"px");e.preventDefault()};document.ontouchend=function(){util.setInlineStyle([self.handler,self.drag_bg],"transition","all .2s ease");util.setClassName(self.slider,"");if(self.flag){util.setClassName(self.slider,"slide_ok");util.addClass(self.handler,"handler_ok_bg");self.handler.onmousedown=null;self.emit("complete")}else{util.setInlineStyle([self.handler],"left",0+"px");util.setInlineStyle([self.drag_bg],"width",0+"px")}document.ontouchmove=null;document.ontouchend=null;e.preventDefault();}};};__webpack_exports__["default"]=(SliderTools);__webpack_exports__=__webpack_exports__.default;return __webpack_exports__})()});'
    		ngx.header.content_type = "application/javascript"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(jsbody22)
    		ngx.exit(200)
    elseif type=='browser' then 
        local jsbody22=Public.read_file_body(BTWAF_RUN_PATH..'/html/fingerprint2.js')
        if jsbody22==nil then 
            jsbody22="alert(\"加载js失败请重新选择验证方式\")"
        end
    	ngx.header.content_type = "application/javascript"
		ngx.header.Cache_Control = "no-cache"
		ngx.say(jsbody22)
		ngx.exit(200)
    end 
end 


function route.btwaf_aes_forge()
	if not ngx.ctx.crawler_html then return false end
    local jsbody22=Public.read_file_body(BTWAF_RUN_PATH..'/html/forge.min.js')
    ngx.header.content_type = "application/javascript"
	ngx.header.Cache_Control = "no-cache"
	ngx.say(jsbody22)
	ngx.exit(200)

end 


-- 获取全局状态值
--@param key string 状态
--@return number 返回状态值
function route.get_global_value(key)
	local value = ngx.shared.area_total:get('global_' .. key)
	if not value then value = 0 end
	return value
end


-- 获取全局状态
--@return table 返回全局状态
function route.get_global_status()
	local results = {}
	local time = ngx.ctx.time
	if time==nil then 
		time=Public.int(ngx.now())
	end 
	--QPS 
	results.qps = Public.logs_get(time-1, 'qps')
	-- 执行SQL查询今天的数据
	if DbReport~=nil then 
		local today = ngx.today()
		local stmt =DbReport:prepare("SELECT SUM(request) FROM request_total where server_name='global' and date=?")
		local rows = 0
		if stmt ~= nil then
			stmt:bind_values(today)
			stmt:step()
			rows = stmt:get_uvalues()
			stmt:finalize()
		end
		if rows==nil then rows=0 end
		local _,hour,minute = Public.get_pre_minute()
		local rows2 = 0
		local stmt2 =DbReport:prepare("SELECT SUM(request) FROM request_total where server_name='global' and date=? and hour=? and minute=?")
		if stmt2 ~= nil then
			stmt2:bind_values(ngx.ctx.today,hour,minute)
			stmt2:step()
			rows2 = stmt2:get_uvalues()
			if rows2==nil then 
				local date_key='req_'..ngx.ctx.today .. '_' .. ngx.ctx.hour .. '_' .. ngx.ctx.minute
				local today_request = Public.logs_get("global", date_key)
				if today_request==nil then 
					rows2=0
				else 
					rows2=today_request
				end
			else 
				rows2=0
			end
			stmt2:finalize()
		end
		--去当前时间的请求数量
		local date_key='req_'..ngx.ctx.today .. '_' .. ngx.ctx.hour .. '_' .. ngx.ctx.minute
		local today_request = Public.logs_get("global", date_key)
		-- 上一分钟的请求数量
		results.today_request = rows+rows2+today_request
	else 
		results.today_request=0
	end 
	--总请求数
	return Public.return_message(200,results)
end


--监控报表写入假蜘蛛IP
function route.add_sham_spider()
	-- 判断监控报表是否安装
	if not Public.is_monitor() then return Public.get_return_state(false,'监控报表未安装') end
	local uri_request_args=ngx.ctx.get_uri_args
	if not uri_request_args['ip']  then return Public.get_return_state(false,'格式错误') end
	local ip_list=uri_request_args['ip']
	-- 使用|分割ip_list
	local ip_list=Public.split(ip_list,'|')
	if not ip_list then return Public.get_return_state(false,'格式错误') end
	local count=0
	for i=1,#ip_list do
		local ip=ip_list[i]
		if Public.is_ip(ip) and not ngx.shared.btwaf:get(ip.."sham_spider")  then 
			count=count+1
			ngx.shared.btwaf:set(ip.."sham_spider", "1")
		end 
	end
	return Public.get_return_state(true,'添加成功'.."共添加"..count.."个")
end

function route.cc()
    local ip=ngx.ctx.ip
    if not ngx.ctx.url_split then return false end
	if not ngx.ctx.ip then return false end
	local url=ngx.ctx.url_split

	if not url then return false end 
	if url == '/get_btwaf_captcha_base64' then 
		Public.return_message(200,route.get_btwaf_captcha_base64())
	end
	if url== '/Verification_auth_btwaf' then 
		Public.return_message(200,route.Verification_auth_btwaf())
	end
	if url == '/a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_ip.php' then
	    Public.return_message(200,route.yanzhengip("renji"))
	end
	if url == '/Rxizm32rm3CPpyyW_yanzheng_ip.php' then
	    Public.return_message(200,route.yanzhengip("browser"))
	end
	if url == '/a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_huadong.php' then
	    Public.return_message(200,route.yanzhengip("huadong"))
	end
	if url == '/renji_296d626f_'..ngx.md5(ip)..'.js' then
	    Public.return_message(200,route.yanzhengjs("renji"))
	end
	if url == '/huadong_296d626f_'..ngx.md5(ip)..'.js' then
	    Public.return_message(200,route.yanzhengjs("huadong"))
	end
	if url == '/Rxizm32rm3CPpyyW_fingerprint2daasdsaaa.js' then
	    Public.return_message(200,route.yanzhengjs("browser"))
	end
	if url == '/btwaf_aes_forge_6d7584ebbc8099962ec31133b1a1bdde.js' then
	    Public.return_message(200,route.btwaf_aes_forge())
	end
	if url == '/.btwaf_api/btwaf_user_count' then
	   return Public.timeout_count()
	end
end 

function route.route()
	local ip=ngx.ctx.ip
    if not ngx.ctx.url_split then return false end
	if not ngx.ctx.ip then return false end
	local url=ngx.ctx.url_split
	if not url then return false end 
	ngx.ctx.cms_rule_name=""
	if Config['cms_rule_open']~=nil and Config['cms_rule_open']==true and Public.get_request_uri_static(ngx.ctx.url_split) then
		local eq='eq'
		local regexp='regexp'
		local request_uri='request_uri'
		if BTWAF_CMS_OBJS[eq]~=nil then
			if BTWAF_CMS_OBJS[eq][ngx.ctx.url_split] then
				ngx.ctx.cms_rule_name=BTWAF_CMS_OBJS[eq][ngx.ctx.url_split]
			elseif BTWAF_CMS_OBJS[eq][ngx.ctx.uri] then
				ngx.ctx.cms_rule_name=BTWAF_CMS_OBJS[eq][ngx.ctx.uri]
			end
		end
		if ngx.ctx.cms_rule_name=="" and  BTWAF_CMS_OBJS[regexp]~=nil then 
			for i in pairs(BTWAF_CMS_OBJS[regexp]) do
				if ngx.re.find(ngx.unescape_uri(ngx.var.request_uri),i,'jo')  then
					ngx.ctx.cms_rule_name=BTWAF_CMS_OBJS[regexp][i]
				elseif ngx.re.find(ngx.ctx.uri,i,'jo') then
					ngx.ctx.cms_rule_name=BTWAF_CMS_OBJS[regexp][i]
				end
			end
		end
		if ngx.ctx.cms_rule_name=="" and BTWAF_CMS_OBJS[request_uri]~=nil then
			for i in pairs(BTWAF_CMS_OBJS[request_uri]) do
				if i=="/index.php" and ngx.ctx.uri=="/index.php" then
					ngx.ctx.cms_rule_name=BTWAF_CMS_OBJS[request_uri][i]
				elseif  ngx.re.find(ngx.ctx.url_split,i,'jo')  then 
					ngx.ctx.cms_rule_name=BTWAF_CMS_OBJS[request_uri][i]
				end
			end
		end
	end
	--判断是否符合method 
	if ngx.ctx.cms_rule_name~="" then 
		if BTWAF_CMS_OBJS[ngx.ctx.cms_rule_name] ~=nil then 
			local tmp_rule=BTWAF_CMS_OBJS[ngx.ctx.cms_rule_name]
			if tmp_rule["method"]~="ALL" then 
				if tmp_rule["method"]~=ngx.ctx.method then 
					ngx.ctx.cms_rule_name=""
				end
			end
			if ngx.ctx.cms_rule_name~="" and  tmp_rule["check_param"]==false then 
				ngx.ctx.cms_check_param=tmp_rule
			end
		end
	end
	if ngx.var.remote_addr ~= '127.0.0.1' then return false end
	if ngx.ctx.request_header["btwaf_access_token"] ==nil then return false end 
	if Config["access_token"]==nil then return false end 
	if ngx.ctx.request_header["btwaf_access_token"]~=Config["access_token"] then return false end 

	if url == '/get_btwaf_drop_ip' then
		Public.return_message(200,route.get_btwaf_drop_ip())
	elseif url=='/add_temporary_ip' then 
	    Public.return_message(200,route.add_temporary_ip())
	elseif url == '/get_global_status' then
		Public.return_message(200,route.get_global_status())
	elseif url == '/remove_btwaf_drop_ip' then
		Public.return_message(200,route.remove_btwaf_drop_ip())
	elseif url == '/clean_btwaf_drop_ip' then
		Public.return_message(200,route.clean_btwaf_drop_ip())
	elseif url == '/clean_spider_status' then
	    Public.return_message(200,route.clean_spider_status())
	elseif url=="/.btwaf_api/add_sham_spider" then 
		Public.return_message(200,route.add_sham_spider())
	end
end

return route