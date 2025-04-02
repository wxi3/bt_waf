xss_engine={}
local BLACKATTREVENT = {}
BLACKATTREVENT["onbeforeunload"] = true
BLACKATTREVENT["onblur"] = true
BLACKATTREVENT["onerror"] = true
BLACKATTREVENT["onfocus"] = true
BLACKATTREVENT["onhashchange"] = true
BLACKATTREVENT["onload"] = true
BLACKATTREVENT["onmessage"] = true
BLACKATTREVENT["onpageshow"] = true
BLACKATTREVENT["onresize"] = true
BLACKATTREVENT["onchange"] = true
BLACKATTREVENT["onforminput"] = true
BLACKATTREVENT["onselect"] = true
BLACKATTREVENT["onsubmit"] = true
BLACKATTREVENT["onkeydown"] = true
BLACKATTREVENT["onkeypress"] = true
BLACKATTREVENT["onkeyup"] = true
BLACKATTREVENT["onclick"] = true
BLACKATTREVENT["ondblclick"] = true
BLACKATTREVENT["onmousedown"] = true
BLACKATTREVENT["onmousemove"] = true
BLACKATTREVENT["onmouseout"] = true
BLACKATTREVENT["onmouseover"] = true
BLACKATTREVENT["onmouseup"] = true
BLACKATTREVENT["ontoggle"] = true
BLACKATTREVENT["onfocusout"]=true
BLACKATTREVENT["onfocusin"]=true
BLACKATTREVENT["onscroll"]=true
BLACKATTREVENT["onmouseenter"]=true
BLACKATTREVENT["onmouseleave"]=true
BLACKATTREVENT["onmousewheel"]=true
BLACKATTREVENT["oncontextmenu"]=true
BLACKATTREVENT["oncopy"]=true
BLACKATTREVENT["oninput"]=true
BLACKATTREVENT["oninput"]=true
BLACKATTREVENT["onbegin"]=true
BLACKATTREVENT["onanimationstart"]=true
BLACKATTREVENT["onafterscriptexecute"]=true
BLACKATTREVENT["onanimationend"]=true
BLACKATTREVENT["onloadstart"]=true
BLACKATTREVENT["onbeforeprint"]=true
local html_parser=require("html_parser")


local voidelements={
	area = true,
	base = true,
	col = true,
	command = true,
	hr = true,
	img = true,
	input = true,
	keygen = true,
	link = true,
	meta = true,
	param = true,
	source = true,
	track = true,
	wbr = true,
	a=true,
	image=true,
	script=true,
	audio=true,
	video=true,
	object=true,
	svg=true,
	html=true,
	body=true,
	bgsound=true,
	style=true,
	frameset=true,
	applet=true,
	marquee=true,
	xml=true,
	div=true,
	button=true,
	embed=true,
	plaintext=true,
	var=true,
	input=true,
	iframe=true,
	details=true,
	select=true,
	isindex=true,
	form=true,
	textarea=true,
	bleh=true,
	animate=true,
	storeid=true,
	id=true,
}

local infoi_name={}
infoi_name["p"]=1
infoi_name["font"]=1
infoi_name["br"]=1
infoi_name["h1"]=1
infoi_name["h2"]=1
infoi_name["h3"]=1
infoi_name["h4"]=1
infoi_name["h5"]=1
infoi_name["h6"]=1
infoi_name["hr"]=1
infoi_name["head"]=1
infoi_name["em"]=1
infoi_name["s"]=1
infoi_name["tr"]=1
infoi_name["th"]=1
infoi_name["ol"]=1
infoi_name["ul"]=1
infoi_name["li"]=1
infoi_name["td"]=1
infoi_name["tr"]=1

local function de_decode(s)
    return (s:gsub("&#(%d+);", function(n) return string.char(n) end))
end

local htmlparser_opts=""
local htmlparser_looplimit=1000
local function rine(val)
	return (val and #val>0) and val
end
local function rit(a)
	return (type(a) == "table") and a
end
local noop = function() end
local esc = function(s) return string.gsub(s, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%" .. "%1") end
local str = tostring
local char = string.char
local opts = rit(htmlparser_opts) or {}
local prn = opts.silent and noop or function(l,f,...)
	local fd = (l=="i") and "stdout" or "stderr"
	local t = (" [%s] "):format(l:upper())
	io[fd]
		:write('[HTMLParser]'..t..f:format(...)
			..(opts.nonl or "\n")
		)
end
local err = opts.noerr and noop or function(f,...) prn("e",f,...) end
local out = opts.noout and noop or function(f,...) prn("i",f,...) end
local line = debug and function(lvl) return debug.getinfo(lvl or 2).currentline end or noop
local dbg = opts.debug and function(f,...) prn("d",f:gsub("#LINE#",str(line(3))),...) end or noop

local ElementNode = require"ElementNode"

local function parse(text,limit)
	local opts = rine(opts)
		or rit(htmlparser_opts)
		or {}
	opts.looplimit = opts.looplimit or htmlparser_looplimit

	local text = ngx.unescape_uri(ngx.unescape_uri(text))
	local limit = limit or opts.looplimit or 1000
	local tpl = false
	if not opts.keep_comments then
		text = text:gsub("<!%-%-.-%-%->","")
	end
	local tpr={}

	if not opts.keep_danger_placeholders then
		local busy,i={},0;
		repeat
			local cc = char(i)
			if not(text:match(cc)) then
				if not(tpr["<"]) or not(tpr[">"]) then
					if not(busy[i]) then
						if not(tpr["<"]) then 
							tpr["<"] = cc;
						elseif not(tpr[">"]) then
							tpr[">"] = cc;
						end
						busy[i] = true
					end
				else
					break
				end
			end
			local skip=1
			if i==31 then
				skip=96
			end
			i=i+skip
		until (i==255)
		i=nil

		if not(tpr["<"]) or not(tpr[">"]) then
		end
		local function g(id,...)
			local arg={...}
			local orig=arg[id]
			arg[id]=arg[id]:gsub("(.)",tpr)
			if arg[id] ~= orig then
				tpl=true
			end
			return table.concat(arg)
		end
		text=text
			:gsub(
				"(=[%s]-)"..
				"(%b'')",
				function(...)return g(2,...)end
			)
			:gsub(
				"(=[%s]-)"..
				'(%b"")',
				function(...)return g(2,...)end
			)
			:gsub(
				"(<"..
				(opts.tpl_skip_pattern or "[^!]")..
				")([^>]+)".. 
				"(>)",
				function(...)return g(2,...)end
			)
			:gsub(
				"("..
				(tpr["<"] or "__FAILED__")..
				")("..
				(opts.tpl_marker_pattern or "[^%w%s]")..
				")([%g%s]-)"..
				"(%2)(>)".. 
				"([^>]*>)",
				function(...)return g(5,...)end
			)
	end
	local index = 0
	local root = ElementNode:new(index, str(text))
	local node, descend, tpos, opentags = root, true, 1, {}
	while true do 
		local openstart, name
		if   root._text:find("<!ENTITY")  and root._text:find("SYSTEM") then 
		    if root._text:find("file://") then 
		        return true
		    end 
		    if root._text:find("http") then 
		        return true
		    end  
		end 
		
		openstart, tpos, name = root._text:find(
				"<" .. 
						"([%w-]+)" ..
						"[^>]*>",
				tpos)
		
		-- }}}
		if not name then 
		    break 
		end
		name=name:lower()
		-- Some more vars {{{
		index = index + 1
		local tag = ElementNode:new(index, str(name), (node or {}), descend, openstart, tpos)
		node = tag
		local tagst, apos = tag:gettext(), 1
        local tagloop
    	local info =[[((?<=[\'"\s/])[^\s/>][^\s/=>]*)(\s*=+\s*(\'[^\']*\'|"[^"]*"|(?![\'"])[^>\s]*))?(?:\s|/(?!>))*]]
        local header_data_check =ngx.re.gmatch(tagst,info)
        
        local ret={}
        while true do
            if tagloop == limit then -- {{{
				break
            end
    	    local m, err = header_data_check()
          	if m then 
          	    local k =m[1] or ""
          	    local v =m[3] or ""
          	    k=k:lower()
          	    v=v:lower()
          	    if BLACKATTREVENT[k] then
                    if v ~="" then
                        return true
                    end
          	    end
          	     if k=="values" or k=="src" or k=="href" or k=="action" or k=="xlink:href" or k=="values" or  k=="formaction" or k=="from" or  k=="data" and v  then
                    local tmp=string.gsub(v,'\n','')
                    tmp=string.gsub(tmp,'\r','')
                    tmp=de_decode(tmp)
					if ngx.re.find(tmp,"alert\\(","jo") then
						return true
				   	end 
					--判断是否存在&#x 这种编码
					if string.find(tmp,"&#x") then
						return true
					end
                    if string.find(tmp,"javascript") and tmp~='\\"javascript:;\\"' and tmp~="javascript:;" and tmp~='"javascript:;"' then
                        return true
                   end
				   if string.find(tmp,"file://") then 
						return true
				   end

                end 
				if name=="object" and k=="data"  and v then 
					if string.find(v,"base64") then
						return true
					end 
				end
					
                if name =="script" and k=="src" and v then 
                    return true
                end

                
                if name =="iframe" and k=="srcdoc" and v  then 
                    return true
                elseif name =="iframe" and k=="src" and v then 
                    if string.find(v,"html") and string.find(v,"text") then
                        return true
                    end 
                end
                if name=="meta" and k=="http-equiv" and v and string.find(v,"refresh") then 
                    return true
                end 
                
                if name=="embed" and k=="code" and v and string.find(v,"http") then 
                    return true
                end 
                if name=="use" and k=="href" and v and string.find(v,"base64") then 
                    return true
                end 
          	else
          		break
          	end 
          	tagloop = (tagloop or 0) + 1
        end
        if name=="script" then 
    		if  voidelements[tag.name:lower()]  then -- {{{
    			descend = false
    			tag:close()
    		else
    			descend = true
    			opentags[tag.name] = opentags[tag.name] or {}
    			if  infoi_name[tag.name]==nil then
    				table.insert(opentags[tag.name], tag)
    			else
    				if tag:length()>0 then
    					table.insert(opentags[tag.name], tag)
    				else
    					limit=limit+1
    				end
    			end
    		end
    		local closeend = tpos
    		local closingloop
    		while true do 
    			if closingloop == limit then
    				err("Tag closing loop reached loop limit (%d). Consider either increasing it or checking HTML-code for syntax errors", limit)
    				break
    			end
    			local closestart, closing, closename
    			closestart, closeend, closing, closename = root._text:find("[^<]*<(/?)([%w-]+)", closeend)
    			dbg("[TagCloseLoop]:#LINE# closestart=%s || closeend=%s || closing=%s || closename=%s",str(closestart),str(closeend),str(closing),str(closename))
    			if not closing or closing == "" then break end
    			tag = table.remove(opentags[closename] or {}) or tag -- kludges for the cases of closing void or non-opened tags
    			closestart = root._text:find("<", closestart)
    			dbg("[TagCloseLoop]:#LINE# closestart=%s",str(closestart))
    			tag:close(closestart, closeend + 1)
    			node = tag.parent
    			descend = true
    			closingloop = (closingloop or 0) + 1
    		end -- }}}
    		if tag:getcontent() ~="" then 
    		   if  #tag:getcontent()>=1 then 
    		       return true
    		    end 
    		end 
    	end
	end
	return false
end -- }}}

local function xss2(text)
    local ok,status_is = pcall(function()
	  return parse(text)
    end)
    if not ok then
	   return false
    end
   return status_is
end

local function xss(text)
	if #text<10 then return false end 
    if Public.os_file_exists("/dev/shm/xss_decode.sock") then 
        text=html_parser.unescape(text)
        local sock = ngx.socket.tcp()
        sock:settimeout(500)
        local ok, err = sock:connect("unix:/dev/shm/xss_decode.sock")
        if not ok then
            sock:close()
            return xss2(text)
        end
        local bytes, err = sock:send(text.."\n")
        if err~=nil then 
            sock:close()
            return xss2(text)
    
        end 
        
        local data, err, partial = sock:receive()
        if err then
            sock:close()
            return xss2(text)
        end
        
        sock:setkeepalive(60000, 100)
        local end_time = Public.getMilliseconds()
        if data=="100" or data==100 then return true end 
        return false 
    else
        return xss2(text)
    end 
end


local function parseXss(requires_data)
    local ok,status_is,key,value = pcall(function()
	    for k,v in pairs(requires_data) do
	        if #v>5 then
	            if parse(v) then 
	                return true,k,v
	            end 
	        end 
	    end
	    return false,"",""
    end)
     if not ok then
	    return false
     end
    return status_is,key,value
    
end
xss_engine.xss = xss
xss_engine.parseXss = parseXss
return xss_engine