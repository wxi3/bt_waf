local readonly={}

-- 只读模式、限制很严格、非攻防演练期间不要开启
function readonly.readonly()
    if Site_config[ngx.ctx.server_name]==nil  then return false end
    if Site_config[ngx.ctx.server_name]['readonly']==nil then return false end 
    if Site_config[ngx.ctx.server_name]['readonly']['open']==nil then return false end 
    local readonly_open = Site_config[ngx.ctx.server_name]['readonly']['open']
    if not readonly_open then return false end
    --不允许非GET请求
    ngx.ctx.is_type="护网模式拦截"
    if ngx.ctx.method~="GET" then 
        IpInfo.write_log('sql','护网模式拦截、不允许出现GET以外的请求')
        Public.return_html(Config['get']['status'],BTWAF_RULES.get_html)
    end
    if Public.len(ngx.ctx.get_uri_args)==0 then return false end
    --get参数不能大于10 
    if Public.len(ngx.ctx.get_uri_args)>=10 then 
        IpInfo.write_log('sql','护网模式拦截、不允许get参数大于10')
        Public.return_html(Config['get']['status'],BTWAF_RULES.get_html)
    end
    --判断参数内容是否符合规则  参数内容只允许是数字和字母
    for k,v in pairs(ngx.ctx.get_uri_args) do 
        --只允许是数字和字母
        if v and #v>50 then 
            IpInfo.write_log('sql','护网模式拦截、参数内容大于50')
            Public.return_html(Config['get']['status'],BTWAF_RULES.get_html)
        end 
        if v and #v>5  and  not ngx.re.match(v,"^[A-Za-z0-9_\\-\\+\\* ]+$") then
            IpInfo.write_log('sql','护网模式拦截、参数内容只允许是数字和字母')
            Public.return_html(Config['get']['status'],BTWAF_RULES.get_html)
        end
    end
    --header头部信息总的不能大于20
    if Public.len(ngx.ctx.request_header)>=20 then 
        IpInfo.write_log('sql','护网模式拦截、header 长度不能大于20')
        Public.return_html(Config['get']['status'],BTWAF_RULES.get_html)
    end
    --ua长度不能小于5 大于200
    if string.len(ngx.ctx.ua)<=5 or string.len(ngx.ctx.ua)>=200 then 
        IpInfo.write_log('sql','护网模式拦截、ua长度不能大于200')
        Public.return_html(Config['get']['status'],BTWAF_RULES.get_html)
    end
    --Cookie 总长度不能大于500
    if Public.len(ngx.var.http_cookie)>=500 then 
        IpInfo.write_log('sql','护网模式拦截、cookie长度不允许大于500')
        Public.return_html(Config['get']['status'],BTWAF_RULES.get_html)
    end
    --其他的头部长度不能超过300
    for _,v in ipairs(ngx.ctx.request_header) do
        --判断头部的长度是否超过300
        if #v>=300 then 
        IpInfo.write_log('sql','护网模式拦截、header头部不允许大于300')
        Public.return_html(Config['get']['status'],BTWAF_RULES.get_html)
        end
    end
end

return readonly