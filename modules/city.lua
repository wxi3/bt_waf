local city={}



--自定义拦截全球地区
function city.reg_tions()
    local overall_country=ngx.ctx.country
    if Public.count_sieze(BTWAF_RULES.reg_tions_rules)>=1 then
         if not overall_country then return false end 
         if  overall_country=="" then return false end 
         if overall_country=="内网地址" then return false end 
		 local province = ""
         if overall_country == "中国" then
            province = ngx.ctx.ip_province
            if province == "香港" or province == "澳门" or province == "台湾" then
                overall_country = province
            end
         end
         for _,v in ipairs(BTWAF_RULES.reg_tions_rules) do 
             if  v['open']~=nil and v['status']~=nil and v['open'] then 
                 if  v["site"]["allsite"]~=nil then 
                     if v["types"]=="refuse" then 
                         if v["region"]["海外"]~=nil then 
                             if overall_country~="中国" then 
                                ngx.var.waf2monitor_blocked="地区限制|".."禁止中国大陆以外"
                                Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到禁止中国大陆以外的地区访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                                Public.return_html(v["status"],BTWAF_RULES.city_html)
                             end 
                         elseif v["region"][overall_country]~=nil then
                             ngx.var.waf2monitor_blocked="地区限制|".."匹配到禁止【"..Public.city_join(v["region"]).."】访问"
                             Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到禁止【"..Public.city_join(v["region"]).."】访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                              Public.return_html(v["status"],BTWAF_RULES.city_html)
                         end
                     elseif v["types"]=="accept" then
                         if v["region"]["海外"]~=nil then
                             if overall_country=="中国" then 
                                 ngx.var.waf2monitor_blocked="地区限制|".."匹配到只允许"..Public.city_join(v["region"]).."访问"
                                 Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到只允许"..Public.city_join(v["region"]).."访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                                 Public.return_html(v["status"],BTWAF_RULES.city_html)
                             end 
                         elseif v["region"][overall_country]==nil then
                              ngx.var.waf2monitor_blocked="地区限制"
                              Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到只允许【"..Public.city_join(v["region"]).."】访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                              Public.return_html(v["status"],BTWAF_RULES.city_html)
                         end
                     end 
                 elseif v["site"][ngx.ctx.server_name]~=nil then
                     if v["types"]=="refuse" then 
                         if v["region"]["海外"]~=nil then 
                             if overall_country~="中国" then
                                 ngx.var.waf2monitor_blocked="地区限制|".."匹配到禁止中国大陆以外的地区访问"
                                Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到禁止中国大陆以外的地区访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                                Public.return_html(v["status"],BTWAF_RULES.city_html)
                             end 
                         elseif v["region"][overall_country]~=nil then
                             ngx.var.waf2monitor_blocked="地区限制|".."匹配到禁止【"..Public.city_join(v["region"]).."】访问"
                             Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到禁止【"..Public.city_join(v["region"]).."】访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                              Public.return_html(v["status"],BTWAF_RULES.city_html)
                         end 
                     elseif v["types"]=="accept" then 
                         if v["region"]["海外"]~=nil then
                             if overall_country=="中国" then 
                                 ngx.var.waf2monitor_blocked="地区限制|".."匹配到只允许"..Public.city_join(v["region"]).."访问"
                                 Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到只允许"..Public.city_join(v["region"]).."访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                                 Public.return_html(v["status"],BTWAF_RULES.city_html)
                             end 
                         elseif v["region"][overall_country]==nil then 
                              ngx.var.waf2monitor_blocked="地区限制|".."匹配到只允许【"..Public.city_join(v["region"]).."】访问"
                              Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到只允许【"..Public.city_join(v["region"]).."】访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                              Public.return_html(v["status"],BTWAF_RULES.city_html)
                         end
                     end 
                 end 
            end
         end 
    end 
    return false
 end 
 
 
 --自定义拦截国内的城市地区
 function city.reg_city()
    local overall_country=ngx.ctx.country
    
    local ip=ngx.ctx.ip
    if Public.count_sieze(BTWAF_RULES.reg_city_rules)>=1 then
         if not overall_country then return false end 
         if  overall_country=="" then return false end 
         if overall_country=="内网地址" then return false end 
        if ngx.ctx.ip_city==nil then  ngx.ctx.ip_city="" end 
        if ngx.ctx.ip_province==nil then ngx.ctx.ip_province="" end 
         local city =ngx.ctx.ip_city
         local p =ngx.ctx.ip_province
         for _,v in ipairs(BTWAF_RULES.reg_city_rules) do 
             if  v['open']~=nil and v['status']~=nil and v['open'] then 
                 if v["site"]["allsite"]~=nil then 
                     if v["types"]=="refuse" then 
                         if v["region"][city]~=nil or v["region"][p]~=nil then
                              ngx.var.waf2monitor_blocked="省市地区限制|".."匹配到禁止【"..Public.city_join(v["region"]).."】访问"
                              Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到禁止【"..Public.city_join(v["region"]).."】访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                              Public.return_html(v["status"],BTWAF_RULES.city_html)
                         end
                     elseif v["types"]=="accept" then
                         if v["region"][city]==nil and v["region"][p]==nil then
                              ngx.var.waf2monitor_blocked="省市地区限制|".."匹配到只允许【"..Public.city_join(v["region"]).."】访问"
                              Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到只允许【"..Public.city_join(v["region"]).."】访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                              Public.return_html(v["status"],BTWAF_RULES.city_html)
                         end
                     end 
                 elseif v["site"][ngx.ctx.server_name]~=nil then
                     if v["types"]=="refuse" then 
                         if v["region"][city]~=nil or v["region"][p]~=nil then
                             ngx.var.waf2monitor_blocked="省市地区限制|".."匹配到禁止【"..Public.city_join(v["region"]).."】访问"
                             Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到禁止【"..Public.city_join(v["region"]).."】访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                              Public.return_html(v["status"],BTWAF_RULES.city_html)
                         end
                     elseif v["types"]=="accept" then
                         if v["region"][city]==nil and v["region"][p]==nil then
                             ngx.var.waf2monitor_blocked="省市地区限制|".."匹配到只允许【"..Public.city_join(v["region"]).."】访问"
                              Public.log_rule_hit(1,"地区限制",ngx.ctx.time, "地区限制", "匹配到只允许【"..Public.city_join(v["region"]).."】访问".." IP为:"..ngx.ctx.ip, ngx.var.host, ngx.var.request_uri, ngx.ctx.ip)
                              Public.return_html(v["status"],BTWAF_RULES.city_html)
                         end
                     end 
                 end 
            end 
         end 
    end
    return false
 end 
 
return city