local error_info={}


function error_info.mysql_error(text)
    if ngx.re.match(text,"SQLSTATE\\[|Column count doesn't match|Column count doesn't match value count at row|supplied argument is not a valid MySQL|An illegal character has been found in the statement|You have an error in your SQL syntax;|You have an error in your SQL syntax near|MySQL server version for the right syntax to use|the used select statements have different number of columns|Syntax error in string in query expression|on MySQL result index|has occurred in the vicinity of:|Sintaxis incorrecta cerca de","ijo") then 
        if ngx.re.match(text, "MyS(?:QL server version for the right syntax to use|qlClient\\.)|(?:supplied argument is not a valid |SQL syntax.*)MySQL|Column count doesn't match(?: value count at row)?|(?:Table '[^']+' doesn't exis|valid MySQL resul)t|You have an error in your SQL syntax(?: near|;)|Warning.{1,10}mysql_(?:[a-z_()]{1,26})?|ERROR [0-9]{4} \\([a-z0-9]{5}\\):|mysql_fetch_array\\(\\)|on MySQL result index|\\[MySQL\\]\\[ODBC", "ijo") then
            return true
        end
    end
end

return error_info