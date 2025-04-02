return {
    ["status"] = true,
    ["info"] = "dede tpl.php后台代码执行漏洞",
    ["method"] = "",
    ["keys"] = {
        ["filename"] = "$_BT_REGEXP.php$",
        ["action"] = "savetagfile",
        ["content"] = "$_BT_PHPCODE",
        ["token"] = "$_BT_LEN32"
    }
}