return {
    ["status"] = true,
    ["info"] = "dedecms_add 后台代码执行漏洞",
    ["method"] = "POST",
    ["keys"] = {
        ["dopost"] = "save",
        ["normbody[htmlcode]"] = "$_BT_PHPCODE",
    }
}