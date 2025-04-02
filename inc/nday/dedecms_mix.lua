return {
    ["status"] = true,
    ["info"] = "dedecms_mix 后台代码执行漏洞",
    ["method"] = "POST",
    ["keys"] = {
        ["dopost"] = "save",
        ["allsource"] = "$_BT_PHPCODE",
    }
}