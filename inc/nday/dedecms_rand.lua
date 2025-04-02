return {
    ["status"] = true,
    ["info"] = "dedecms_rand 后台代码执行漏洞",
    ["method"] = "POST",
    ["keys"] = {
        ["dopost"] = "save",
        ["templates"] = "$_BT_PHPCODE",
    }
}