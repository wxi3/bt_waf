return {
    ["status"] = true,
    ["info"] = "phpcms后台代码执行漏洞",
    ["method"] = "POST",
    ["keys"] = {
        ["bt_args_m"] = ""
    },
    ["matchs"] = {
        [1] = {
            ["bt_args_pc_hash"] = "",
            ["dosubmit"] = "",
            ["language"] = "",
            ["info[name]"] = ""
        },
        [2] = {
            ["bt_args_c"] = "block_admin",
            ["bt_args_a"] = "",
            ["template"] = "$_BT_PHPCODE"
        },
        [3] = {
            ["bt_args_c"] = "special",
            ["bt_args_a"] = "",
            ["special[banner]"] = "$_BT_PHPCODE",
            ["special[title]"] = "",
            ["special[filename]"] = ""
        },
        [4] = {
            ["bt_args_c"] = "special",
            ["bt_args_a"] = "",
            ["special[banner]"] = "",
            ["special[title]"] = "",
            ["special[filename]"] = "",
            ["special[description]"] = "$_BT_PHPCODE"
        }
    }
}