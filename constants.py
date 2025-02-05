# -*- coding: utf-8 -*-
# @Date     : 2024-07-08
# @File     : constants.py
# @function : 界面中文化，unicode字符解码

def decode_text(text):
    return text.encode('utf-8').decode('unicode_escape')

STRINGS = {
    "ext_name": "\u0041\u0050\u0049\u0020\u0048\u0069\u0067\u0068\u006c\u0069\u0067\u0068\u0074\u0065\u0072\u0020\u0062\u0079\u0020\u8fb0\u79b9", #
    "batch_import_label": "\u6279\u91cf\u5bfc\u5165\u0041\u0050\u0049", # 批量导入API
    "import_button": "\u5bfc\u5165\u0041\u0050\u0049", # 导入API
    "remove_button": "\u5220\u9664\u0041\u0050\u0049", # 移除API
    "toggle_tested_button": "\u5207\u6362\u6d4b\u8bd5\u72b6\u6001", # 切换测试状态
    "toggle_vulnerable_button": "\u5207\u6362\u6f0f\u6d1e\u7c7b\u578b", # 切换漏洞状态
    "move_tested_to_top_button": "\u5c06\u5df2\u6d4b\u8bd5\u79fb\u81f3\u9876\u90e8", # 移动已测试到顶部
    "add_domain_to_scope_button": "\u6dfb\u52a0\u5230\u0073\u0063\u006f\u0070\u0065", # 添加到scope
    "find_api_button": "\u67e5\u627e\u0041\u0050\u0049", # 查找API
    "precise_match_checkbox": "\u542f\u7528\u7cbe\u786e\u5339\u914d", # 开启精确匹配
    "check_whole_request_checkbox": "\u68c0\u67e5\u5b8c\u6574\u6570\u636e\u5305", # 检查完整数据包
    "enable_regex_matching_checkbox": "\u542f\u7528\u6b63\u5219\u89c4\u5219\u66ff\u6362\uff08\u0022\u007b\u0078\u0078\u0078\u007d\u0022\u0020\u002d\u003e\u0020\u0022\u005c\u0064\u002b\u0022\uff09", # 启用正则匹配（"{xxx}" -> "\d+"）
    "find_sensitive":"\u654f\u611f\u4fe1\u606f\u68c0\u67e5\uff08\u0048\u0061\u0045\u89c4\u5219\uff09", # 敏感信息检查（HaE规则）
    "change_test_status_item": "\u4fee\u6539\u6d4b\u8bd5\u72b6\u6001", # 修改测试状态
    "mark_as_vulnerable_item": "\u5b58\u5728\u6f0f\u6d1e", # 存在漏洞
    "Vulnerable":"\u5b58\u5728\u6f0f\u6d1e", #存在漏洞
    "Captured interface (history interface check)":"\u5df2\u6355\u83b7\u63a5\u53e3\u0028\u5386\u53f2\u63a5\u53e3\u68c0\u67e5\u0029",#已捕获接口(历史接口检查)
    "Test passed, safe": "\u6d4b\u8bd5\u901a\u8fc7\uff0c\u5b89\u5168",  # 测试通过，安全
    "Test passed, safe (history interface check)": "\u6d4b\u8bd5\u901a\u8fc7\uff0c\u5b89\u5168\u0028\u5386\u53f2\u63a5\u53e3\u68c0\u67e5\u0029",  # 测试通过，安全(历史接口检查)
    "Under Test": "\u5df2\u6355\u83b7\u63a5\u53e3\uff0c\u63a5\u53e3\u6d4b\u8bd5\u4e2d",  # 已捕获接口，接口测试中
    "url_encode_button": "\u0055\u0052\u004c\u7f16\u7801", # URL编码
    "Check API History":"\u68c0\u67e5\u0041\u0050\u0049\u5386\u53f2\u8bb0\u5f55", # 检查API历史记录
    "PrivilegeEscalation_Horizontal":"\u6c34\u5e73\u8d8a\u6743", # 水平越权
    "PrivilegeEscalation_Vertical":"\u5782\u76f4\u8d8a\u6743", # 垂直权限
    "Unauthorized":"\u672a\u6388\u6743", # 未授权
    "SensitiveInfo":"\u654f\u611f\u4fe1\u606f\u6cc4\u9732", # 敏感信息泄露
    "add_api_item": "\u6dfb\u52a0\u0041\u0050\u0049", # 添加API
}
