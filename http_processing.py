# -*- coding: utf-8 -*-
# @Date     : 2024-07-28
# @File     : http_processing_test.py
# @function : 负责处理HTTP消息
import re
import yaml
from utils import replace_api_patterns, URL_encode
from constants import STRINGS, decode_text
import threading
import time



def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
    """
        核心函数！
        处理HTTP消息并根据API列表更新消息的状态和注释。

        messageIsRequest: 消息是否为请求消息
        messageInfo: HTTP消息
    """
    # 判断是否为请求消息,如果不是，则不处理
    if not messageIsRequest:
        # 获取请求报文的URL和body信息
        request_info = self._helpers.analyzeRequest(messageInfo)
        url = request_info.getUrl().toString()
        http_method = request_info.getMethod().decode('utf-8').upper()
        request_string = self._helpers.bytesToString(messageInfo.getRequest())
        # 在API列表中查找匹配的API
        api_row, found_api = find_api_in_list(self, url, request_string)
        # 如果找到了API，则更新消息状态和注释
        if found_api:
            update_message_info(self, messageInfo, api_row)
            update_comment_if_needed(self, messageInfo, api_row)
            update_http_method(self, messageInfo, api_row, http_method)
            update_domain(self, messageInfo, api_row, url)
            find_sensitive(self, messageInfo, api_row)

def update_comment_if_needed(self, messageInfo, api_row):
    """
        更新表格模型中的注释，如果消息的注释与API行的注释不匹配，则进行更新

        message_info: 包含请求或响应数据的消息对象
        api_row: API行的索引
        return: 更新后的注释
    """
    # 获取这个API当前在API表格中的注释
    comment = self._table_model.getValueAt(api_row, 2)
    # 如果消息的注释与API表格中的注释不匹配，则进行更新API表格中的注释
    if messageInfo.getComment() is not None and messageInfo.getComment() != comment:
        #print("message_info.getComment(): ", messageInfo.getComment())
        self._table_model.setValueAt(messageInfo.getComment(), api_row, 2)
        return messageInfo.getComment()
    return comment # 返回注释


def find_api_in_list(self, url, request_string):
    """
    在API列表中查找匹配的API，并返回API行号和是否找到API的布尔值。
    url: 请求的URL
    request_string: 请求的body信息
    """
    found_api = False
    api_row = -1
    api_rules = [(row, self._table_model.getValueAt(row, 1)) for row in range(self._table_model.getRowCount())]

    # 将URL和请求字符串转换为小写，以便进行不区分大小写的匹配
    lower_url = url.lower()
    lower_request_string = request_string.lower()

    for row, api in api_rules:
        # 替换 {id} 为 \d+ 以匹配数字
        api_regex_pattern = api.replace("{id}", r"\d+")
        # 用 $ 来确保结尾匹配
        if api_regex_pattern.endswith('/'):
            api_regex_pattern += r'?$'
        else:
            api_regex_pattern += r'$'

        api_regex = re.compile(api_regex_pattern, re.IGNORECASE)

        # 先检查请求字符串
        if self._check_whole_request_button.isSelected():
            match_request = api_regex.search(lower_request_string)
        else:
            match_request = None

        # 再检查URL
        match_url = api_regex.search(lower_url)

        # 如果在请求字符串中找到匹配，或在URL中找到匹配
        if match_request or match_url:
            api_row = row
            found_api = True
            break
        elif not match_url and not match_request:
            # 如果没有匹配，进行模糊匹配
            if (not self._precise_match_button.isSelected() and
                    (api.lower() in lower_url or api.lower() in lower_request_string)):
                api_row = row
                found_api = True
                break

    return api_row, found_api
def update_message_info(self, messageInfo, api_row):
    """
    根据API表格中的状态更新HTTP消息的状态和注释。
    """
    # 获取API表格中的注释和测试状态
    comment = self._table_model.getValueAt(api_row, 2)
    #print("comment: ", comment)
    tested = self._table_model.getValueAt(api_row, 3)
    #print("tested: ", tested)
    # 根据API状态设置消息状态和注释
    # 如果API是漏洞,则设置消息状态为红色
    if comment == decode_text(STRINGS["Vulnerable"]):
        messageInfo.setHighlight("red")
        messageInfo.setComment(decode_text(STRINGS["Vulnerable"]))
        self._table_model.setValueAt(decode_text(STRINGS["Vulnerable"]), api_row, 2)
        return
    # 如果API是水平越权、垂直越权、未授权或敏感信息,则设置消息状态为橙色
    elif comment == decode_text(STRINGS["PrivilegeEscalation_Horizontal"]):
        messageInfo.setHighlight("orange")
        messageInfo.setComment(decode_text(STRINGS["PrivilegeEscalation_Horizontal"]))
        self._table_model.setValueAt(decode_text(STRINGS["PrivilegeEscalation_Horizontal"]), api_row, 2)
        return
    elif comment == decode_text(STRINGS["PrivilegeEscalation_Vertical"]):
        messageInfo.setHighlight("orange")
        messageInfo.setComment(decode_text(STRINGS["PrivilegeEscalation_Vertical"]))
        self._table_model.setValueAt(decode_text(STRINGS["PrivilegeEscalation_Vertical"]), api_row, 2)
        return
    elif comment == decode_text(STRINGS["Unauthorized"]):
        messageInfo.setHighlight("orange")
        messageInfo.setComment(decode_text(STRINGS["Unauthorized"]))
        self._table_model.setValueAt(decode_text(STRINGS["Unauthorized"]), api_row, 2)
        return
    elif comment == decode_text(STRINGS["SensitiveInfo"]):
        messageInfo.setHighlight("orange")
        messageInfo.setComment(decode_text(STRINGS["SensitiveInfo"]))
        self._table_model.setValueAt(decode_text(STRINGS["SensitiveInfo"]), api_row, 2)
        return
    # 如果备注是自定义的并且测试过，那就不用处理，只需要同步history中的备注和颜色
    elif tested and comment is not None and comment != decode_text(STRINGS["Test passed, safe"]):
        messageInfo.setHighlight("red")
        messageInfo.setComment(comment)
        return

    #如果API是已测试,则设置消息状态为绿色,并设置注释为"安全'
    if tested:
        messageInfo.setHighlight("green")
        messageInfo.setComment(decode_text(STRINGS["Test passed, safe"]))
        self._table_model.setValueAt(decode_text(STRINGS["Test passed, safe"]), api_row, 2)
    # 如果API是未测试,则设置消息状态为黄色,并设置注释为"测试中"
    else:
        messageInfo.setHighlight("yellow")
        messageInfo.setComment(decode_text(STRINGS["Under Test"]))
        self._table_model.setValueAt(decode_text(STRINGS["Under Test"]), api_row, 2)

# def check_api_history(self,event):
#     """
#     检查代理历史记录中的所有请求,并将匹配的API标记为已测试,如果有注释,则更新注释
#     """
#     # 获取代理历史记录
#     history = self._callbacks.getProxyHistory()
#     # 遍历历史记录中的每个请求
#     for request in history:
#         request_info = self._helpers.analyzeRequest(request)
#         url = request_info.getUrl().toString()
#         request_string = self._helpers.bytesToString(request.getRequest())
#         api_row, found_api = find_api_in_list(self, url, request_string)
#         # 如果找到了API，则更新消息状态和注释
#         if found_api:
#             update_message_info(self, request, api_row)
#             update_comment_if_needed(self, request, api_row)

def check_api_history(self, event):
    """
    检查代理历史记录中的所有请求
    此处使用多线程进行优化
    """
    # 如果没有打开“检查历史记录”选项，则返回
    if not self._check_api_history_button.isSelected():
        return
    # 获取history记录
    history = self._callbacks.getProxyHistory()

    # 添加安全锁
    lock = threading.Lock()
    # 请求处理函数
    def process_request(request):
        # 获取请求信息和URL
        request_info = self._helpers.analyzeRequest(request)
        url = request_info.getUrl().toString()
        request_string = self._helpers.bytesToString(request.getRequest())
        api_row, found_api = find_api_in_list(self, url, request_string)

        # 如果找到了API，则更新消息状态和注释
        if found_api:
            with lock:
                update_message_info(self, request, api_row)
                #update_comment_if_needed(self, request, api_row)

    # 创建线程列表，设置10线程
    threads = []
    max_threads = 10
    # 遍历历史记录中的每个请求
    for request in history:
        # 检查线程数量，如果＞10，则等待
        while threading.active_count() > max_threads:
            time.sleep(0.1)
        # process_request函数作为参数传递给线程
        t = threading.Thread(target=process_request, args=(request,))
        t.start()
        threads.append(t)

    # 等待所有线程完成
    for t in threads:
        t.join()

def autoadd_http_method(self, event):
    """
    自动补充http方法，如果有出现多个http方法，则新增一行
    """
    # 获取代理历史记录
    history = self._callbacks.getProxyHistory()
    # 遍历历史记录中的每个请求
    for request in history:
        request_info = self._helpers.analyzeRequest(request)
        url = request_info.getUrl().toString()
        http_method = request_info.getHttpMethod()
        request_string = self._helpers.bytesToString(request.getRequest())
        api_row, found_api = find_api_in_list(self, url, request_string)
        # 如果找到了API，则更新消息状态和注释
        if found_api:
            update_message_info(self, request, api_row)
            update_comment_if_needed(self, request, api_row)


def update_http_method(self, messageInfo, api_row, http_method):
    """
    自动补充http方法，如果有出现多个http方法，则新增一行
    """
    method = self._table_model.getValueAt(api_row, 0)
    # 如果method为None，则更新method
    if method is None:
        method = http_method
        self._table_model.setValueAt(method, api_row, 0)
        return messageInfo.getComment()
    # 如果method和http_method不一致，则补充http_method，变为GET/POST
    elif method != http_method:
        method = method + "/" + http_method
        # 过滤OPTIONS,并且结果需要去重
        method = method.replace("OPTIONS", "")
        method = "/".join(set(method.split("/")))
        # 删除开头的/
        method = method.lstrip("/")
        self._table_model.setValueAt(method, api_row, 0)
        return messageInfo.getComment()


def update_domain(self, messageInfo, api_row, domain):
    """
    更新域名
    """
    # 过滤:443 端口信息
    domain = domain.replace(":443", "")

    # 获取当前API的域名
    current_domain = self._table_model.getValueAt(api_row, 5)
    #print("current_domain: ", current_domain)
    # 如果域名为空，则更新域名
    if current_domain is None:
        self._table_model.setValueAt(domain, api_row, 5)
        return messageInfo.getComment()
    # 如果域名和当前域名不一致，则更新域名
    elif current_domain != domain:
        self._table_model.setValueAt(domain, api_row, 5)
        return messageInfo.getComment()

file_path = 'Rules.yml'
def load_sensitive_info_rules(file_path):
    with open(file_path, 'r') as f:
        data = yaml.safe_load(f)

    rules = []
    for group in data['rules']:
        for rule in group['rule']:
            if rule['loaded']: # 只有加载过的规则才会被添加
                rules.append((rule['f_regex'], rule['name'])) # f_regex是正则表达式，name是敏感信息标签

    return rules



def find_sensitive(self, messageInfo, api_row):
    """
    检查代理历史记录中的所有请求,并将匹配的API标记为已测试,如果有注释,则更新注释
    """
    # 如果没有打开“敏感信息检查”选项，则返回
    if not self._find_sensitive_button.isSelected():
        return
    # 获取请求信息
    request_info = self._helpers.analyzeRequest(messageInfo)
    request_url = request_info.getUrl().toString() # 获取URL
    request_body = messageInfo.getRequest()  # 获取请求体
    request_response = messageInfo.getResponse() # 获取响应
    # 获取敏感信息规则
    hae_rules = load_sensitive_info_rules("Rules.yml")
    # 敏感信息标记
    found_sensitive_info = []

    # 检查响应体中的敏感信息
    if request_response:
        # print(request_response)
        body_str = request_response.tostring()  # 将字节转换为字符串，适当处理编码

        for regex, label in hae_rules:
            if re.search(regex, body_str.decode('utf-8', errors='ignore')):  # 忽略编码错误
                found_sensitive_info.append(label)
                # print("Found sensitive info: {}".format(label))  # 修改为标准格式化
    # 如果有敏感信息
    if found_sensitive_info:
        #print("All found sensitive info: {}".format(', '.join(found_sensitive_info)))
        messageInfo.setHighlight("orange")
        messageInfo.setComment(decode_text(STRINGS["SensitiveInfo"]))
        # 更新表格信息
        self._table_model.setValueAt(decode_text(STRINGS["SensitiveInfo"]), api_row, 2)
        # 连接所有命中的规则名称，并更新到表格的第 5 列
        combined_labels = ', '.join(found_sensitive_info)  # 将所有找到的标签合并为一个字符串
        self._table_model.setValueAt(combined_labels, api_row, 4)  # 更新表格第 5 列
        return

def _add_sensitive_info_tab(self, messageInfo, matches):
    """
    为给定的流量添加一个标签页，记录匹配的敏感信息
    """
    print("Adding sensitive info tab...")
    tab_title = "Sensitive Info"
    existing_tabs = self._helpers.getTabs(messageInfo)

    # 检查是否已存在该标签页
    if not any(tab.getTitle() == tab_title for tab in existing_tabs):
        new_tab = self._helpers.createTab(tab_title)

        # 在新标签中显示敏感信息
        for match in matches:
            new_tab.addLine("Label: {} | Regex: {}".format(match['label'], match['regex']))

        # 将新标签关联到特定的流量
        self._helpers.setTabForMessage(new_tab, messageInfo)
    else:
        print("The 'Sensitive Info' tab already exists for this message.")


# 未授权检查
# def check_api_authorization(self, messageInfo, api_row):
#     """
#     检查代理历史记录中的所有请求,并将匹配的API标记为已测试,如果有注释,则更新注释
#     """
#     # 如果没有打开“未授权检查”选项，则返回
#     # if not self._check_api_authorization_button.isSelected():
#     #     return
#     # 把消息放到repeater中
#     self._callbacks.sendToRepeater(messageInfo)
#
#     # 删除cookie
#     self._callbacks.deleteCookie(messageInfo)
#
#     # 获取响应
#     response = self._callbacks.makeHttpRequest(messageInfo)
#
#     if response is None:
#         return  # 如果没有响应，则返回
#
#     # 获取响应状态码
#     response_info = self._helpers.analyzeResponse(response)
#     response_status_code = response_info.getStatusCode()
#
#     # 状态码401表示未授权，状态码403表示禁止访问
#     if response_status_code in (401, 403):
#         # 创建重复项
#         self._callbacks.addToRepeater(messageInfo.getRequest(), "未授权检查 - {}".format(
#             self._helpers.analyzeRequest(messageInfo).getUrl().toString()))
#
#         # 标记为未授权
#         messageInfo.setHighlight("orange")
#         messageInfo.setComment(decode_text(STRINGS["Unauthorized"]))
#
#         # 更新表格信息
#         api_row, found_api = find_api_in_list(self, self._helpers.analyzeRequest(messageInfo).getUrl().toString(),self._helpers.bytesToString(messageInfo.getRequest()))
#         if found_api:
#             self._table_model.setValueAt(decode_text(STRINGS["Unauthorized"]), api_row, 2)