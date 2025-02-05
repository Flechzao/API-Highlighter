# -*- coding: utf-8 -*-
# @Date     : 2024-07-08
# @File     : menu_actions.py
# @function : 右键菜单方法
import re

from java.util import ArrayList
from java.net import URL
from constants import STRINGS, decode_text
from javax.swing import JMenuItem, JPopupMenu, JMenu
from utils import replace_api_patterns, URL_encode

def change_test_status(self, invocation):
    """
        更改测试状态功能函数
    """
    # 获取选中的消息
    selected_messages = invocation.getSelectedMessages()
    # 遍历选中的消息
    for message in selected_messages:
        request = message.getRequest()
        analyzed_request = self._helpers.analyzeRequest(message.getHttpService(), request) #
        # 获取URL
        url = analyzed_request.getUrl().toString()
        api_row = None
        # 遍历表格中的行
        for row in range(self._table_model.getRowCount()):
            api = self._table_model.getValueAt(row, 1)   # 在API表格的第二列获取具体的API信息
            # 如果API在URL中出现，则记录行号
            if api in url:
                api_row = row
                break
        # 如果找到了对应的API
        if api_row is not None:
            tested = self._table_model.getValueAt(api_row, 3) # 在API表格的第四列获取测试状态
            # 如果当前已被测试过
            if tested:
                # 调整API表格
                self._table_model.setValueAt(False, api_row, 3) # 测试状态修改为未测试
                self._table_model.setValueAt(decode_text(STRINGS["Under Test"]), api_row, 2) # 测试结果修改为"正在测试中"
                # 调整history中的接口信息
                message.setHighlight("yellow") # 将接口的状态设置为高亮 黄色
                message.setComment(decode_text(STRINGS["Under Test"])) # 设置注释为 "正在测试中"
            # 如果当前未被测试过
            else:
                # 调整API表格
                self._table_model.setValueAt(True, api_row, 3) # 修改为已测试
                self._table_model.setValueAt(decode_text(STRINGS["Test passed, safe"]), api_row, 2) # 测试结果修改为"测试通过，安全"
                # 调整history中的接口信息
                message.setHighlight("green") # 将接口的状态设置为高亮 绿色
                message.setComment(decode_text(STRINGS["Test passed, safe"])) # 设置注释为 "测试通过，安全"


def createMenuItems(self, invocation):
    """
        创建右键菜单项
    """
    # 创建菜单
    menu = ArrayList()
    # 如果当前选中的是历史记录，则添加菜单
    if invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY: #
        # 创建"改变测试状态"菜单项
        change_test_status_item = JMenuItem(
            decode_text(STRINGS["change_test_status_item"]),
            actionPerformed=lambda x: self.change_test_status(invocation)
        )
        menu.add(change_test_status_item)

        # 创建"添加接口"菜单项
        add_api_item = JMenuItem(
            decode_text(STRINGS["add_api_item"]),
            actionPerformed=lambda x: self.add_api(invocation)
        )
        menu.add(add_api_item)

        # 创建"标记存在漏洞"菜单（二级菜单）
        mark_as_vulnerable_menu = JMenu(decode_text(STRINGS["mark_as_vulnerable_item"]))
        menu.add(mark_as_vulnerable_menu)
        # 创建"标记存在漏洞"菜单项
        mark_as_vulnerable = JMenuItem(
            decode_text(STRINGS["Vulnerable"]),
            actionPerformed=lambda x: self.mark_as_vulnerable(invocation)
        )
        mark_as_vulnerable_menu.add(mark_as_vulnerable)
        # 创建"标记存在垂直越权漏洞"菜单项
        mark_as_privilege_escalation_Vertical = JMenuItem(
            decode_text(STRINGS["PrivilegeEscalation_Vertical"]),
            actionPerformed=lambda x: self.mark_as_privilege_escalation_Vertical(invocation)
        )
        mark_as_vulnerable_menu.add(mark_as_privilege_escalation_Vertical)
        # 创建"标记存在水平越权漏洞"菜单项
        mark_as_privilege_escalation_Horizontal = JMenuItem(
            decode_text(STRINGS["PrivilegeEscalation_Horizontal"]),
            actionPerformed=lambda x: self.mark_as_privilege_escalation_Horizontal(invocation)
        )
        mark_as_vulnerable_menu.add(mark_as_privilege_escalation_Horizontal)
        # 创建"标记存在敏感信息漏洞"菜单项
        mark_as_sensitive_info_item = JMenuItem(
            decode_text(STRINGS["SensitiveInfo"]),
            actionPerformed=lambda x: self.mark_as_sensitive_info(invocation)
        )
        mark_as_vulnerable_menu.add(mark_as_sensitive_info_item)
        # 创建"标记存在未授权漏洞"菜单项
        mark_as_unauthorized_item = JMenuItem(
            decode_text(STRINGS["Unauthorized"]),
            actionPerformed=lambda x: self.mark_as_unauthorized(invocation)
        )
        mark_as_vulnerable_menu.add(mark_as_unauthorized_item)
    return menu


def mark_as_vulnerable(self, invocation):
    """
        标记存在漏洞
    """
    # 获取选中的消息
    selected_messages = invocation.getSelectedMessages()
    # 遍历选中的消息
    for message in selected_messages:
        request = message.getRequest()
        # 分析请求
        analyzed_request = self._helpers.analyzeRequest(message.getHttpService(), request)
        # 获取URL
        url = analyzed_request.getUrl().toString()
        api_row = None
        # 查找URL在表格中的位置
        for row in range(self._table_model.getRowCount()):
            api = self._table_model.getValueAt(row, 1)
            if api in url:
                api_row = row
                break
        # 如果找到了，在表格中将其标记为"存在漏洞"
        if api_row is not None:
            # 在消息中添加注释
            message.setComment(decode_text(STRINGS["Vulnerable"]))
            # 在表格中标记为漏洞
            self._table_model.setValueAt(True, row, 3)
            # 在表格中标记API为漏洞
            self._table_model.setValueAt(decode_text(STRINGS["Vulnerable"]), api_row, 2)
            # 高亮显示消息
            message.setHighlight("red")

# 标记存在水平越权漏洞函数
def mark_as_privilege_escalation_Horizontal(self, invocation):
    mark_vulnerability(self, invocation, STRINGS["PrivilegeEscalation_Horizontal"])

# 标记存在垂直越权漏洞函数
def mark_as_privilege_escalation_Vertical(self, invocation):
    mark_vulnerability(self, invocation, STRINGS["PrivilegeEscalation_Vertical"])

# 标记存在未授权漏洞函数
def mark_as_unauthorized(self, invocation):
    mark_vulnerability(self, invocation, STRINGS["Unauthorized"])

# 标记存在敏感信息漏洞函数
def mark_as_sensitive_info(self, invocation):
    mark_vulnerability(self, invocation, STRINGS["SensitiveInfo"])
    # selected_messages = invocation.getSelectedMessages()
    # for message in selected_messages:
    #     request = message.getRequest()
    #     analyzed_request = self._helpers.analyzeRequest(message.getHttpService(), request)
    #     url = analyzed_request.getUrl().toString()
    #     api_row = None
    #     for row in range(self._table_model.getRowCount()):
    #         api_path = self._table_model.getValueAt(row, 1)
    #         if api_path in url:
    #             api_row = row
    #             break
    #     if api_row is not None:
    #         message.setComment(decode_text(STRINGS["SensitiveInfo"]))
    #         self._table_model.setValueAt(True, api_row, 3)
    #         self._table_model.setValueAt(decode_text(STRINGS["SensitiveInfo"]), api_row, 2)
    #         message.setHighlight("orange")


def add_api(self, invocation):
    """
        右键添加接口函数
    """
    selected_messages = invocation.getSelectedMessages()

    if len(selected_messages) != 1:
        return  # 只处理一个消息，如果选中多于一个，则返回

    message = selected_messages[0]
    request = message.getRequest()

    # 分析请求
    analyzed_request = self._helpers.analyzeRequest(message.getHttpService(), request)

    # 获取HTTP方法和URL
    http_method = analyzed_request.getMethod().decode('utf-8').upper()
    url = analyzed_request.getUrl().toString()

    # 解析URL以分离路径
    parsed_url = URL(url)
    api_path = parsed_url.getPath()

    # 应用URL编码和正则表达式替换（如果启用）
    if self._url_encode_button.isSelected():
        api_path = URL_encode(api_path)

    if self._enable_regex_matching_button.isSelected():
        api_path = replace_api_patterns(api_path)

    # 构建API元组用于比较
    api_tuple = (http_method, api_path)

    # 检查是否已有相同的API记录
    existing_apis = {
        (self._table_model.getValueAt(row, 0), self._table_model.getValueAt(row, 1))
        for row in range(self._table_model.getRowCount())
    }
    # 如果已有记录，则返回
    if api_tuple in existing_apis:
        return

    # 添加新API到表格中
    self._table_model.addRow([http_method, api_path, "", False])


def mark_vulnerability(self, invocation, vulnerability_type):
    """
    标记选定的消息为指定类型的漏洞，并在表格中相应位置更新状态和结果。
    invocation: 当前的Burp协作器调用
    vulnerability_type: 漏洞类型字符串，用于评论和表格值
    """
    # 获取选中的消息
    selected_messages = invocation.getSelectedMessages()

    # 遍历选中的消息
    for message in selected_messages:
        # 获取请求
        request = message.getRequest()
        # 分析请求
        analyzed_request = self._helpers.analyzeRequest(message.getHttpService(), request)
        # 获取URL
        url = analyzed_request.getUrl().toString()

        # 查找URL在表格中的行数
        api_row = next(
            (row for row in range(self._table_model.getRowCount()) if self._table_model.getValueAt(row, 1) in url),
            None)

        # 如果找到了对应的行数
        if api_row is not None:
            # 在消息上添加评论
            message.setComment(decode_text(vulnerability_type))
            # 在表格中相应位置更新状态和结果
            self._table_model.setValueAt(True, api_row, 3)
            self._table_model.setValueAt(decode_text(vulnerability_type), api_row, 2)
            # 高亮显示消息
            message.setHighlight("orange")


def create_menu_items():
    return None