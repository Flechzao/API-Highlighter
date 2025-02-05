# -*- coding: utf-8 -*-
# @Date     : 2024-07-08
# @File     : API-Highlighter_test.py
# @function : 主文件，整合其他文件

from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory
from java.awt.event import ActionListener
from javax.swing import JMenuItem
from constants import STRINGS, decode_text
from ui import init_ui, getUiComponent, getTabCaption
from api_management import import_apis, remove_api, toggle_tested, move_tested_to_top, find_api, toggle_vulnerable, \
    add_domain_to_scope
from http_processing import processHttpMessage, update_comment_if_needed, check_api_history, find_api_in_list, \
    update_message_info, update_http_method, update_domain
from menu_actions import change_test_status, createMenuItems, mark_as_vulnerable, mark_as_unauthorized, \
    mark_as_sensitive_info, mark_as_privilege_escalation_Vertical, \
    mark_as_privilege_escalation_Horizontal, add_api

# 信息
info = '''author:flechazo
version:API-Highlighter 3.0.0
description:用于高亮显示API调用，并提供API历史记录功能。它支持HTTP请求和响应的API调用识别，并能够自动更新API注释。
Github:https://github.com/Flechzao/API-Highlighter
'''
print(info)

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory, ActionListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(decode_text(STRINGS["ext_name"]))
        callbacks.registerHttpListener(self)
        self.init_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

    def __init__(self):
        self.included_domains = {}
    # UI方法
    def init_ui(self):
        return init_ui(self)

    def getUiComponent(self):
        return getUiComponent(self)

    def getTabCaption(self):
        return getTabCaption(self)

    # API管理方法
    def import_apis(self, event):
        return import_apis(self, event)

    def remove_api(self, event):
        return remove_api(self, event)

    def toggle_tested(self, event):
        return toggle_tested(self, event)

    def toggle_vulnerable(self, event):
        return toggle_vulnerable(self, event)

    def move_tested_to_top(self, event):
        return move_tested_to_top(self, event)

    def find_api(self, event):
        return find_api(self, event)

    def add_domain_to_scope(self, event):
        return add_domain_to_scope(self, event)

    # HTTP处理方法
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        return processHttpMessage(self, toolFlag, messageIsRequest, messageInfo)

    def update_comment_if_needed(self, message_info, api_row):
        return update_comment_if_needed(self, message_info, api_row)

    def find_api_in_list(self, url, request_string):
        return find_api_in_list(self, url, request_string)

    def update_message_info(self, message_info, api_row):
        return update_message_info(self, message_info, api_row)

    def check_api_history(self, event):
        return check_api_history(self, event)

    def update_http_method(self, event):
        return update_http_method(self, event)

    def update_domain(self, event):
        return update_domain(self, event)

    # 右键菜单管理方法
    def change_test_status(self, invocation):
        return change_test_status(self, invocation)

    def createMenuItems(self, invocation):
        return createMenuItems(self, invocation)

    def mark_as_vulnerable(self, invocation):
        return mark_as_vulnerable(self, invocation)

    #def mark_as_privilege_escalation(self, invocation):
        return mark_as_privilege_escalation(self, invocation)

    def mark_as_unauthorized(self, invocation):
        return mark_as_unauthorized(self, invocation)

    def mark_as_sensitive_info(self, invocation):
        return mark_as_sensitive_info(self, invocation)

    def mark_as_privilege_escalation_Vertical(self, invocation):
        return mark_as_privilege_escalation_Vertical(self, invocation)

    def mark_as_privilege_escalation_Horizontal(self, invocation):
        return mark_as_privilege_escalation_Horizontal(self, invocation)

    def add_api(self, invocation):
        return add_api(self, invocation)

