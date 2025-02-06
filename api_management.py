# -*- coding: utf-8 -*-
# @Date     : 2024-07-18
# @File     : api_management.py
# @function : API管理方法
from java.net import URL
from constants import decode_text, STRINGS
from utils import replace_api_patterns, URL_encode

def import_apis(self, event):
    """
        导入新的API到表格模型中。
        遍历文本区域中的每一行，解析出HTTP方法和API路径，
        并将它们添加到表格模型中，除非这些组合已存在于表中。
        如果启用了正则表达式匹配，则替换API模式；
        如果URL编码按钮被选中，则对API路径进行URL编码。
    """
    # 提取当前存在的API列表以避免重复导入
    existing_apis = {(self._table_model.getValueAt(row, 0), self._table_model.getValueAt(row, 1)) for row in range(self._table_model.getRowCount())}

    # 处理每行文本，并添加到表格模型中
    apis = self._text_area.text.splitlines()
    new_apis = set()  # 新建一个集合存储新导入的API

    for api in apis:
        api = api.strip()
        if not api:
            continue

        # 尝试分割HTTP方法和API路径
        parts = api.split(" ", 1)
        if len(parts) == 1:
            method = ""  # 如果没有提供HTTP方法，设为空字符串
            api_path = parts[0]  # 全部作为API路径
        else:
            method = parts[0].upper()  # 标准化HTTP方法为大写
            api_path = parts[1]  # 赋值API路径

        # 处理API路径空白字符
        api_path = api_path.strip()

        # 启用正则替换功能
        if self._enable_regex_matching_button.isSelected():
            api_path = replace_api_patterns(api_path)

        # 启用URL编码功能
        if self._url_encode_button.isSelected():
            api_path = URL_encode(api_path)

        # 构造API的唯一标识符元组
        api_tuple = (method, api_path)

        # 检查是否已有相同的API记录
        if api_tuple in existing_apis or api_tuple in new_apis:
            continue

        # 添加新API到集合和表格中
        new_apis.add(api_tuple)
        self._table_model.addRow([method, api_path, "", False])


def remove_api(self, event):
    """
        移除选定的API条目。

        获取选定的行号列表，从后向前遍历删除行，
        这样可以避免因删除操作导致的索引偏移问题。
    """
    selected_rows = self._table.getSelectedRows()
    if not selected_rows:
        return
    for i in reversed(selected_rows):
        self._table_model.removeRow(i)

def toggle_tested(self, event):
    """
        切换所选API的测试状态。

        更新选定行的测试状态和评论字段，
        支持三种状态：未测试、测试通过、发现漏洞。

    """
    # 获取选定的行，如果没有选择，则退出
    selected_rows = self._table.getSelectedRows()
    if not selected_rows:
        return

    # 遍历选定行更新测试状态和评论信息
    for row in selected_rows:
        tested = self._table_model.getValueAt(row, 3)
        comment = self._table_model.getValueAt(row, 2)

        # 根据当前状态切换至下一个状态
        if comment == decode_text(STRINGS["Vulnerable"]):
            new_state = [False, decode_text(STRINGS["Under Test"])]
        elif not tested:
            new_state = [True, decode_text(STRINGS["Test passed, safe"])]
        else:
            new_state = [True, decode_text(STRINGS["Vulnerable"])]

        # 更新表格模型中的值
        self._table_model.setValueAt(new_state[0], row, 3)
        self._table_model.setValueAt(new_state[1], row, 2)

def toggle_vulnerable(self, event):
    """
        切换所选API的漏洞状态。

        更新选定行的测试状态和评论字段，
        支持三种状态：未授权、水平越权、垂直越权、敏感信息泄露。
    """
    # 获取选定的行，如果没有选择，则退出
    selected_rows = self._table.getSelectedRows()
    if not selected_rows:
        return

    # 遍历选定行更新测试状态和评论信息
    for row in selected_rows:
        tested = self._table_model.getValueAt(row, 3)
        comment = self._table_model.getValueAt(row, 2)

        # 根据当前状态切换至下一个状态
        if comment == decode_text(STRINGS["Vulnerable"]):
            new_state = [True, decode_text(STRINGS["Unauthorized"])]
        elif comment == decode_text(STRINGS["Unauthorized"]):
            new_state = [True, decode_text(STRINGS["PrivilegeEscalation_Horizontal"])]
        elif comment == decode_text(STRINGS["PrivilegeEscalation_Horizontal"]):
            new_state = [True, decode_text(STRINGS["PrivilegeEscalation_Vertical"])]
        elif comment == decode_text(STRINGS["PrivilegeEscalation_Horizontal"]):
            new_state = [True, decode_text(STRINGS["SensitiveInfo"])]
        else:
            new_state = [True, decode_text(STRINGS["Vulnerable"])]
        # 更新表格模型中的值
        self._table_model.setValueAt(new_state[0], row, 3)
        self._table_model.setValueAt(new_state[1], row, 2)


def move_tested_to_top(self, event):
    """
        将所有已测试的API移动到表格顶部。

        先分离已测试和未测试的API数据，
        然后清空表格模型并重新按顺序添加数据。
    """
    tested_rows = []
    untested_rows = []
    # 分离已测试和未测试的API数据行
    for i in range(self._table_model.getRowCount()):
        if self._table_model.getValueAt(i, 3): # 测试状态为True，则添加到已测试行
            tested_rows.append(self._table_model.getDataVector().elementAt(i))
        else: # 测试状态为False，则添加到未测试行
            untested_rows.append(self._table_model.getDataVector().elementAt(i))
    # 清空现有表格数据并重新填充
    self._table_model.setRowCount(0)
    for row in tested_rows + untested_rows:
        self._table_model.addRow(row)

def find_api(self, event):
    """
        在表格中查找包含特定文本的API。

        使用搜索框中的文本作为关键词，
        查找第一个匹配项并在表格中高亮显示。
        若未找到匹配项，则清除当前选择。

        优化项：出现类似名称的时候，可以匹配到所有名称
    """
    # 获取搜索文本
    search_text = self._filter_text.text.strip()
    if not search_text:
        return
    # 遍历表格寻找匹配项
    api_row = -1
    for row in range(self._table_model.getRowCount()):
        method = self._table_model.getValueAt(row, 0)
        api = self._table_model.getValueAt(row, 1)
        if search_text in method or search_text in api:
            api_row = row
            break
    # 高亮显示匹配行或清除选择
    if api_row != -1:
        self._table.setRowSelectionInterval(api_row, api_row)
        self._table.scrollRectToVisible(self._table.getCellRect(api_row, 0, True))
    else:
        self._table.clearSelection()

# 添加筛选菜单
def add_domain_to_scope(self, invocation):
    """
        将所选API的域名添加到Burp Suite的域范围中。
    """
    # 获取选定的行，如果没有选择，则退出
    selected_rows = self._table.getSelectedRows()
    if not selected_rows:
        return

    # 获取所选行的域名
    domains = set()
    for row in selected_rows:
        domain = self._table_model.getValueAt(row, 5)
        if domain:
            domain = domain.strip().replace('\r', '').replace('\n', '')  # 清理和替换
            domains.add(domain)

    # 将域名添加到scope中
    for domain in domains:
        try:
            # print("Domain: {}, Type: {}".format(domain, type(domain)))
            url = URL(domain)
            self._callbacks.includeInScope(url)
        except Exception as e:
            print("Error including domain in scope: {}".format(e))