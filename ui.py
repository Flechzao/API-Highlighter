# -*- coding: utf-8 -*-
# @Date     : 2024-08-05
# @File     : ui.py
# @function : 用户界面模块，用于创建和布局GUI组件

from javax.swing import (
    JPanel, JTextArea, JScrollPane, JTable, JButton, BorderFactory, BoxLayout, SwingConstants,
    JCheckBox, Box, JMenuItem, JPopupMenu, JTabbedPane, AbstractCellEditor
)
from constants import STRINGS, decode_text
from java.awt import Component, GridLayout
from ui_components import CustomTableModel, ChineseTextEditor, CenterRenderer, CheckBoxRenderer, CheckBoxEditor

# javax.swing: Java的标准GUI工具包，用于创建窗口、按钮、文本框等组件
# java.awt: 提供了图形用户界面的基础类，如布局管理器、颜色等
# constants: 本地模块，包含字符串常量和解码函数
# ui_components: 本地模块，包含自定义UI组件，如表格模型、文本编辑器等

def init_ui(self):
    """
    初始化UI组件，设计插件的布局
    """
    # [Section: 主面板]
    self._main_panel = JPanel()
    self._main_panel.layout = BoxLayout(self._main_panel, BoxLayout.Y_AXIS) # 设置为垂直布局

    # [Section: 导入API面板]
    # “导入API” 文本框
    self._text_area = JTextArea(10, 30)
    self._text_area.border = BorderFactory.createTitledBorder(decode_text(STRINGS["batch_import_label"]))
    self._main_panel.add(JScrollPane(self._text_area)) # 将文本框添加到主面板中
    # 按钮面板
    self._button_import_panel = JPanel()
    self._button_import_panel.layout = BoxLayout(self._button_import_panel, BoxLayout.X_AXIS) # 设置为水平布局
    self._main_panel.add(self._button_import_panel) # 将按钮面板添加到主面板中
    self._import_button = JButton(decode_text(STRINGS["import_button"]), actionPerformed=self.import_apis) # 创建“导入API按钮”
    self._button_import_panel.add(self._import_button) # 将导入按钮添加到按钮面板中

    # [Section: 复选框面板]
    self._button_import_panel.add(Box.createHorizontalStrut(10)) # 设置复选框之间的水平间距，10像素
    self._precise_match_button = JCheckBox(decode_text(STRINGS["precise_match_checkbox"])) # 创建“精确匹配”复选框
    self._precise_match_button.setSelected(True) # 默认开启
    self._button_import_panel.add(self._precise_match_button) # 添加到按钮面板中
    self._check_whole_request_button = JCheckBox(decode_text(STRINGS["check_whole_request_checkbox"])) # 创建“检查完整数据包”复选框
    self._button_import_panel.add(self._check_whole_request_button)
    self._enable_regex_matching_button = JCheckBox(decode_text(STRINGS["enable_regex_matching_checkbox"])) # 创建“启用正则规则替换”复选框
    self._button_import_panel.add(self._enable_regex_matching_button)
    self._url_encode_button = JCheckBox(decode_text(STRINGS["url_encode_button"])) # 创建“URL编码”复选框
    self._button_import_panel.add(self._url_encode_button)
    self._check_api_history_button = JCheckBox(decode_text(STRINGS["Check API History"])) # 创建“检查API历史记录”复选框
    self._check_api_history_button.addActionListener(self.check_api_history) # 添加事件监听器，用于回调
    self._button_import_panel.add(self._check_api_history_button)
    self._find_sensitive_button = JCheckBox(decode_text(STRINGS["find_sensitive"])) # 创建“敏感信息检查（HaE规则）”复选框
    self._find_sensitive_button.setSelected(True) # 默认开启
    self._button_import_panel.add(self._find_sensitive_button)

    # [Section: 表格面板]
    # 创建表格模型，包含请求方法（HTTP）、URL路径（API）、测试结果（result）、测试状态（state）和备注（note）
    self._table_model = CustomTableModel(["HTTP", "API", "result", "state", "note", "Domain"], 0)
    center_renderer = CenterRenderer() #设置居中渲染
    # 创建并配置表格
    self._table = JTable(self._table_model)
    self._table.setRowSelectionAllowed(True) # 允许选择行
    self._table.setColumnSelectionAllowed(False) # 禁止选择列
    self._table.setAutoCreateRowSorter(True) # 自动创建排序
    # 获取表格列模型以进一步配置各列
    column_model = self._table.getColumnModel()
    # 配置HTTP method列：设置宽度（100）、设置编辑器为中文文本编辑器、应用居中渲染
    method_column = column_model.getColumn(0)
    method_column.setMaxWidth(100)
    method_column.setCellEditor(ChineseTextEditor())
    method_column.setCellRenderer(center_renderer)
    # 配置API列：设置宽度（650）
    api_column = column_model.getColumn(1)
    api_column.setMaxWidth(650)
    # 配置result列：设置宽度（650）、设置编辑器为中文文本编辑器
    comment_column = column_model.getColumn(2)
    comment_column.setMaxWidth(300)
    comment_column.setCellEditor(ChineseTextEditor())
    # 配置state列：设置宽度（80）、使用自定义的居中复选框渲染器和编辑器
    test_column = column_model.getColumn(3)
    test_column.setMaxWidth(80)
    test_column.setCellRenderer(CheckBoxRenderer())  # 使用自定义的居中复选框渲染器
    test_column.setCellEditor(CheckBoxEditor())
    # 配置note列：设置宽度（500）、设置编辑器为中文文本编辑器
    note_column = column_model.getColumn(4)
    note_column.setCellEditor(ChineseTextEditor())
    note_column.setMaxWidth(500)
    # 配置域名列：设置宽度（500）、设置编辑器为中文文本编辑器
    domain_column = column_model.getColumn(5)
    domain_column.setMaxWidth(500)
    domain_column.setCellEditor(ChineseTextEditor())
    # 设置表格行高（25）
    self._table.setRowHeight(25)
    self._main_panel.add(JScrollPane(self._table)) # 将表格添加到主面板中

    # [Section: 底部按钮面板]
    # 初始化按钮面板及其布局
    self._button_panel = JPanel()
    self._button_panel.layout = GridLayout(1, 4)
    self._main_panel.add(self._button_panel)
    self._remove_button = JButton(decode_text(STRINGS["remove_button"]), actionPerformed=self.remove_api) # 添加“删除API”按钮
    self._button_panel.add(self._remove_button)
    self._toggle_tested_button = JButton(decode_text(STRINGS["toggle_tested_button"]), actionPerformed=self.toggle_tested) # 添加“切换测试状态”按钮
    self._button_panel.add(self._toggle_tested_button)
    self._toggle_vulnerable_button = JButton(decode_text(STRINGS["toggle_vulnerable_button"]), actionPerformed=self.toggle_vulnerable) # 添加“切换漏洞类型”按钮
    self._button_panel.add(self._toggle_vulnerable_button)
    self._move_tested_to_top_button = JButton(decode_text(STRINGS["move_tested_to_top_button"]), actionPerformed=self.move_tested_to_top) # 添加“将已测试移至顶部”按钮
    self._button_panel.add(self._move_tested_to_top_button)
    self._add_domain_to_scope_button = JButton(decode_text(STRINGS["add_domain_to_scope_button"]), actionPerformed=self.add_domain_to_scope) # 添加“添加过滤器”按钮
    self._button_panel.add(self._add_domain_to_scope_button)

    # [Section：查找API面板]
    # 创建查找API面板，包含文本框和按钮
    self._filter_panel = JPanel()
    self._filter_panel.layout = BoxLayout(self._filter_panel, BoxLayout.X_AXIS)
    self._main_panel.add(self._filter_panel)
    # 添加查找API文本框
    self._filter_text = JTextArea(1, 10)
    self._filter_panel.add(JScrollPane(self._filter_text))
    # 添加“查找API”按钮
    self._filter_button = JButton(decode_text(STRINGS["find_api_button"]), actionPerformed=self.find_api)
    self._filter_panel.add(self._filter_button)

def getUiComponent(self):
    """
    获取UI组件
    """
    return self._main_panel

def getTabCaption(self):
    """
    获取Tab标题
    """
    return "API Highlighter"
