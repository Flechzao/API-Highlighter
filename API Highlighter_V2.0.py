from burp import IBurpExtender, IHttpListener, ITab
from java.lang import Boolean
from javax.swing import (JPanel, JTextArea, JScrollPane, JTable, JButton,
                         BorderFactory, BoxLayout, SwingConstants, JCheckBox,
                         Box)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableCellEditor
from java.awt import Component, GridLayout
from java.awt.event import ActionListener

info = '''author:flechazo
https://github.com/Flechzao/API-Highlighter'''
print(info)


class CustomTableModel(DefaultTableModel):
    def getColumnClass(self, columnIndex):
        if columnIndex == 3:
            return Boolean.TYPE
        return str


class CenterRenderer(DefaultTableCellRenderer):
    def __init__(self):
        super(CenterRenderer, self).__init__()
        self.setHorizontalAlignment(SwingConstants.CENTER)


class CheckBoxRenderer(DefaultTableCellRenderer):
    def __init__(self):
        super(CheckBoxRenderer, self).__init__()

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        checkbox = JCheckBox("", value)
        checkbox.setHorizontalAlignment(SwingConstants.CENTER)
        return checkbox


class CheckBoxEditor(TableCellEditor, ActionListener):
    def __init__(self):
        self.checkbox = JCheckBox()
        self.checkbox.setHorizontalAlignment(SwingConstants.CENTER)

    def getTableCellEditorComponent(self, table, value, isSelected, row, column):
        self.checkbox.selected = value
        self.checkbox.addActionListener(self)
        return self.checkbox

    def getCellEditorValue(self):
        return self.checkbox.isSelected()

    def stopCellEditing(self):
        self.fireEditingStopped()
        return True

    def actionPerformed(self, event):
        self.fireEditingStopped()


class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("API Highlighter")
        callbacks.registerHttpListener(self)
        self.init_ui()
        callbacks.addSuiteTab(self)

    def init_ui(self):
        self._main_panel = JPanel()
        self._main_panel.layout = BoxLayout(self._main_panel, BoxLayout.Y_AXIS)
        self._text_area = JTextArea(10, 30)
        self._text_area.border = BorderFactory.createTitledBorder("Batch import APIs")
        self._main_panel.add(JScrollPane(self._text_area))

        self._button_import_panel = JPanel()
        self._button_import_panel.layout = BoxLayout(self._button_import_panel, BoxLayout.X_AXIS)
        self._main_panel.add(self._button_import_panel)

        self._import_button = JButton("Import APIs", actionPerformed=self.import_apis)
        self._button_import_panel.add(self._import_button)
        self._button_import_panel.add(Box.createHorizontalStrut(10))

        self._precise_match_button = JCheckBox("Enable Precise Match")
        self._button_import_panel.add(self._precise_match_button)

        self._table_model = CustomTableModel(["Method", "API", "Comment", "TEST"], 0)
        self._table = JTable(self._table_model)
        self._table.setRowSelectionAllowed(True)
        self._table.setColumnSelectionAllowed(False)
        column_model = self._table.getColumnModel()
        column_model.getColumn(0).setMaxWidth(90)
        column_model.getColumn(3).setMaxWidth(75)
        center_renderer = CenterRenderer()
        checkbox_renderer = CheckBoxRenderer()
        checkbox_editor = CheckBoxEditor()
        column_model.getColumn(3).setCellRenderer(checkbox_renderer)
        column_model.getColumn(3).setCellEditor(checkbox_editor)
        self._table.setRowHeight(25)
        self._main_panel.add(JScrollPane(self._table))
        self._button_panel = JPanel()
        self._button_panel.layout = GridLayout(1, 4)
        self._main_panel.add(self._button_panel)
        self._remove_button = JButton("Remove API", actionPerformed=self.remove_api)
        self._button_panel.add(self._remove_button)
        self._toggle_tested_button = JButton("Toggle Tested", actionPerformed=self.toggle_tested)
        self._button_panel.add(self._toggle_tested_button)
        self._move_tested_to_top_button = JButton("Move Tested to Top", actionPerformed=self.move_tested_to_top)
        self._button_panel.add(self._move_tested_to_top_button)
        self._filter_text = JTextArea(1, 10)
        self._filter_button = JButton("Find API", actionPerformed=self.find_api)
        self._filter_panel = JPanel()
        self._filter_panel.layout = BoxLayout(self._filter_panel, BoxLayout.X_AXIS)
        self._main_panel.add(self._filter_panel)
        self._filter_panel.add(JScrollPane(self._filter_text))
        self._filter_panel.add(Box.createHorizontalStrut(10))
        self._filter_panel.add(self._filter_button)

    def getUiComponent(self):
        return self._main_panel

    def getTabCaption(self):
        return "API Highlighter"

    def import_apis(self, event):
        existing_apis = {(self._table_model.getValueAt(row, 0), self._table_model.getValueAt(row, 1))
                         for row in range(self._table_model.getRowCount())}
        apis = self._text_area.text.splitlines()
        for api in apis:
            if not api:
                continue
            parts = api.split(" ", 1)
            if len(parts) == 1:
                method = ""
                api = parts[0]
            else:
                method, api = parts
            method = method.upper()
            api = api.strip()
            if (method, api) in existing_apis:
                continue
            self._table_model.addRow([method, api, "", False])

    def remove_api(self, event):
        selected_rows = self._table.getSelectedRows()
        if not selected_rows:
            return
        for i in reversed(selected_rows):
            self._table_model.removeRow(i)

    def toggle_tested(self, event):
        selected_rows = self._table.getSelectedRows()
        if not selected_rows:
            return
        for i in selected_rows:
            tested = self._table_model.getValueAt(i, 3)
            self._table_model.setValueAt(not tested, i, 3)

    def move_tested_to_top(self, event):
        tested_rows = []
        untested_rows = []
        for i in range(self._table_model.getRowCount()):
            if self._table_model.getValueAt(i, 3):
                tested_rows.append(self._table_model.getDataVector().elementAt(i))
            else:
                untested_rows.append(self._table_model.getDataVector().elementAt(i))
        self._table_model.setRowCount(0)
        for row in tested_rows + untested_rows:
            self._table_model.addRow(row)

    def find_api(self, event):
        search_text = self._filter_text.text.strip()
        if not search_text:
            return
        api_row = -1
        for row in range(self._table_model.getRowCount()):
            method = self._table_model.getValueAt(row, 0)
            api = self._table_model.getValueAt(row, 1)
            if method == search_text or api == search_text:
                api_row = row
                break
        if api_row != -1:
            self._table.setRowSelectionInterval(api_row, api_row)
            self._table.scrollRectToVisible(self._table.getCellRect(api_row, 0, True))
        else:
            self._table.clearSelection()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            http_service = messageInfo.getHttpService()
            request = messageInfo.getRequest()
            analyzed_request = self._helpers.analyzeRequest(http_service, request)
            url = analyzed_request.getUrl().toString()
            found_api = False
            api_row = None
            for row in range(self._table_model.getRowCount()):
                api = self._table_model.getValueAt(row, 1)
                method = self._table_model.getValueAt(row, 0)
                if self._precise_match_button.isSelected():
                    if api == url:
                        api_row = row
                        found_api = True
                        break
                else:
                    if api in url:
                        api_row = row
                        found_api = True
                        break
            if found_api:
                tested = self._table_model.getValueAt(api_row, 3)
                comment = self._table_model.getValueAt(api_row, 2)
                if messageInfo.getComment() and messageInfo.getComment() != comment:
                    self._table_model.setValueAt(messageInfo.getComment(), api_row, 2)
                    comment = messageInfo.getComment()
                messageInfo.setComment(comment if comment else "Under Test")
                messageInfo.setHighlight("green" if tested else "yellow")
                messageInfo.setResponse(messageInfo.getResponse())

