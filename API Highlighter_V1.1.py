from burp import IBurpExtender, IProxyListener, ITab
from java.lang import Boolean
from javax.swing import JPanel, JTextArea, JScrollPane, JTable, JButton, BorderFactory, BoxLayout, SwingConstants, JCheckBox
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableCellEditor
from java.awt import Component, GridLayout
from java.awt.event import ActionListener

info='''author:flechazo\nhttps://github.com/Flechzao/API-Highlighter'''
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

class BurpExtender(IBurpExtender, IProxyListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("API Highlighter")
        callbacks.registerProxyListener(self)
        self.init_ui()
        callbacks.addSuiteTab(self)

    def init_ui(self):
        self._main_panel = JPanel()
        self._main_panel.layout = BoxLayout(self._main_panel, BoxLayout.Y_AXIS)
        self._text_area = JTextArea(10, 30)
        self._text_area.border = BorderFactory.createTitledBorder("Batch import APIs")
        self._main_panel.add(JScrollPane(self._text_area))
        self._import_button = JButton("Import APIs", actionPerformed=self.import_apis)
        self._main_panel.add(self._import_button)
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

    def getUiComponent(self):
        return self._main_panel

    def getTabCaption(self):
        return "API Highlighter"

    def import_apis(self, event):
        api_lines = self._text_area.text.splitlines()
        http_methods = ["POST", "GET", "DELETE", "PUT"]
        for api_line in api_lines:
            method = None
            api = None
            for http_method in http_methods:
                if api_line.upper().startswith(http_method):
                    method = http_method
                    api = api_line[len(http_method):].strip()
                    break
            if not api:
                api = api_line.strip()
            if not self.api_exists(api):
                self._table_model.addRow([method, api, "", False])

    def api_exists(self, api):
        for row in range(self._table_model.getRowCount()):
            if self._table_model.getValueAt(row, 1) == api:
                return True
        return False

    def remove_api(self, event):
        selected_rows = self._table.getSelectedRows()
        for row in reversed(selected_rows):
            self._table_model.removeRow(row)

    def toggle_tested(self, event):
        selected_rows = self._table.getSelectedRows()
        for row in selected_rows:
            current_value = self._table_model.getValueAt(row, 3)
            self._table_model.setValueAt(not current_value, row, 3)

    def move_tested_to_top(self, event):
        tested_rows_indices = [index for index in range(self._table_model.getRowCount()) if self._table_model.getValueAt(index, 3)]
        for index in reversed(tested_rows_indices):
            tested_row = self._table_model.getDataVector().elementAt(index)
            self._table_model.removeRow(index)
            self._table_model.insertRow(0, tested_row)

    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest:
            message_info = message.getMessageInfo()
            http_service = message_info.getHttpService()
            request = message_info.getRequest()
            analyzed_request = self._helpers.analyzeRequest(http_service, request)
            url = analyzed_request.getUrl().toString()
            for row in range(self._table_model.getRowCount()):
                api = self._table_model.getValueAt(row, 1)
                tested = self._table_model.getValueAt(row, 3)
                comment = self._table_model.getValueAt(row, 2)
                if api in url:
                    message_info.setHighlight("green" if tested else "yellow")
                    message_info.setComment(comment if comment else "Under Test")
                    break

def create_instance():
    return BurpExtender()
