from burp import IBurpExtender, IProxyListener, ITab
from javax.swing import JPanel, JTextArea, JScrollPane, JTable, JButton, BorderFactory, BoxLayout, SwingConstants
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer


info='''author:flechazo\nhttps://github.com/Flechzao/API-Highlighter'''
print(info)


class CustomTableModel(DefaultTableModel):
    def getColumnClass(self, columnIndex):
        return str


class CenterRenderer(DefaultTableCellRenderer):
    def __init__(self):
        super(CenterRenderer, self).__init__()
        self.setHorizontalAlignment(SwingConstants.CENTER)


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
        column_model = self._table.getColumnModel()
        center_renderer = CenterRenderer()
        column_model.getColumn(0).setMaxWidth(90)
        column_model.getColumn(3).setCellRenderer(center_renderer)
        column_model.getColumn(3).setMaxWidth(75)
        self._table.setRowHeight(25)
        self._main_panel.add(JScrollPane(self._table))
        self._remove_button = JButton("Remove API", actionPerformed=self.remove_api)
        self._main_panel.add(self._remove_button)

    def getUiComponent(self):
        return self._main_panel

    def getTabCaption(self):
        return "API Highlighter"

    def import_apis(self, event):
        api_lines = self._text_area.text.splitlines()
        http_methods = ["POST", "GET", "DELETE", "PUT", "post", "get", "delete", "put"]

        for api_line in api_lines:
            method = None
            api = None
            for http_method in http_methods:
                if api_line.upper().startswith(http_method):
                    method = api_line[:len(http_method)].strip()
                    api = api_line[len(http_method):].strip()
                    break
            if not api:
                api = api_line.strip()
            if not self.api_exists(api):
                self._table_model.addRow([method, api, "", "n"])

    def api_exists(self, api):
        for row in range(self._table_model.getRowCount()):
            if self._table_model.getValueAt(row, 1) == api:
                return True
        return False

    def remove_api(self, event):
        selected_row = self._table.getSelectedRow()
        if selected_row != -1:
            self._table_model.removeRow(selected_row)

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
                    message_info.setHighlight("green" if tested.lower() == "y" else "yellow")
                    message_info.setComment(comment if comment else "Under Test")
                    break


def create_instance():
    return BurpExtender()
