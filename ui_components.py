from javax.swing import (JPanel, JTextArea, JScrollPane, JTable, JButton, BorderFactory, BoxLayout, SwingConstants, AbstractCellEditor, JCheckBox, Box, JTextField)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableCellEditor
from java.awt.event import ActionListener
from javax.swing import DefaultCellEditor
from java.lang import Boolean


class CustomTableModel(DefaultTableModel):
    def __init__(self, column_names, row_count):
        super(CustomTableModel, self).__init__(column_names, row_count)
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

class CheckBoxEditor(TableCellEditor, ActionListener, AbstractCellEditor):
    # def __init__(self):
    #     self.checkbox = JCheckBox()
    #     self.checkbox.setHorizontalAlignment(SwingConstants.CENTER)

    def __init__(self):
        super(CheckBoxEditor, self).__init__()
        self.check_box = JCheckBox()

    def getTableCellEditorComponent(self, table, value, isSelected, row, column):
        self.check_box.setSelected(value)
        return self.check_box

    def getCellEditorValue(self):
        return self.check_box.isSelected()

    def isCellEditable(self, event):
        return True

    def shouldSelectCell(self, event):
        return True

class ChineseTextEditor(DefaultCellEditor):
    def __init__(self):
        super(ChineseTextEditor, self).__init__(JTextField())
