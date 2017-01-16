'''
    UI Functionality should be implemented here.
'''
import sys
if (sys.platform == 'win32'):
    sys.path.append("C:\\Python27\\lib\\site-packages")

from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtCore import Qt

from defunct.widgets import BinjaWidget
import defunct.widgets
from binaryninja import *

class MultiChoiceBox(QtWidgets.QDialog):
    def __init__(self, msg, parent=None):
        super(MultiChoiceBox, self).__init__(parent)

        msgBox = QtWidgets.QMessageBox()
        msgBox.setText(msg)
        msgBox.addButton(QtWidgets.QPushButton('Nop Out Calls'), QtWidgets.QMessageBox.YesRole)
        msgBox.addButton(QtWidgets.QPushButton('Hook Calls'), QtWidgets.QMessageBox.NoRole)
        msgBox.addButton(QtWidgets.QPushButton('Cancel Packaging'), QtWidgets.QMessageBox.RejectRole)
        self.ret = msgBox.exec_()
       
    def getResp(self):
        print self.ret
        if (self.ret == 0):
            return 'nop'
        elif (self.ret == 1):
            return 'hook'
        else:
            return 'cancel'
        
class riprTable(QtWidgets.QTableWidget):
    '''
        Handle all QTable related code here to keep the main GUI
        class relatively clean.
    '''
    def __init__(self, emuchunks, parent=None):
        super(riprTable, self).__init__()
        self.setContextMenuPolicy(Qt.DefaultContextMenu)
        self.emuchunks = emuchunks
        
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(['Name', 'Start Address', 'End Address'])
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setVisible(False)
    
    def _get_selected_codeobj(self):
        '''
            selectedIndexes returns a QModelIndex that is passed to the QtreeWidget
            which we get the QTreeWidgetItem from, which finally gets us the class name,
            which we can get the codeobj from.
        '''
         # Grab the "Index" that is selected
        item = self.triggeredIndex
        # Find the Class name from the index
        name = self.item(item.row(), item.column()).text()
        # Open the Editor
        print "Selected Codeobj: %s" % name
        return self.emuchunks[name]

    def contextMenuEvent(self, event):
        index = self.indexAt(event.pos())
        
        self.triggeredIndex = index
        menu = QtWidgets.QMenu()
        menu.addAction("Save to File", self._saveCode)
        menu.addAction("Map Address", self._addMmap)
        menu.exec_(event.globalPos())

    def _addMmap(self):
        codeobj = self._get_selected_codeobj()
        addr = QtWidgets.QInputDialog().getText(self, "Binary Ninja - ripr", "Enter Address (hex)")
        try:
            addr = int(addr[0], 16)
        except: # Show error
            print "[error]"
            return 
        codeobj.add_mmap(addr)

    def _addData(self):
        pass

    def _saveCode(self):
        codeobj = self._get_selected_codeobj()
        dialog = QtWidgets.QFileDialog(None, None)
        dialog.setFileMode(QtWidgets.QFileDialog.AnyFile)
        if dialog.exec_():
            fileNames = dialog.selectedFiles()
            if len(fileNames) > 0:
                f = open(fileNames[0], 'wb')
                f.write(codeobj.final)
                f.close() 

class riprWidget(BinjaWidget):
    '''
        riprWidget uses BinjaDock to display its essential information.
        "Helper" Functions are also defined here for simplicity
    '''
    def __init__(self, emuchunks=None):
        super(riprWidget, self).__init__('ripr')
        self.emuchunks = emuchunks
        self._table = riprTable(emuchunks=emuchunks)

        self.setLayout(QtWidgets.QStackedLayout())
        self.layout().addWidget(self._table)
        self.setObjectName('BNPlugin_ripr')

    def update_table(self, emuchunks):
        '''
            This function updates the table with new code objects received from the packager
            at the end of a "ripping" process.
        '''
        self._table.setRowCount(len(emuchunks))
        self._table.emuchunks = emuchunks
        row = 0
        for chunkName in emuchunks:
            nameField =  QtWidgets.QTableWidgetItem(chunkName)
            nameField.setFlags(Qt.ItemIsEnabled)

            startAddr = QtWidgets.QTableWidgetItem('0x%.8x' % emuchunks[chunkName].startaddr)
            startAddr.setFlags(Qt.ItemIsEnabled)

            endAddr = QtWidgets.QTableWidgetItem('0x%.8x' % (int(emuchunks[chunkName].startaddr) + int(emuchunks[chunkName].codelen)))
            endAddr.setFlags(Qt.ItemIsEnabled)
            
            self._table.setItem(row, 0, nameField)
            self._table.setItem(row, 1, startAddr)
            self._table.setItem(row, 2, endAddr)
            row += 1
        
        self._core.show()
        self._core.selectTab(self)
        self.show()


    ### Convenience wrappers for some frequently used things
    def yes_no_box(self, msg):
        choice = QtWidgets.QMessageBox.question(self, "Binary Ninja - ripr", msg, QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
        if (choice == QtWidgets.QMessageBox.Yes):
            return True
        return False

    def text_input_box(self,msg):
        text, ok = QtWidgets.QInputDialog.getText(self, "Binary Ninja - ripr", msg)
        if (ok):
            return text
        return ''

    def impCallsOptions(self):
        x = MultiChoiceBox(msg="Code contains calls to imported functions. How should this be handled?")
        return x.getResp()
