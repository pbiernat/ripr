'''
    UI Functionality is implemented here.
'''
import sys
if (sys.platform == 'win32'):
    sys.path.append("C:\\Python27\\lib\\site-packages")
try:
    from PyQt5 import QtWidgets, QtGui, QtCore
    from PyQt5.QtCore import Qt
    from defunct.widgets import BinjaWidget
    import defunct.widgets
    qtAvailable = True
except:
    qtAvailable = False

from binaryninja import *

try:
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
except:
    pass

try:
    class riprWidget(BinjaWidget):
        '''
            riprWidget uses BinjaDock to display its essential information.
            "Helper" Functions are also defined here for simplicity
        '''
        def __init__(self, emuchunks=None):
            self.qtAvailable = qtAvailable
            if not qtAvailable:
                return
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
            if (not self.qtAvailable):
                return
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
        def save_file(self, codeobj):
            fname = interaction.get_save_filename_input("[ripr] Save output")
            if fname == None:
                return
            f = open(fname, "w+")
            f.write(codeobj.final)
            f.close()
    
    
        def yes_no_box(self, msg):
            choice = interaction.show_message_box("Binary Ninja - ripr", msg, enums.MessageBoxButtonSet.YesNoButtonSet)
            if choice == enums.MessageBoxButtonResult.YesButton:
                return True
            return False

        def msgBox(self, msg):
            interaction.show_message_box("Binary Ninja - ripr", msg, enums.MessageBoxButtonSet.OKButtonSet)

    
        def text_input_box(self,msg):
            text = interaction.get_text_line_input(msg, "Binary Ninja - ripr")
            return text
    
        def impCallsOptions(self):
            msg="Code contains calls to imported functions. How should this be handled?"
            choice = interaction.get_choice_input(msg, "", ["Hook Calls", "Nop Out Calls", "Cancel"])
            if choice == 0:
                return "hook"
            if choice == 1:
                return "nop"
            if choice == 2:
                return "cancel"
except:
    # TODO Clean up/remove duplicated code
    class riprWidget(object):
        def __init__(self):
            self.qtAvailable = False
            return
        
        def update_table(self, emuchunks):
            return
        
        def save_file(self, codeobj):
            fname = interaction.get_save_filename_input("[ripr] Save output")
            if fname == None:
                return
            f = open(fname, "w+")
            f.write(codeobj.final)
            f.close()
        
        def yes_no_box(self, msg):
            choice = interaction.show_message_box("Binary Ninja - ripr", msg, enums.MessageBoxButtonSet.YesNoButtonSet)
            if choice == enums.MessageBoxButtonResult.YesButton:
                return True
            return False
    
        def text_input_box(self,msg):
            text = interaction.get_text_line_input(msg, "Binary Ninja - ripr")
            return text
    
        def impCallsOptions(self):
            msg="Code contains calls to imported functions. How should this be handled?"
            choice = interaction.get_choice_input(msg, "", ["Hook Calls", "Nop Out Calls", "Cancel"])
            if choice == 0:
                return "hook"
            if choice == 1:
                return "nop"
            if choice == 2:
                return "cancel"
    pass
