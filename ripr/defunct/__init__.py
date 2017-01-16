"""
Defunct <defunct<at>defunct.io> - NOP Developments LLC. 2016

MIT License

Copyright (c) <2016> <NOP Developments LLC>                                                                                         

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from PyQt5 import QtWidgets
from widgets import BinjaDockWidget


def instance():
    app = QtWidgets.QApplication.instance()
    main_window = [x for x in app.allWidgets() if x.__class__ is QtWidgets.QMainWindow][0]
    try:
        dock = [x for x in main_window.children() if x.__class__ is BinjaDockWidget][0]
    except:
        dock = BinjaDockWidget()

    return dock

