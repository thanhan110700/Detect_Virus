from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

import sys,time
import glob,re,os,csv
import rarfile
from zipfile import ZipFile
from hash_md5 import *
import patoolib
import shutil
safeLevel=100
path=""
class Stream(QObject):
    """Redirects console output to text widget."""
    newText = pyqtSignal(str)

    def write(self, text):
        self.newText.emit(str(text))
class ThreadWork(QThread):
    work_setPath = pyqtSignal(str)

    def run(self):
        self.work_setPath.emit(path)



class Window(QWidget):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.title = "Bảo mật"
        self.top = 100
        self.left = 100
        self.width = 600
        self.height = 400
        self.InitWindow()
        oImage = QImage("background.jpg")
        sImage = oImage.scaled(QSize(self.width, self.height))  # resize Image to widgets size
        palette = QPalette()
        palette.setBrush(QPalette.Window, QBrush(sImage))
        self.setPalette(palette)
        sys.stdout = Stream(newText=self.onUpdateText)
        self.label = QLabel('Test', self)  # test, if it's really backgroundimage
        self.label.setGeometry(50, 50, 200, 50)

    def InitWindow(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left,self.top,self.width,self.height)
        self.UiComponents()

        self.show()

    # method for widgets
    def UiComponents(self):

        v_main = QVBoxLayout()
        h_path = QHBoxLayout()

        #Input Path
        self.input_path = QLineEdit()
        self.input_path.setStyleSheet("Background-color:none;border: 1px solid white;border-radius:10px;height:30%;width:25%;color:black")

        #Button Path
        btn_open_path = QPushButton("Open",self)
        btn_open_path.setStyleSheet("Background-color:none;border: 1px solid white;border-radius:10px;height:30%;width:25%;color:white")
        btn_open_path.clicked.connect(self.open_file)

        #Progress bar
        lbl_pbar = QLabel("Mức độ an toàn")
        lbl_pbar.setStyleSheet("color:white")
        self.pbar = QProgressBar(self)
        self.pbar.setValue(0)
        self.pbar.setStyleSheet("QProgressBar"
                          "{"
                          "border: 1px solid white;"
                          "border-radius: 5px;"
                          " color: black; "
                          "text-align:center;"
                          "}"
                          "QProgressBar::chunk { "
                          "background-color: #05B8CC;"
                           "border-radius: 5px;"
                          "}")

        h_path.addWidget(self.input_path,5)
        h_path.addWidget(btn_open_path,1)

        #Result
        lbl_result = QLabel("Kết quả")
        lbl_result.setStyleSheet("color:white")

        self.result = QTextEdit()
        self.result.setStyleSheet("border:none;")
        self.result.setReadOnly(True)

        # self.result.ensureCursorVisible()
        # self.result.setLineWrapColumnOrWidth(500)
        # self.result.setLineWrapMode(QTextEdit.FixedPixelWidth)

        # self.result.move(30, 100)

        #set layout
        v_main.addLayout(h_path,2)
        v_main.addWidget(lbl_pbar,1)
        v_main.addWidget(self.pbar,2)
        v_main.addWidget(lbl_result, 1)
        v_main.addWidget(self.result,8)
        self.setLayout(v_main)

    def set_path(self,value):
        self.input_path.setText(value)
    def onUpdateText(self, text):
        """Write console output to text widget."""
        cursor = self.result.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        self.result.setTextCursor(cursor)
        self.result.ensureCursorVisible()
    def open_file(self):
        global path
        #get path file
        self.path = QFileDialog.getOpenFileName(filter="File (*.*)")[0]
        arr = [2, 3, 7, 9]
        if(self.path!=''):
            path=self.path

            self.set_safe_console()

            self.pathWork = ThreadWork()
            self.pathWork.start()
            self.pathWork.work_setPath.connect(self.set_path)

    def set_safe_console(self):
        global safeLevel
        prbval = self.run_all(self.path)

        # update progress

        for i in range(prbval + 1):
            # slowing down the loop
            time.sleep(0.001)
            # setting value to progress bar
            self.pbar.setValue(i)

        # append text to result
        safeLevel = 100
    def setvaluePrb(self,value):
        self.pbar.setValue(value)
    def checkExtension(self,path):
        global safeLevel

        extensionArray = [".exe", ".vbs", ".bat", ".pif", ".application", ".gadget", ".msi",
                          ".cpl", ".msc", ".bat",
                          ".cmd", ".vb", ".jse",
                          ".ws", ".wsf", ".wsc", ".lnk", ".inf", ".reg", ".scf"]

        fileName, fileExtension = os.path.splitext(path)
        fileExtension = fileExtension.lower()

        for e in extensionArray:
            if (e == fileExtension):

                print("\tContain " + os.path.basename(fileName) + "" + e)
                return 1

        return 0

    def checker_hash(self,path):
        global safeLevel

        virus_hash = list(open("hash_virus.txt", "r").read().split('\n'))
        virus_hash_info = list(open("virus_info.txt", "r").read().split('\n'))
        detectedVirus = 0
        hash_check = getHash(path)
        count = 0

        for hash in virus_hash:
            if (hash == hash_check):

                print("\tScan by hash file detected virus: " + virus_hash_info[count])
                detectedVirus = 1
                return 1
            count += 1

        if (detectedVirus == 0):

            print("\tFile " + os.path.basename(path) + " is clean")

    def detectForSignature(self,path):

        global safeLevel

        print("Start Scanning.....")

        fileName, fileExtension = os.path.splitext(path)
        fileExtension = fileExtension.lower()
        if (fileExtension == ".rar"):
            rf = rarfile.RarFile(path)
            for f in rf.infolist():
                print(f)
                file_ex = os.path.splitext(f.filename)
                file_ex = file_ex[1].lower()

        if (fileExtension == ".zip"):
            with ZipFile(path, 'r') as zipObj:
                listOfiles = zipObj.namelist()
                for elem in listOfiles:
                    thisFileDetected = False
                    file = open(elem, "r")
                    lines = file.readlines()
                    file.close()

                    for line in lines:
                        if (re.search("virus", line)):

                            print("virus found " + elem)
                            thisFileDetected = True
                    if (thisFileDetected == False):

                        print(elem + " File Clean")

        programs = glob.glob(path)
        for p in programs:

            thisFileDetected = False
            file = open(p, "r")
            lines = file.readlines()
            file.close()

            for line in lines:
                if (re.search("virus", line)):

                    print("virus found " + p)
                    thisFileDetected = True
            if (thisFileDetected == False):

                print(p + " File Clean")

        print("Safe")

    def getFileData(self,path):
        programs = glob.glob(path)
        programList = []
        for p in programs:
            programSize = os.path.getsize(p)
            programModified = os.path.getmtime(p)
            programData = [p, programSize, programModified]

            programList.append(programData)
        return programList

    def writeFileData(self,programs):
        with open("fileData.txt", "w") as file:
            wr = csv.writer(file)
            wr.writerows(programs)

    def detectForChange(self,path):

        with open("fileData.txt") as file:
            fileList = file.read().splitlines()
        originalFileList = []
        for each in fileList:
            items = each.split(',')
            originalFileList.append(items)

        currentFileList = self.getFileData(path)

        for c in currentFileList:
            for o in originalFileList:
                if (c[0] == o[0]):
                    if (str(c[1]) != str(o[1]) or str(c[2]) != str(o[2])):
                        print("\tFile " + os.path.basename(c[0]) + " appears to be change")
                        print("\tCurrent Value= " + str(c))
                        print("\tOriginal Value= " + str(o))
                        return 1
                    else:

                        print("\tFile " + os.path.basename(c[0]) + " appears to be unchange")
        os.remove("fileData.txt")

    ##########################################################
    def run_all(self,path):
        global safeLevel

        fileName, fileExtension = os.path.splitext(path)
        fileExtension = fileExtension.lower()

        if (fileExtension == ".zip" or fileExtension == ".rar"):
            patoolib.extract_archive(path, outdir=os.getcwd() + "\\fileArchive")
            path = os.getcwd() + "\\fileArchive"
            files = []
            countDetected = 0
            # r=root, d=directories, f = files
            for r, d, f in os.walk(path):
                for file in f:
                    files.append(os.path.join(r, file))

            print("Filter extension file....")
            for f in files:
                if (self.checkExtension(f) == 1):
                    countDetected += 1
            if (countDetected > 0):
                safeLevel = safeLevel - 10
                countDetected = 0

            print("Finish filter extension file....")

            print("Scan virus by hash file....")
            for f in files:
                if (self.checker_hash(f) == 1):
                    countDetected += 1
            if (countDetected > 0):
                safeLevel = safeLevel - 50
                countDetected = 0

            print("Finish scan virus by hash file....")

            print("Verify change file")
            for f in files:
                self.writeFileData(self.getFileData(f))
                if (self.detectForChange(f) == 1):
                    countDetected += 1
            if (countDetected > 0):
                safeLevel = safeLevel - 20
                countDetected = 0

            print("Finish detect change in files")

            shutil.rmtree(path)
        else:

            print("Filter extension file....")
            if (self.checkExtension(path) == 1):
                safeLevel = safeLevel - 10

            print("Finish filter extension file....")

            print("Scan virus by hash file....")
            if (self.checker_hash(path) == 1):
                safeLevel = safeLevel - 50

            print("Finish scan virus by hash file....")

            print("Verify change file")
            self.writeFileData(self.getFileData(path))
            if (self.detectForChange(path) == 1):
                safeLevel = safeLevel - 20

            print("Finish detect change in files\n##################################################")
        return safeLevel
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Window()
    sys.exit(app.exec_())