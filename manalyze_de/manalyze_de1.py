import sys
import os
import subprocess
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QCoreApplication

class QPushButton(QPushButton): #버튼 layout
    def __init__(self, parent = None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
class QLabel(QLabel):
    def __init__(self, parent = None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

class QLineEdit(QLineEdit):
    def __init__(self, parent = None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
class MyApp(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        ###프로그램 로고/이름
        self.setWindowTitle('악성파일 검사')
        self.setWindowIcon(QIcon('logo.png'))
        
        ###main_layout 생성/각 위젯및 버튼을 배치할 layout 생성
        main_layout = QVBoxLayout() 
        layout_file_found = QHBoxLayout()
        layout_file_dir = QVBoxLayout()
        layout_ok_cancel = QHBoxLayout()
        
        ###경로 출력을 위한 LineEdit 위젯 생성 및 버튼 생성
        label_file = QLabel("Path: ") # Lable 생성
        self.file = QLineEdit("") #경로를 띄워주는 창 생성
        fileButton = QPushButton('파일') #파일 찾기 버튼 생성
        dirButton = QPushButton('폴더') #폴더 찾기 버튼 생성
        okButton = QPushButton('검사하기') #검사하기 버튼 생성
        cancelButton = QPushButton('취소') #취소 버튼 생성
        
        ###layout_에 위젯/버튼을 추가
        layout_file_dir.addWidget(fileButton, 1)
        layout_file_dir.addWidget(dirButton, 1)
        layout_file_found.addWidget(label_file, 0.5)
        layout_file_found.addWidget(self.file, 5)
        layout_file_found.addLayout(layout_file_dir, 1)
        layout_ok_cancel.addWidget(okButton)
        layout_ok_cancel.addWidget(cancelButton)
        
        ###버튼 클릭 시 시그널 설정
        self.fname = 0
        self.fname_dir = 0
        fileButton.clicked.connect(self.fileopen)
        dirButton.clicked.connect(self.diropen)
        okButton.clicked.connect(self.upload_file)
        cancelButton.clicked.connect((QCoreApplication.instance().quit))     
        
        ###버튼 layout 설정
        main_layout.addLayout(layout_file_found, stretch=1)
        main_layout.addLayout(layout_ok_cancel, stretch=1)
        self.setLayout(main_layout)
	    
        ###화면 크기와 화면 띄우기
        self.setGeometry(300, 300, 800, 100)
        self.center() #창을 화면 가운데로 띄우기
        self.show()

    ###파일 경로 선택(파일 버튼 클릭 시)
    def fileopen(self):
        self.fname_dir = 0
        self.fname = QFileDialog.getOpenFileName(self, 'Open file', "", " exe Files(*.exe);; dll Files(*.dll)", '/')
        if self.fname[0]:
        	self.file.setText(self.fname[0])
        else:
        	QMessageBox.about(self, "Warning", "파일을 선택하지 않았습니다.")
    
    ###폴더 경로 선택(폴더 버튼 클릭 시)
    def diropen(self):
        self.fname = 0
        self.fname_dir = str(QFileDialog.getExistingDirectory(self, "Select Directory", '/'))
        if self.fname_dir:
        	self.file.setText(self.fname_dir)
        else:
        	QMessageBox.about(self, "Warning", "폴더를 선택하지 않았습니다.")

        print(self.fname_dir)
        
    ###선택한 파일 분석(검사하기 버튼 클릭 시)
    def upload_file(self):
        ###단일 파일 검사
        if self.fname != 0 and self.fname[0] != '':
            file_name = str(self.fname[0]) 
            subprocess.check_output("cd /manalyze_de/ && python manalyze_de1-1.py "+file_name, shell=True)
            #res = subprocess.check_output("cd /Manalyze/bin/ && ./manalyze --hash "+file_name+" | 			grep SHA256 | awk '{print $2}'", shell=True)
            #print(res)
            self.fname = 0
            sys.exit(0)

        ###폴더 내 파일 검사
        elif self.fname_dir != 0 and self.fname_dir != '':
            file_dir_name = self.fname_dir
            subprocess.check_output("cd /manalyze_de/ && python manalyze_de1-1.py "+file_dir_name, shell=True)
            self.fname_dir = 0

         ###단일 파일 또는 폴더 선택 X
        else:
            QMessageBox.about(self, "Warning", "파일 또는 폴더를 선택하지 않았습니다. 파일 또는 폴더를 선택하세요.")

    ###창을 화면 가운데로 띄우기 메소드
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

if __name__ == '__main__':
   app = QApplication(sys.argv)
   ex = MyApp()
   sys.exit(app.exec_())
