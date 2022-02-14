import sys
import subprocess
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon

class QPushButton(QPushButton): #버튼 layout
    def __init__(self, parent = None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

class MyApp(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        ###프로그램 로고/이름
        self.setWindowTitle('악성파일 탐지 프로그램')
        self.setWindowIcon(QIcon('logo.png'))
       
        ###main_layout 생성/각 버튼을 배치할 layout 생성
        main_layout = QVBoxLayout()
        layout_funtion = QHBoxLayout()

        ###버튼 생성
        normalButton = QPushButton('악성파일 검사')
        timeButton = QPushButton('실시간 악성파일 검사')
        
        ###layout에 위젯/버튼을 추가
        layout_funtion.addWidget(normalButton)
        layout_funtion.addWidget(timeButton)

        ###버튼 클릭 시 시그널 설정
        normalButton.clicked.connect(self.normalButton_clicked)
        timeButton.clicked.connect(self.timeButton_clicked)

        ###버튼 layout 설정
        main_layout.addLayout(layout_funtion, stretch=1)
        self.setLayout(main_layout)

        ###화면 크기와 화면 띄우기
        self.setGeometry(300, 300, 800, 400)
        self.center() #창을 화면 가운데로 띄우기
        self.show()

    ###악성파일 검사 모드
    def normalButton_clicked(self):
        subprocess.check_output("cd /manalyze_de/ && python manalyze_de1.py", shell=True)

    ###실시간 악성파일 검사 모드
    def timeButton_clicked(self):
        subprocess.check_output("cd /manalyze_de/ && python manalyze_de2.py", shell=True)

    #창을 화면 가운데로 띄우기 메소드
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())
 
if __name__ == '__main__':
   app = QApplication(sys.argv)
   ex = MyApp()
   sys.exit(app.exec_())
