import sys
import os
import subprocess
import pefile
import array
import math
import pickle
import joblib
import sys
import argparse
from itertools import starmap
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QCoreApplication
file_name = sys.argv[1]

class QPushButton(QPushButton): #버튼 layout
    def __init__(self, parent = None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

class QTextEdit(QTextEdit):
    def __init__(self, parent = None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

class MyApp(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        ###프로그램 로고/이름
        self.setWindowTitle('악성파일 탐지 시스템')
        self.setWindowIcon(QIcon('logo.png'))

        ###self 변수 할당
        self.count_file = 0
        self.count_dir = 0
        self.count_unknow = 0
        self.file_unknow = None
        self.unknow_file = []

        ###main_layout 생성/각 위젯 및 버튼을 배치할 layout 생성
        main_layout = QVBoxLayout()
        layout_file = QVBoxLayout()
        layout_rm_cancel = QHBoxLayout()

        ###악성파일 목록 출력을 위한 textEdit 위젯 생성 및 버튼 생성
        self.textEdit = QTextEdit() #파일 목록 출력용 textEdit
        unknowButton = QPushButton('동적분석') #동적분석하기 버튼 생성
        rmunknowButton = QPushButton('알려지지 않은 파일 삭제하기') #알려지지 않은 파일 삭제
        rmButton = QPushButton('악성 파일 삭제하기') #삭제하기 버튼 생성
        cancelButton = QPushButton('취소') #취소 버튼 생성

        ###학습모델 불러오기
        clf = joblib.load('/manalyze_de/classifier.pkl')
        features = pickle.loads(open(os.path.join('/manalyze_de/features.pkl'),'rb').read())

        ###파일 검사
        if '.' in str(os.path.basename(file_name)):
            #변수 초기화
            self.count_file = 0
            self.count_unknow = 0
            self.file_name = None
            self.file_unknow = None
            pe_features = []
            j=0

            self.textEdit.setText("파일 검사 결과")
            data = self.extract_infos(file_name)
            for j in range(len(list(data))):
                for i in features:
                    if i == list(data)[j]:
                        pe_features.append(data[list(data)[j]])
            #pe_features = list(map(lambda x:data[x], features))
            '''
            for i in pe_features:
                if j == 0:
                    self.textEdit.setText(str(i))
                    j += 1
                else:
                    self.textEdit.append(str(i))
            '''
            res= clf.predict_proba([pe_features])[0]    
            self.textEdit.append(str(res))

            if res[0] > 0.62:
                self.textEdit.append(file_name+"은 악성파일 입니다.")
                self.file_name = file_name
                self.count_file += 1
            elif res[1] > 0.62:
                self.textEdit.append(file_name+"은 정상 입니다.")
            else:
                self.textEdit.append(file_name+"은 알려지지 않은 파일 입니다. 동적분석을 권장드립니다.")
                self.count_unknow += 1
                self.file_unknow = file_name

        ###폴더 검사
        else:
            #변수 초기화
            self.count_dir = 0
            self.count_unknow = 0
            file_path = []
            self.malware_file = []
            self.unknow_file = []
            pe_features = []

            self.textEdit.setText(str(file_name)+" 폴더 내 파일 검사 결과")
            ###폴더 안 파일 추출
            for (root, directories, files) in os.walk(file_name):
                for file in files:
                    if '.exe' in file:
                        file_path.append(os.path.join(root, file))

            ###폴더 내 파일 검사
            if len(file_path) != 0:
                for i in file_path:
                    pe_features = []
                    data = self.extract_infos(i)
                    for j in range(len(list(data))):
                        for i in features:
                            if i == list(data)[j]:
                                pe_features.append(data[list(data)[j]])
                    #pe_features = list(map(lambda x:data[x], features))
                    res = clf.predict_proba([pe_features])[0]
                    if res[0] > 0.62:
                        self.malware_file.append(i)
                        self.count_dir += 1
                    elif res[0] < 0.62 and res[1] < 0.62:
                        self.unknow_file.append(i)
                        self.count_unknow += 1
                
                self.textEdit.append("전체 파일 개수 : {}, 정상 파일 개수 : {}, 악성 파일 개수 : {}, 알려지지 않은 파일 개수 : {}".format(len(file_path), len(file_path)-self.count_dir-self.count_unknow, self.count_dir, self.count_unknow))
                
                if self.count_dir > 0:
                    self.textEdit.append("-------------------------------------------------------------------------------------------")
                    self.textEdit.append("악성파일 종류")
                    for i in self.malware_file:
                        self.textEdit.append("악성파일 : "+i)
                    self.textEdit.append("악성파일의 개수는 총 "+str(self.count_dir)+"개 입니다.")
                if self.count_unknow > 0:
                    self.textEdit.append("-------------------------------------------------------------------------------------------")
                    self.textEdit.append("알려지지 않은 파일 종류")
                    for i in self.unknow_file:
                        self.textEdit.append("알려지지 않은 파일 : "+i)
                    self.textEdit.append("알려져져 않은 파일의 개수는 총 "+str(self.count_unknow)+"개 입니다.")
                if self.count_dir == 0 and self.count_unknow == 0:
                    self.textEdit.append("-------------------------------------------------------------------------------------------")
                    self.textEdit.append("모두 정상 파일입니다.")
                self.textEdit.append("-------------------------------------------------------------------------------------------")

            else:
                QMessageBox.about(self, "Warning", "폴더 안에 실행파일이 존재하지  않습니다.")
                sys.exit()

        ###layout_에 위젯/버튼을 추가
        if self.count_unknow > 0:
            layout_rm_cancel.addWidget(unknowButton)
            layout_rm_cancel.addWidget(rmunknowButton)
        layout_rm_cancel.addWidget(rmButton)
        layout_rm_cancel.addWidget(cancelButton)
        layout_file.addWidget(self.textEdit, 9)
        layout_file.addLayout(layout_rm_cancel, 1)

        ###버튼 클릭 시 시그널 설정
        if self.count_unknow > 0:
            unknowButton.clicked.connect(self.dynamic_analysis)
            rmunknowButton.clicked.connect(self.remove_unknowfile)
        rmButton.clicked.connect(self.remove_file)
        cancelButton.clicked.connect(QCoreApplication.instance().quit)

        ###버튼 layout 설정
        main_layout.addLayout(layout_file, stretch=1)
        self.setLayout(main_layout)

        
        ###화면 크기와 화면 띄우기
        self.setGeometry(300, 300, 800, 400)
        self.center() #창을 화면 가운데로 띄우기
        self.show()
        
    ###
    def get_entropy(self, data):
        if len(data) == 0:
            return 0.0
        occurences = array.array('L', [0]*256)
        for x in data:
            occurences[x if isinstance(x, int) else ord(x)] += 1

        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x*math.log(p_x, 2)

        return entropy

    def get_resources(self, pe):
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    size = resource_lang.data.struct.Size
                                    entropy = self.get_entropy(data)
                                    resources.append([entropy, size])
            except Exception as e:
                return resources
        return resources

    def get_version_info(self, pe):
        res = {}
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        res[entry[0]] = entry[1]
            if fileinfo.Key == 'VarFileInfo':
                for var in fileinfo.Var:
                    res[var.entry.items()[0][0]] = var.entry.items()[0][1]
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
            res['os'] = pe.VS_FIXEDFILEINFO.FileOS
            res['type'] = pe.VS_FIXEDFILEINFO.FileType
            res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
            res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
            res['signature'] = pe.VS_FIXEDFILEINFO.Signature
            res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
        return res

    def extract_infos(self, fpath):
        res = {}
        pe = pefile.PE(fpath)
        res['Machine'] = pe.FILE_HEADER.Machine
        res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        res['Characteristics'] = pe.FILE_HEADER.Characteristics
        res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        try:
            res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
        except AttributeError:
            res['BaseOfData'] = 0
        res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
        res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

        # Sections
        res['SectionsNb'] = len(pe.sections)
        entropy = list(map(lambda x:x.get_entropy(), pe.sections))
        res['SectionsMeanEntropy'] = sum(entropy)/float(len(entropy))
        res['SectionsMinEntropy'] = min(entropy)
        res['SectionsMaxEntropy'] = max(entropy)
        raw_sizes = list(map(lambda x:x.SizeOfRawData, pe.sections))
        res['SectionsMeanRawsize'] = sum(raw_sizes)/float(len(raw_sizes))
        res['SectionsMinRawsize'] = min(raw_sizes)
        res['SectionsMaxRawsize'] = max(raw_sizes)
        virtual_sizes = list(map(lambda x:x.Misc_VirtualSize, pe.sections))
        res['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))
        res['SectionsMinVirtualsize'] = min(virtual_sizes)
        res['SectionMaxVirtualsize'] = max(virtual_sizes)

        #Imports
        try:
            res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
            res['ImportsNb'] = len(imports)
            #res['ImportsNbOrdinal'] = len(filter(lambda x:x.name is None, imports))
        except AttributeError:
            res['ImportsNbDLL'] = 0
            res['ImportsNb'] = 0
            res['ImportsNbOrdinal'] = 0

        #Exports
        try:
            res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except AttributeError:
            # No export
            res['ExportNb'] = 0

        #Resources
        resources= self.get_resources(pe)
        res['ResourcesNb'] = len(resources)
        if len(resources)> 0:
            entropy = list(map(lambda x:x[0], resources))
            res['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))
            res['ResourcesMinEntropy'] = min(entropy)
            res['ResourcesMaxEntropy'] = max(entropy)
            sizes = list(map(lambda x:x[1], resources))
            res['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
            res['ResourcesMinSize'] = min(sizes)
            res['ResourcesMaxSize'] = max(sizes)
        else:
            res['ResourcesNb'] = 0
            res['ResourcesMeanEntropy'] = 0
            res['ResourcesMinEntropy'] = 0
            res['ResourcesMaxEntropy'] = 0
            res['ResourcesMeanSize'] = 0
            res['ResourcesMinSize'] = 0
            res['ResourcesMaxSize'] = 0

        # Load configuration size
        try:
            res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        except AttributeError:
            res['LoadConfigurationSize'] = 0


        # Version configuration size
        try:
            version_infos = self.get_version_info(pe)
            res['VersionInformationSize'] = len(version_infos.keys())
        except AttributeError:
            res['VersionInformationSize'] = 0
        return res


    ###악성파일 삭제(삭제하기 버튼 클릭 시)
    def remove_file(self):
        sucess = 0
        reply = QMessageBox.question(self, 'Message', '정말로 삭제하시겠습니까?', QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if reply == QMessageBox.Yes:
            if self.count_file == 1:
                subprocess.check_output("rm -r "+self.file_name, shell=True)
                QMessageBox.about(self, "Message", str(self.file_name)+" 악성 파일을 성공적으로 삭제하였습니다.")
                #sys.exit(0)
            elif self.count_dir > 0:
                for i in self.malware_file:
                    subprocess.check_output("rm -r "+i, shell=True)
                    sucess += 1
                QMessageBox.about(self, "Message", "총 "+str(sucess)+"개의 악성 파일을 삭제하였습니다.")
                #sys.exit(0)
            else:
                QMessageBox.about(self, "Message", "악성파일이 존재하지 않습니다.")
        #elif reply == QMessageBox.No:

    ###알려지지 않은 파일 동적분석(동적분석 버튼 클릭 시)
    def dynamic_analysis(self):
        reply1 = QMessageBox.question(self, 'Message', '동적분석을 하시겠습니까?', QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if reply1 == QMessageBox.Yes:
            subprocess.check_output("sleep 3", shell=True)
            subprocess.check_output("gnome-terminal --tab -e \"cuckoo community\" --tab -e \"vboxmanage startvm cuckoo1\" --tab -e \"cuckoo\"", shell=True)
            subprocess.check_output("sleep 20", shell=True)
            subprocess.check_output("gnome-terminal --tab -e \"cuckoo web runserver 0.0.0.0:8000\"", shell=True)
            subprocess.check_output("sleep 30", shell=True)
            if self.file_unknow != None:
                subprocess.check_output("cd /manalyze_de && python3 web.py "+self.file_unknow, shell=True)
            elif len(self.unknow_file) > 0:
                subprocess.check_output("cd /manalyze_de && python3 web.py "+self.unknow_file[0], shell=True)

    ###알려지지 않은 파일  삭제(알려지지 않은 파일 삭제하기 버튼 클릭 시)
    def remove_unknowfile(self):
        sucess = 0
        reply = QMessageBox.question(self, 'Message', '정말로 삭제하시겠습니까?', QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if reply == QMessageBox.Yes:
            if self.count_unknow == 1:
                subprocess.check_output("rm -r "+self.file_unknow, shell=True)
                QMessageBox.about(self, "Message", str(self.file_unknow)+" 알려지지 않은파일을 성공적으로 삭제하였습니다.")
                #sys.exit(0)
            elif self.count_dir > 0:
                for i in self.unknow_file:
                    subprocess.check_output("rm -r "+i, shell=True)
                    sucess += 1
                QMessageBox.about(self, "Message", "총 "+str(sucess)+"개의 알려지지 않은 파일을 삭제하였습니다.")
                #sys.exit(0)
            else:
                QMessageBox.about(self, "Message", "악성파일이 존재하지 않습니다.")
        #elif reply == QMessageBox.No:

        


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
