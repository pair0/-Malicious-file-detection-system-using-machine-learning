import sys
import datetime
import subprocess
from time import localtime, strftime
import datetime
import os

t_date=strftime("%y-%m-%d %H:%M:%S", localtime())

d_file='/root/다운로드/'
files=os.listdir(d_file)
now = datetime.datetime.now()
print ('현재시간: ' ,now)

exe_down = 1
while(exe_down):
    #now = datetime.datetime.now()
    for i in range(0,len(files)):
        if(now>datetime.datetime.fromtimestamp(os.path.getmtime(d_file+files[i]))):
            exe_down=0
            count=i

'''
for i in range(0,len(files)):
    for j in range(0,len(files)):
        if datetime.datetime.fromtimestamp(os.path.getmtime(d_file+files[i]))>\
            datetime.datetime.fromtimestamp(os.path.getmtime(d_file+files[j])):
            (files[i], files[j])=(files[j], files[i])
            '''
#exe_down = 1;

#while(exe_down):
#    for i in range(0,len(files)):
#        if(now==datetime.datetime.fromtimestamp(os.path.getmtime(d_file+files[i]))):
#            exe_down = 0;
#            count = i;


most_recent_file=d_file+files[count]
print('가장 최근 파일: ',most_recent_file)
print('\n')

'''
#파일 특징 추출  
res = subprocess.check_output("cd /Manalyze/bin/ && ./manalyze --hash "+d_file+""+most_recent_file+" | grep SHA256 | awk '{print $2}'", shell=True)
print(type(res))

#타이틀의 공백을 제거합니다.
title = "SHA256".split(" ")
print(type(title))

#저장할 파일명과 인코딩 타입을 알려준다.
csvf = open('data.csv', "w", encoding="utf-8-sig")

#csv 파일로 쓰기 위해 함수를 실행
w=csv.writer(csvf)
data = res
print(data)
w.writerow(title)
w.writerow(data)
'''
