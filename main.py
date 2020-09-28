import webbrowser
import shodan
import time
import pyautogui
from PIL import ImageGrab
import pyautogui as pag
from itertools import product
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains

'''
out = open('output.txt','w',-1,"utf-8")
try:
    results = api.search('apache')
    print('Results found: {}'.format(results['total']))
    for result in results['matches']:
        print('IP: {}'.format(result['ip_str']))
        print('-----------')
    print(results, file=out)
except shodan.APIError as e:
    print('Error: {}'.format(e))
''' #파일로 출력하기


def get_shodan_api_key():
    SHODAN_API_KEY = "rNu7d26Vf49aGFBRLv2ZoWHLU0ndh3QN";  #세영
    api_key = shodan.Shodan(SHODAN_API_KEY);
    return api_key
def print_host_vulnerable_Info():
    print(
    """
    [[Host Vulnerable Information]]
    IP : {}
    Country : {}
    City : {}
    
    latitude : {}
    longitude : {}

    last_update : {}
    exposed ports count : {}
    exposed ports : {}
   \n
    """
    .format(host['ip_str'],
            host['country_name'],
            host['city'],
            host['latitude'],
            host['longitude'],
            host['last_update'],
            len(host['ports']),
            host['ports']
            )
    )
    #tags: host['tags']
def print_host_CVE_Info():
    total_CVE_NUM = 0
    print("======Vulnerabilities======")
    for item in host['data']:                                       #각각의 data[i]에서 vulns 정보 분리하기
        if 'vulns' in item: #CVE 정보가 있다면
            print("\nPort: {}" .format(item['port']))               #Port 번호 출력
            total_CVE_NUM +=len(item['vulns'])
            print("Vulns : {}" .format(len(item['vulns'])))         #CVE 갯수 출력
            for cve in (item['vulns']): print("{}".format(cve))     #CVE 목록 출력    #print("vulns : {}\n".format(item['vulns']))

        '''
        else: #CVE 정보가 없다면
            print("\ nPort: {}".format(item['port']))
            print("Vulns:NONE")
        '''
    # 최종 CVE 검사 결과 출력
    if total_CVE_NUM >= 1 :    #CVE가 1개라도 있다면
        print("\nVulnerability Checkout Result : total CVEs {}" .format(total_CVE_NUM))
        print("!Note: the device may not be impacted by all of these issues. The vulnerabilities are implied based on the software and version.")
    elif total_CVE_NUM == 0 :  #CVE가 1개도 없다면
        print("\nVulnerability Checkout Result : None")

def get_host_URL_Info():
    #각각의 data[i]에서 url,timestamp,shodan_module 정보 분리하기
    for item in host['data']:
        item_url="http://{}:{}".format(host['ip_str'],item['port'])
        item_timestamp = "{}".format(item['timestamp'])
        item_module="{}".format(item['_shodan'].get('module'))

        #http 프로토콜을 사용하는 data 분류하기  -> url_list_http
        if 'http' in item_module:
            http_url_list.append(item_url)

        # 각 요소를 리스트로
        url_list.append(item_url)
        moduel_list.append(item_module)
        timestamp_list.append(item_timestamp)
    http_url_list_Num=len(http_url_list)
    return http_url_list_Num
def print_host_URL_Info():
    '''
    # url_list 정보 출력하기
    url_list_Num = len(host['data'])
    print("[[ Host URL List Info ]]")
    print("url list count : {}" .format(url_list_Num))
    for i in range (0,url_list_Num):
        print(
        """
    URL {} : {} 
    moduel : {} 
    timestamp : {}
    """
        .format(i+1,url_list[i],moduel_list[i],timestamp_list[i])
    )
    '''
    # http-url_list 정보 출력하기
    print("\n[[ Host HTTP-URL List Info ]]")
    print("url_list_http_num : {}". format(http_url_list_Num))
    for i in range(0,http_url_list_Num) :
        print(http_url_list[i])
def open_http_url():
    for i in range(0,http_url_list_Num) :
        url = "{}".format(http_url_list[i])
        webbrowser.open(url)
        time.sleep(1)
        pag.click((970, 240))  # 사용자이름 좌표
        #pyautogui.typewrite(test1)  #ID를 입력한다
        time.sleep(1)
        pag.click((970, 280))  # 비밀번호 좌표
        pyautogui.typewrite(password)  # PW를 입력한다
        print("Log : HTTP-URL open success.\n")

def brute_force():
    """무차별 대입 공격을 통한 패스워드 해킹 시도"""
    count = 0
    tlist = []

    start_time = 0
    end_time = 0

    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*'  # 특수문자를 포함한 모든 char

    f = open("brute_force.txt", 'w')  # 쓰기모드로 brute_force.txt 파일 생성

    for length in range(1, 3):  # 주입할 문자열 최소, 최대 길이 조정. range(최소 길이, 최대 길이)
        # product() : 순열 조합 생성, (a,a)같은 중복 조합 허용, repeat으로 인자 설정!
        to_attempt = product(chars, repeat=length)  # char에서 length개 char를 뽑아서 순열 조합 생성, 리스트로 반환

        for attempt in to_attempt:  # 생성된 문자열 하나씩 파일에 쓰기
            brute = ''.join(attempt)  # join(): 리스트의 문자열 합치기
            f.write(brute + '\n')

    with open("brute_force.txt", 'rt') as file:
        tlist = file.read()
        for _ in tlist:
            if _ == '\n':
                count += 1
    print("문자열 개수:", count)

    # readlines 함수를 통해 파일의 모든 줄을 읽어서 각각의 줄을 요소로 갖는 리스트를 돌려준다.
    with open("brute_force.txt", 'r') as file:
        start_time = time.time()  # 처리 전 시간
        for line in file:  # for에 파일 객체를 지정하면 파일의 내용을 한 줄씩 읽어서 변수에 저장함
            if (line.strip('\n') == password):
                # print("일치하는 게 존재한다.")
                break
        end_time = time.time()  # 처리 후 시간
        # else:
        # print("일치하는 게 존재하지 않는다.")

        elapsed_time = end_time - start_time

    print('\n처리시간:', elapsed_time)

    if (elapsed_time > effective_time):
        print('\n무차별 대입 공격에 실패하였습니다.')
    else:
        print('\n무차별 대입 공격에 성공하였습니다.')

    f.close()

###############  main ##################
effective_time = 10
password = '**'

url_list=[]
http_url_list=[]
moduel_list=[]
timestamp_list=[]

# 쇼단 테스트 ip 목록
# 필요 시 쇼단에 ipcamera country:"KR" 검색 후 테스트 ip 사용.
#host_ip = '125.138.199.246 '  #한국 용인시 로그인 페이지
#host_ip = '66.84.125.5'       #외국 블루아이리시
#host_ip = '210.113.146.217'   #한국 CVE 목록 뜨는 ip
host_ip= '121.162.174.166'
#host_ip = '211.51.205.144' #로그인 팝업


api=get_shodan_api_key()
host = api.host(host_ip)  #검색 API


#print_host_vulnerable_Info();               #host 취약 정보 출력

http_url_list_Num = get_host_URL_Info();    #host http-url 정보 가져오기
print_host_URL_Info();                      #host http-url 정보 출력
open_http_url();                            #http-url open
print_host_CVE_Info()





