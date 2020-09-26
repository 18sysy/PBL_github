import webbrowser
import shodan
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

def print_host_general_Info():
    print(
    """
    [[Host General Information]]
    IP : {}
    tags : {}
    Country : {}
    City : {}
    \n
    """
    .format(host['ip_str'],
            host['tags'],
            host['country_name'],
            host['city'],
            )
    )
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
    ) #CVE 정보 추가 필요, CVE 필드가 없을 경우 나오는 에러 처리하기

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
        webbrowser.open(url)  #에러처리 추가 필요 #오픈 성공 시 위험도 증가 코드 필요
        print("Log : HTTP-URL open success.")
        
def print_host_Vuls_Info():
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

###############  main ##################
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


api=get_shodan_api_key()
host = api.host(host_ip)  #검색 API

#print_host_general_Info();                 #host 기본 정보 출력
#print_host_vulnerable_Info();               #host 취약 정보 출력

#http_url_list_Num = get_host_URL_Info();    #host http-url 정보 가져오기
#print_host_URL_Info();                      #host http-url 정보 출력
#open_http_url();                            #http-url open
print_host_Vuls_Info()





