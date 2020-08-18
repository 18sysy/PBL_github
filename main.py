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
    SHODAN_API_KEY = "rNu7d26Vf49aGFBRLv2ZoWHLU0ndh3QN";
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
        region_code : {} 

        last_update : {}
        exposed ports count : {}
        exposed ports : {}
        \n
        """
            .format(host['ip_str'],
                    host['tags'],
                    host['country_name'],
                    host['city'],
                    host['region_code'],
                    host['last_update'],
                    len(host['ports']),
                    host['ports']
                    )
    )
def get_host_URL_Info():
    #각각의 data[i]에서 url,timestamp,shodan_module 정보 분리하기
    for item in host['data']:
        item_url="http://{}:{}".format(host['ip_str'],item['port'])
        item_timestamp = "{}".format(item['timestamp'])
        item_module="{}".format(item['_shodan'].get('module'))

        #http 프로토콜을 사용하는 data 분류하기  -> url_list_http
        if 'http' in item_module:
            url_list_http.append(item_url)

        # 각 요소를 리스트로
        url_list.append(item_url)
        moduel_list.append(item_module)
        timestamp_list.append(item_timestamp)


    # url_list 정보 출력하기
    url_list_Num = len(host['data'])
    print("[[ Host URL List Info ]]")
    print("     url list count : {}" .format(url_list_Num))
    for i in range (0,url_list_Num):
        print(
        """
        URL {} : {} 
        moduel : {} 
        timestamp : {}
        """
        .format(i+1,url_list[i],moduel_list[i],timestamp_list[i])
        )

    # http-url_list 정보 출력하기
    url_list_http_Num = len(url_list_http)
    print("[[ Host HTTP-URL List Info ]]")
    print("url_list_http_num : {} \n". format(url_list_http_Num))
    for i in range(0,url_list_http_Num) :
        print(url_list_http[i])
        url = "{}".format(url_list_http[i])
        webbrowser.open(url)  #에러처리 추가 필요 #오픈 성공 시 위험도 증가 코드 필요
        print("Log : HTTP-URL open success.")

url_list=[]
moduel_list=[]
timestamp_list=[]
url_list_http=[]


################  main ##################
print("0818 start")

host_ip = '66.84.125.5'

api=get_shodan_api_key()
host = api.host(host_ip)

print_host_general_Info();
get_host_URL_Info();

print("0818 end")




