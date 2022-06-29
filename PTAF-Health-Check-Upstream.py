import requests
import datetime
import urllib3
import json
import os

# В идеале надо будет сделать скрипт в который ты указываешь IP WAF 
# Далее он загружает список upstreams ты выбираешь для какого написать healthcheck
# Вводишь параметры проверки пути, интервалы
# данный скрипт на выходе генерирует маленький скрипт который ты добавляешь в крон, он в случае чего потущит недоступный фронт
# продумать логирование в файл, и отправку с SIEM Для анализа.


# Создание папки по дате (сегодня)
now = datetime.datetime.now().strftime('%d-%m-%y')
path = '/Users/USER/Documents/PTAF_HealthCheck' 

#Создание директории
try:
    os.makedirs(path)
except OSError:
    print (now + " Создать директорию %s не удалось, возможно она уже создана" % path)
else:
    print (now + " Успешно создана директория %s " % path)

# Отключить warning из-за SSL
urllib3.disable_warnings()

# Создаем переменную с именем файла в который будем записывать upstreams
list_upstream = str(path) + 'config_upstream' + str(now) + '.json'

#Тут указываем ID проверяемого upstream, лучше предоставить выбор из выгрузки.
id_upstream = "62b4697e95f57367fa9c25ad"


healthcheck_path = '/lol'
#Задаем переменную с URL по которому 
url_upstreams = "https://192.168.56.102:8443/api/waf/v2/upstreams" + '/' + id_upstream

#Указываем заголовки
headers_ptaf = {'Authorization': 'Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42'}
headers_contentType = {'Authorization':'Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42' , 'Content-Type':'application/json'}
headers_upstream = {}

#Запрашиваем список Upstreams
file_upstream=open( str(list_upstream) ,"wb")
payload_upstream={}
response_upstream = requests.request("GET", url_upstreams, headers=headers_ptaf, data=payload_upstream, verify=False)
print(now + ' запрашиваем список upstream | response code ' ,response_upstream.status_code)

#print(now , response_upstream.content , sep=' ' ,end='\n' , flush=False)
file_upstream.write(response_upstream.content)
file_upstream.close()



#Открываем JSON 
with open( str(list_upstream), encoding = 'UTF-8') as file_upstream:
    JSON_data = json.load(file_upstream)

#print(now + ' JSON_data[addresses] ' ,JSON_data["addresses"] )
#print(now + ' JSON_data[backends] ' ,JSON_data["backends"] )
#print(now + ' JSON_data[backends][0] ' ,JSON_data["backends"][0] )
#print(now + ' JSON_data[backends][0][address] ' ,JSON_data["backends"][0]["address"] )
#print(now + ' JSON_data[backends][1] ' ,JSON_data["backends"][1] )
#print(now + ' JSON_data[backends][1][address] ' ,JSON_data["backends"][1]["address"] )

count = 0 
for n in JSON_data['addresses']:
    #print(now + ' n ' ,n )
    
    #print(now + ' count ' ,count )

    print(now + ' JSON_data[addresses] ' ,JSON_data["addresses"] )
    print(now + ' JSON_data[backends] ' ,JSON_data["backends"][count]["address"] )

    #now_name = str(path) + n["address"] + '.json'
    #file_upstream=open( str(now_name),"wb")
    #payload_upstream={}
    #response_upstream = requests.request("GET", url_upstreams, headers=headers, data=payload_upstream, verify=False)
    #print(now + ' ', upstream_conf)
    #file_upstream.write(response_upstream.content)
    #file_upstream.close()
    #print(now + ' Создан: '+ now_name)
    #Указываем URL HealthCheck
    #url_healthcheck = 'https://' + n['address'] + ':'+ n['port'] + healthcheck_path
    url_healthcheck = 'http://' + str(JSON_data["backends"][count]["address"])+ healthcheck_path
    #url_healthcheck = 'http://localhost'
    #print(now + ' url_healthcheck ' , url_healthcheck)
    payload_healthcheck={}
    HealthCheck =  requests.request("GET", url_healthcheck, headers=headers_upstream, data=payload_healthcheck, timeout=1 ,  verify=False)
    print(now ,  ' url_healthcheck ' , url_healthcheck , ' healthceck status code ' + str(HealthCheck.status_code))
    if  HealthCheck.status_code == 200:
        print(now + ' healthceck status OK ' + str(HealthCheck.status_code))
        count =  count + 1

    else :


            #print(now + ' JSON_data[backends][' + str(count) + '] ' ,JSON_data["backends"][count] )
            print(now + ' JSON_data[backends][' + str(count) + '][address] ' ,JSON_data["backends"][count]["address"] )
            print(now + ' JSON_data[backends][' + str(count) + '][down] ' ,JSON_data["backends"][count]["down"] )
            JSON_data["backends"][count]["down"] = 'True'
            print(now + ' JSON_data[backends][' + str(count) + '][down] ' ,JSON_data["backends"][count]["down"] )
            #payload_upstream = '{"backends": [ {"address": "10.10.10.30", "backup": false, "down": false, "max_fails": 2, "port": 443, "weight": 2}]}'
            #downstatus=input('введи true или false')
            Test_payload = '{"backends": [{"address": "192.168.88.29", "backup": false, "down": "True", "max_fails": 0, "port": 80, "weight": 1}, {"address": "192.168.88.30", "backup": false, "down": false, "max_fails": 1, "port": 80, "weight": 1}]}'
            #print(now + ' Test_payload =' , Test_payload)
            payload_upstream = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'
            #payload_upstream = str(JSON_data["backends"])
            #print(now + ' payload_upstream ' + str(payload_upstream))

            Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_contentType, data=payload_upstream, verify=False)
            print(now + ' Upstream_Down ' + str(Upstream_Down.status_code) )
            #print(now + ' Upstream_Down ' + str(Upstream_Down.status_code),  str(Upstream_Down.content) , )
            #Upstream_Down_1 = requests.request("PATCH", url_upstreams, headers=headers_contentType, data=Test_payload, verify=False)
            #print(now + ' Upstream_Down_1' + str(Upstream_Down_1.status_code),  str(Upstream_Down_1.content) , )
            #e_upstream     = requests.request("GET", url_upstreams, headers=headers_ptaf, data=payload_upstream, verify=False)
            #print(now + ' Upstream_Down ' + str(Upstream_Down.status_code),  str(Upstream_Down.content) , )
            #print(now + ' Изменить значение Upstream ' + str(Upstream_Down))
            count =  count + 1

print(now + ' JSON_data[addresses] ' ,JSON_data["addresses"] )
print(now + ' JSON_data[backends] ' ,JSON_data["backends"] )
