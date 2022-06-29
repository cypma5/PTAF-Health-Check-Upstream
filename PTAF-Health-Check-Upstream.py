import requests
import datetime
import urllib3
import json
import os
import socket

# В идеале надо будет сделать скрипт в который ты указываешь IP WAF 
# Далее он загружает список upstreams ты выбираешь для какого написать healthcheck
# Вводишь параметры проверки пути, интервалы
# данный скрипт на выходе генерирует маленький скрипт который ты добавляешь в крон, он в случае чего потущит недоступный фронт
# продумать логирование в файл, и отправку с SIEM Для анализа.


# Создание папки по дате (сегодня)
now = datetime.datetime.now().strftime('%d-%m-%y %H:%M:%S')
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
list_upstream = str(path) + 'config_upstream'  + '.json'

#Тут указываем ID проверяемого upstream, лучше предоставить выбор из выгрузки.
id_upstream = "62b4697e95f57367fa9c25ad"

#HealthCheck ={}
HealthCheck = {}
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
#Если первый апстрим не пройдет проверку, нужно это заполнить
HealthCheck = requests.request("GET", url_upstreams, headers=headers_ptaf, data=payload_upstream, verify=False)
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
print(now + ' JSON с Апстримами  ' ,JSON_data["addresses"] )

#Переменная для проверки всех апстримов.
upstream_status = 0

#Запускаем цикл проверки 
for n in JSON_data['addresses']:

    print(now + ' Проверка Апстрима:' ,JSON_data["backends"][count]["address"])
    print(now + ' Порт Апстрима:' ,JSON_data["backends"][count]["port"])



#Проверка доступности порта
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    result = sock.connect_ex((JSON_data["backends"][count]["address"],JSON_data["backends"][count]["port"]))
#Если порт открыт, то переходим к проверке http
    if result == 0:
        print (now ,"Port is open")
        
        #Генерируем URL для проверки
        if JSON_data["backends"][count]["port"] == 80:
            protocol = 'http://'
            url_healthcheck = protocol + str(JSON_data["backends"][count]["address"])+ healthcheck_path
        elif JSON_data["backends"][count]["port"] == 443:
            protocol = 'https://'
            url_healthcheck = protocol + str(JSON_data["backends"][count]["address"])+ healthcheck_path
        else:
            protocol = 'https://'
            url_healthcheck = protocol + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) + healthcheck_path
    
        print(now ,  'Получили URL после условий ' , url_healthcheck )
        payload_healthcheck={}

        try:
            HealthCheck =  requests.request("GET", url_healthcheck, headers=headers_upstream, data=payload_healthcheck, timeout=1 ,  verify=False)
            print(now ,  'Проверяем URL ' , url_healthcheck , ' Код HTTP ответа:' + str(HealthCheck.status_code))
        except TimeoutError as error:
            print(now,error)
            #HealthCheck.status_code = 502
        except urllib3.exceptions.ConnectTimeoutError as error:
            print(now,error)
            #HealthCheck.status_code = 502
        except urllib3.exceptions.MaxRetryError as error:
            print(now,error)
            #HealthCheck.status_code = 502
        except urllib3.exceptions.ConnectTimeoutError as error:
            print(now,error)
            #HealthCheck.status_code = 502
        except requests.exceptions.ConnectTimeout as error:
            print(now,error)
            #HealthCheck.status_code = 502
        except AttributeError as error:
            print(now,error)
            #HealthCheck.status_code = 502
            
        if  HealthCheck.status_code == 200:
            print(now , 'Апстрим выключен?:' ,JSON_data["backends"][count]["down"] )
            #Нужно добавит если статус 200 и включен, ничего не делать, иначе включить Upstream_Down
            JSON_data["backends"][count]["down"] = 'False'
            #payload_upstream = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'
            #Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_contentType, data=payload_upstream, verify=False)
            print(now , 'Включили Апстрим', JSON_data["backends"][count]["address"])
            count =  count + 1
            upstream_status = upstream_status + 1
            print(now , 'Доступных Апстримов:', upstream_status)
        else :
            #print(now + ' JSON_data[backends][' + str(count) + '][address] ' ,JSON_data["backends"][count]["address"] )
            print(now ,'Апстрим выключен?:' ,JSON_data["backends"][count]["down"] )
            JSON_data["backends"][count]["down"] = 'True'
            print(now , 'Меняем значение на:' ,JSON_data["backends"][count]["down"] )
            #payload_upstream = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'
            #Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_contentType, data=payload_upstream, verify=False)
            #print(now , 'Настройки применены код ответа от WAF:' + str(Upstream_Down.status_code) )
            count =  count + 1
            print(now , 'Доступных Апстримов:', upstream_status)



        
    else:
        print (now ,"Port closed")
        print(now ,'Апстрим выключен?:' ,JSON_data["backends"][count]["down"] )
        JSON_data["backends"][count]["down"] = 'True'
        print(now , 'Меняем значение на:' ,JSON_data["backends"][count]["down"] )
        count =  count + 1
        print(now , 'Доступных Апстримов:', upstream_status)
        
    sock.close()


    
        
    #print(now ,  'Проверяем URL ' , url_healthcheck , ' Код HTTP ответа:' + str(HealthCheck.status_code))    

    
payload_upstream = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'


if upstream_status >= 1:
    
    Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_contentType, data=payload_upstream, verify=False)
    if  Upstream_Down.status_code == 200:
        print(now , 'Настройки применены код ответа от WAF:' + str(Upstream_Down.status_code) )
        resp_code = str(Upstream_Down.content)
        print(now , 'ответ от WAF:' + resp_code )

    #print(now , 'ответ \n от \n WAF:' , end="\n")

    
    elif Upstream_Down.status_code == 422:
        print(now , 'Настройки не применены , должен быть хотя бы один включенный Upstream' )
        print(now , 'ответ от WAF:', str(Upstream_Down.status_code) , str(Upstream_Down.content) )    

#print(now + ' JSON_data[addresses] ' ,JSON_data["addresses"] )
#print(now + ' JSON_data[backends] ' ,JSON_data["backends"] )

input("prompt: ")
