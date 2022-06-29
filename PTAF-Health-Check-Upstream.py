import requests
import datetime
import urllib3
import json
import os
import socket
import logging

#Creating and Configuring Logger

Log_Format = " %(asctime)s [%(levelname)s] - %(message)s"

logging.basicConfig(filename = "logfile.log",
                    filemode = "w",
                    format = Log_Format, 
                    level = logging.DEBUG)

logger = logging.getLogger()

#Testing our Logger

logger.info("Start Script")

# Далее он загружает список upstreams ты выбираешь для какого написать healthcheck
# Вводишь параметры проверки пути, интервалы
# Данный скрипт должен запускаться на PTAF по крону
# продумать логирование в файл, и отправку с SIEM Для анализа.
#создавать бекап конфига перед изменением
#Добавить заголовок host



# Нужно уйти от этой переменной.
now = datetime.datetime.now().strftime('%d-%m-%y %H:%M:%S')

#Указываем путь куда класть конфиг
path = '/Users/USER/Documents/PTAF_HealthCheck' 
#Тут указываем ID проверяемого upstream, лучше предоставить выбор из выгрузки.
id_upstreams = "62b4697e95f57367fa9c25ad"
#Указываем путь для проверки
healthcheck_path = '/'
healthcheck_host = "multilidae.me"

#IP адрес mgmt интерфейса PTAF
ip_mgmt ="192.168.56.102"

#Указываем upstream_protocol http:// или https:// нужно глянуть какой параметр указан в сервисе, возможно стоит начинать проверку с сервиса.
upstream_protocol = "http://"

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


#HealthCheck ={}
HealthCheck = {}


#Задаем переменную с URL по которому выгружаем конфиг конкретного upstreams
url_upstreams = "https://"+ ip_mgmt + ":8443/api/waf/v2/upstreams" + '/' + id_upstreams

#Указываем заголовки
headers_ptaf = {'Authorization':'Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42' , 'Content-Type':'application/json'}

headers_health_check = {'Host':healthcheck_host}

#Запрашиваем список Upstreams
#v1.9.3 добавил лог ошибок при недоступности mgmt
file_upstream=open( str(list_upstream) ,"wb")
payload_upstream={}
try:
    response_upstream = requests.request("GET", url_upstreams, headers=headers_ptaf, data=payload_upstream, verify=False)
except TimeoutError as error:
    print(now,error)
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

#порядковый номер апстрима в словаре
count = 0

print(now + ' JSON с Апстримами  ' ,JSON_data["addresses"] )

#logger.info(now + ' JSON с Апстримами  ' ,JSON_data["addresses"] )
#Количество включенных апстримов, обнуляем в начале цикла
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
        print (now ,JSON_data["backends"][count]["address"],JSON_data["backends"][count]["port"],"Port is Open")
        
        #Генерируем URL для проверки
        #Есть проблемы если указан порт не стандартный, нужно указывать из Service. Большая доработка. Если перепутаны протоколы, сыпет ошибками когда на hhttp ломишься по https, и тому подобное.
        #В настройках сервиса указывается       "upstream_protocol": "http",
        if JSON_data["backends"][count]["port"] == 80:            
            url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+ healthcheck_path
        #Вообще это дичь врядли кто то будет указывать upstream protocol https и отправлять на http, лучше отбить как missconfiguration
        elif JSON_data["backends"][count]["port"] == 443:
            url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+ healthcheck_path
        #Если порт не 80 или 443 то добавлять его после host
        else:
            url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) + healthcheck_path
    
        print(now ,  'Получили URL после условий ' , url_healthcheck )
        payload_healthcheck={}

        try:
            HealthCheck =  requests.request("GET", url_healthcheck, headers=headers_health_check, data=payload_healthcheck, timeout=1 ,  verify=False)
            print(now ,  'Проверяем URL ' , url_healthcheck , ' Код HTTP ответа:' + str(HealthCheck.status_code))
        #except TimeoutError as error:
         #   print(now,error)
            #HealthCheck.status_code = 502
        #except urllib3.exceptions.ConnectTimeoutError as error:
         #   print(now,error)
            #HealthCheck.status_code = 502
        #except urllib3.exceptions.MaxRetryError as error:
         #   print(now,error)
            #HealthCheck.status_code = 502
        #except urllib3.exceptions.ConnectTimeoutError as error:
         #   print(now,error)
            #HealthCheck.status_code = 502
        #except requests.exceptions.ConnectTimeout as error:
         #   print(now,error)
            #HealthCheck.status_code = 502
        except AttributeError as error:
            print(now,error)
            #HealthCheck.status_code = 502
            
        if  HealthCheck.status_code == 200:
            print(now , 'Апстрим выключен?:' ,JSON_data["backends"][count]["down"] )
            #Нужно добавит если статус 200 и включен, ничего не делать, иначе включить Upstream_Down
            JSON_data["backends"][count]["down"] = 'False'
            #payload_upstream = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'
            #Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_ptaf, data=payload_upstream, verify=False)
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
            #Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_ptaf, data=payload_upstream, verify=False)
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
    
    Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_ptaf, data=payload_upstream, verify=False)
    if  Upstream_Down.status_code == 200:
        print(now , 'Настройки применены код ответа от WAF:' + str(Upstream_Down.status_code) )
        resp_code = str(Upstream_Down.content)
        print(now , 'ответ от WAF:' + resp_code )

    #print(now , 'ответ \n от \n WAF:' , end="\n")

    
    #elif Upstream_Down.status_code == 422:
    else:
        print(now , 'Настройки не применены , должен быть хотя бы один включенный Upstream' )
        print(now , 'ответ от WAF:', str(Upstream_Down.status_code) , str(Upstream_Down.content) )    
else:
    print(now, 'Нет доступных Апстримов, настройки не применены')
#print(now + ' JSON_data[addresses] ' ,JSON_data["addresses"] )
#print(now + ' JSON_data[backends] ' ,JSON_data["backends"] )

input("prompt: ")
