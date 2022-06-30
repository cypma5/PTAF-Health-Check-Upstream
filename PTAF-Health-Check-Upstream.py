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
                    #filemode = "a", #Добавление строк в лог
                    filemode = "w", #перезаписывать файл
                    format = Log_Format, 
                    level = logging.DEBUG)

logger = logging.getLogger()

#Testing our Logger

logger.info("________________________________Start Script________________________________")

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
healthcheck_host = "example.com"

#IP адрес mgmt интерфейса PTAF
ip_mgmt ="192.168.56.102"

#Указываем upstream_protocol http:// или https:// нужно глянуть какой параметр указан в сервисе, возможно стоит начинать проверку с сервиса.
upstream_protocol = "https://"

#Создание директории
logger.info("Создаём директорию")
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
#Полезная нагрузка для проверки апстрима ( для метода POST)
payload_upstream={}
#порядковый номер апстрима в словаре
count = 0
#Обнуляем апстримы доступные
upstream_status = 0
#Задаем переменную с URL по которому выгружаем конфиг конкретного upstreams
url_upstreams = "https://"+ ip_mgmt + ":8443/api/waf/v2/upstreams" + '/' + id_upstreams

#Указываем заголовки
headers_ptaf = {'Authorization':'Basic TEST_YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42' , 'Content-Type':'application/json'}

headers_health_check = {'Host':healthcheck_host}

#Запрашиваем список Upstreams
#v1.9.3 добавил лог ошибок при недоступности mgmt
socket_mgmt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_mgmt.settimeout(3.0)
mgmt_adr = (ip_mgmt , 8443)
result_mgmt = socket_mgmt.connect_ex(mgmt_adr)

if result_mgmt == 0:    #Если порт mgmt открыт , то переходим к загрузке JSON с апстримами
    logger.info("Запрашиваем список апстримов")
    file_upstream=open( str(list_upstream) ,"wb")
    try:    #Пробуем выгрузить апстримы в JSON
        response_upstream = requests.request("GET", url_upstreams, headers=headers_ptaf, data=payload_upstream, verify=False)
        print(now + ' запрашиваем список upstream | response code ' ,response_upstream.status_code)
        print('content' ,response_upstream.content)
        #Если код ответа не 200, то 
        logger.info(" Код ответа " + str(response_upstream.status_code) )
        #print(now , response_upstream.content , sep=' ' ,end='\n' , flush=False)
        file_upstream.write(response_upstream.content)
        file_upstream.close()
        #Открываем JSON 
        with open( str(list_upstream), encoding = 'UTF-8') as file_upstream:
            JSON_data = json.load(file_upstream)            
            
            
            print(now + ' JSON с Апстримами  ' ,JSON_data["addresses"] )
            logging.info(' JSON с Апстримами  ' + str(JSON_data["addresses"]))
            #logger.info(now + ' JSON с Апстримами  ' ,JSON_data["addresses"] )
            #Количество включенных апстримов, обнуляем в начале цикла
            

            
            for n in JSON_data['addresses']:    #Запускаем цикл проверки
                print(now + ' Проверка Апстрима: ' ,JSON_data["backends"][count]["address"])
                print(now + ' Порт Апстрима:' ,JSON_data["backends"][count]["port"])
                logging.info(' Проверка Апстрима: '+ str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]))
                #Проверка доступности порта
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                result_upstream = sock.connect_ex((JSON_data["backends"][count]["address"],JSON_data["backends"][count]["port"]))
                #Если порт открыт, то переходим к проверке http
                if result_upstream == 0: #Если порт открыт то
                    print (now ,JSON_data["backends"][count]["address"],JSON_data["backends"][count]["port"],"Port is Open")
        
                    #Генерируем URL для проверки
                    #Есть проблемы если указан порт не стандартный, нужно указывать из Service. Большая доработка. Если перепутаны протоколы, сыпет ошибками когда на hhttp ломишься по https, и тому подобное.
                    #В настройках сервиса указывается       "upstream_protocol": "http",
                    if ((JSON_data["backends"][count]["port"] == 80) or (JSON_data["backends"][count]["port"] == 443)):            
                        url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+ healthcheck_path
                        #Вообще это дичь врядли кто то будет указывать upstream protocol https и отправлять на http, лучше отбить как missconfiguration
                        #elif JSON_data["backends"][count]["port"] == 443:
                        #    url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+ healthcheck_path
                        #Если порт не 80 или 443 то добавлять его после host
                    else:
                        url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) + healthcheck_path
    
                    print(now ,  'Получили URL после условий ' , url_healthcheck )
                    payload_healthcheck={}

                    try:
                        #Пробуем сделать хелчек
                        HealthCheck =  requests.request("GET", url_healthcheck, headers=headers_health_check, data=payload_healthcheck, timeout=1 ,  verify=False)
                        print(now ,  'Проверяем URL ' , url_healthcheck , ' Код HTTP ответа:' + str(HealthCheck.status_code))
                        print(now ,  'Проверяем URL ' ,  str(HealthCheck.content))
                        
                        if  HealthCheck.status_code == 200:
                            #нужно добавить если статус 200 и включен, ничего не делать, иначе включить Upstream_Down
                            print(now , 'Апстрим выключен?:' ,JSON_data["backends"][count]["down"] )                            
                            JSON_data["backends"][count]["down"] = 'False'
                            #payload_upstream = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'                            
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
                    #Ошибки при выполнении хелсчека
                    except TimeoutError as error1:
                        print(now,'1',error1)
                        logging.error('error1')                        
                    except urllib3.exceptions.ConnectTimeoutError as error2:
                        print(now,'2',error2)
                        logging.error('error2')
                    except urllib3.exceptions.MaxRetryError as error3:
                        print(now,'3',error3)
                        logging.error('error3')
                    except urllib3.exceptions.ConnectTimeoutError as error4:
                        print(now,'4',error4)
                        logging.error('error4')
                    except requests.exceptions.ConnectTimeout as error5:
                        print(now,'error5',error5)
                        print(now,'error5','Отправка https трафика на порт ожидающий http')
                        count =  count + 1
                        logging.critical('Check variable upstream_protocol Отправка https трафика на порт ожидающий http')
                    except AttributeError as error6:
                        print(now,'6',error6)
                        logging.error('error6')
                    except requests.exceptions.SSLError as error8:
                        print(now,'error8',error8)
                        print(now,'error8','Отправка https трафика на порт ожидающий http')
                        logging.error('error8')
                        logging.critical('Check variable upstream_protocol Отправка https трафика на порт ожидающий http')
                else: #Если порт закрыт то
                    print (now ,"Port closed")
                    print(now ,'Апстрим выключен?:' ,JSON_data["backends"][count]["down"] )
                    JSON_data["backends"][count]["down"] = 'True'
                    print(now , 'Меняем значение на:' ,JSON_data["backends"][count]["down"] )
                    count =  count + 1
                    print(now , 'Доступных Апстримов:', upstream_status)
        
                sock.close()   
            if upstream_status >= 1:    #Если после проверок включенных апстримов >= 1 то
                payload_upstream = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'
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
            else:    #Если после проверок включенных апстримов 0
                print(now, 'Нет доступных Апстримов, настройки не применены')
    except TimeoutError as error:
        print(now,error)
        logging.critical('error1-1')
        logging.critical(error)
    except urllib3.exceptions.ConnectTimeoutError as error:
        print(now,error)
        logging.critical('error1-2')
        #logging.exception(error)
        #HealthCheck.status_code = 502
    except urllib3.exceptions.MaxRetryError as error:
        print(now,error)
        logging.critical('error1-3')
        logging.critical(error)
        #HealthCheck.status_code = 502
    except urllib3.exceptions.ConnectTimeoutError as error:
        print(now,error)
        logging.critical('error1-4')
        logging.critical(error)
        #HealthCheck.status_code = 502
    except requests.exceptions.ConnectTimeout as error:
        print(now,error)
        logging.critical('mgmt порт закрыт, невозможно извлечь конфиг upstreams')
        logging.critical(error)
        #HealthCheck.status_code = 502
    except KeyError as error:
        print('Ошибка в кредах, проверь связку логин + пароль')
        logging.critical('Ошибка в кредах, проверь связку логин + пароль')
        logging.critical(error)
        #HealthCheck.status_code = 502        





else:   #Порт mgmt недоступен 
    print('Порт MGMT закрыт, проверь в чем дело')







input("prompt: ")
