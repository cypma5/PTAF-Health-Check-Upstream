#v1.1.4
#Исправил logging на logging
#Исправил 225 строку
#Исправил exeption error17

import requests
import datetime
import urllib3
import json
import os
import socket
import logging
import platform



#import logging

file_log = logging.FileHandler('ptaf-healthcheck.log')
console_out = logging.StreamHandler()

logging.basicConfig(handlers=(file_log, console_out), 
                    format='[%(asctime)s | %(levelname)s]: %(message)s', 
                    datefmt='%m.%d.%Y %H:%M:%S',
                    level=logging.INFO)

logging.info('Info message??))')





#Creating and Configuring logging
hostname = platform.node()
print(hostname)

Log_Format = " %(asctime)s [%(levelname)s] - %(message)s"

logging.basicConfig(filename = "/var/log/ptaf-healthcheck.log",
                    filemode = "a", #Добавление строк в лог
                    #filemode = "w", #перезаписывать файл
                    format = Log_Format,
                    level = logging.DEBUG) 
                    #level = logging.INFO)

logging = logging.getLogger()


#Testing our logging

logging.info("________________________________Start Script________________________________")
logging.debug('ВКЛЮЧЕН РЕЖИМ ДЕБАГА')

# Данный скрипт должен запускаться на PTAF по крону
# продумать логирование в файл, и отправку с SIEM Для анализа.
#создавать бекап конфига перед изменением
#Добавить заголовок host
# проверять настройку протокола в сервисах
#Менять конфиг только когда есть изменения в доступности апстримов
# сравнивать содержимое ответа от апстрима

# Нужно уйти от этой переменной.
now = datetime.datetime.now().strftime('%d-%m-%y %H:%M:%S')

#Настройка Окружения
path = './' 

#Настройка подключения к PTAF

ip_mgmt ="192.168.56.102"   #крашиться при неправильном параметре.
id_upstreams = "62b4697e95f57367fa9c25ad"
headers_ptaf = {'Authorization':'Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42' , 'Content-Type':'application/json'}
payload_ptaf={}

#Настройка HealthCheck
healthcheck_path = '/health'
healthcheck_host = "example.com"
payload_healthcheck={}
headers_health_check = { "User-Agent": "HealthChecker_PTAF", "Host": healthcheck_host }
upstream_protocol = "http://"




#Создание директории
logging.info("Создаём директорию")
try:
    os.makedirs(path)
except OSError:
    print (" Создать директорию %s не удалось, возможно она уже создана" % path)
    logging.debug('Создать директорию %s не удалось, возможно она уже создана')
else:
    print (" Успешно создана директория %s " % path)

# Отключить warning из-за SSL
urllib3.disable_warnings()

#обнуляем Количество изменений в конфиге 
upstream_changed = 0
#порядковый номер апстрима в словаре
count = 0
#Обнуляем апстримы доступные
upstream_status = 0
response_health_check = {}

#Задаем переменную с URL по которому выгружаем конфиг конкретного upstreams
url_upstreams = "https://"+ ip_mgmt + ":8443/api/waf/v2/upstreams" + '/' + id_upstreams
# Создаем переменную с именем файла в который будем записывать upstreams
list_upstream = str(path) + 'config_upstream' + str(id_upstreams)  + '.json'

#Запрашиваем список Upstreams
socket_mgmt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Таймаут недоступности mgmt 3.0 секунды
socket_mgmt.settimeout(3.0)
mgmt_adr = (ip_mgmt , 8443)
try: 
    result_mgmt = socket_mgmt.connect_ex(mgmt_adr)
except socket.gaierror as error:
    print(error)
    logging.critical('PTAF_NETWORK Указан некорректный IP адрес')
    logging.exception(error)

if result_mgmt == 0:    #Если порт mgmt открыт , то переходим к загрузке JSON с апстримами
    logging.debug("PTAF_NETWORK Порт mgmt открыт")
    file_upstream=open( str(list_upstream) ,"wb")
    try:    #Пробуем выгрузить апстримы в JSON
        logging.debug('PTAF_JSON Пробуем выгрузить апстримы в JSON')
        response_upstream = requests.request("GET", url_upstreams, headers=headers_ptaf, data=payload_ptaf, verify=False)
        if response_upstream.status_code == 200:
            print(' Код ответа от PTAF: ' ,response_upstream.status_code)
            logging.info("PTAF_JSON Код ответа от PTAF: " + str(response_upstream.status_code) )
            file_upstream.write(response_upstream.content)
            file_upstream.close()
            #Открываем JSON 
            with open( str(list_upstream), encoding = 'UTF-8') as file_upstream:
                logging.debug("PTAF_JSON Открываем JSON")
                JSON_data = json.load(file_upstream)
                logging.debug('PTAF_JSON JSON с Апстримами  ' + str(JSON_data["addresses"]))
                for n in JSON_data['addresses']:    #Запускаем цикл проверки
                    logging.info('Проверка Апстрима: '+ str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]))
                    logging.debug('Проверка доступности порта')
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3.0)
                    result_upstream = sock.connect_ex((JSON_data["backends"][count]["address"],JSON_data["backends"][count]["port"]))
                    #Если порт открыт, то переходим к проверке http
                    if result_upstream == 0: #Если порт открыт то
                        logging.debug('UPSTREAM_NETWORK Порт открыт, то переходим к проверке http')
                        logging.info('UPSTREAM_NETWORK ' + str(JSON_data["backends"][count]["address"]) +':'+ str(JSON_data["backends"][count]["port"])+' Port is Open')
                        #Генерируем URL для проверки
                        #Есть проблемы если указан порт не стандартный, нужно указывать из Service. Большая доработка. Если перепутаны протоколы, сыпет ошибками когда на hhttp ломишься по https, и тому подобное.
                        #В настройках сервиса указывается       "upstream_protocol": "http",
                        if ((JSON_data["backends"][count]["port"] == 80) or (JSON_data["backends"][count]["port"] == 443)):            
                            url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+ healthcheck_path
                        else:
                            url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) + healthcheck_path
                        #print('Получили URL после условий ' , url_healthcheck)
                        logging.debug('URL Для проверки доступности Апстрима ' + url_healthcheck)
                        try:
                            logging.debug('Пробуем сделать хелчек')
                            response_health_check =  requests.request("GET", url_healthcheck, headers=headers_health_check, data=payload_healthcheck, timeout=1 ,  verify=False)
                            logging.info('Проверяем URL ' + url_healthcheck + ' Код HTTP ответа:' + str(response_health_check.status_code))
                            #logging.debug(str(response_health_check.content))
                            if  (response_health_check.status_code == 200) and (JSON_data["backends"][count]["down"] == True): #Апстрим доступен, но был выключен                                
                                #print('Апстрим выключен?:' ,JSON_data["backends"][count]["down"] )
                                #logging.info(str(JSON_data["backends"][count]["address"]) +':'+ str(JSON_data["backends"][count]["port"])+' Port is Open HTTP: OK')
                                logging.debug('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]))                            
                                JSON_data["backends"][count]["down"] = 'False'                           
                                #print('Включили Апстрим', JSON_data["backends"][count]["address"])
                                logging.debug( 'Включили Апстрим ' + str(JSON_data["backends"][count]["address"]))
                                upstream_changed = upstream_changed + 1
                                count =  count + 1
                                upstream_status = upstream_status + 1
                                logging.debug('Доступных Апстримов: ' + str(upstream_status))
                            elif (response_health_check.status_code == 200) and (JSON_data["backends"][count]["down"] == False): # Если апстрим доступен, и не был выключен
                                logging.info('Апстрим ' + str(JSON_data["backends"][count]["address"]) +' доступен и был включен, действий не требуется ')
                                count =  count + 1
                                upstream_status = upstream_status + 1
                                logging.info('Доступных Апстримов: '+ str(upstream_status))
                            elif (response_health_check.status_code != 200) and (JSON_data["backends"][count]["down"] == False): # Если апстрим недоступен, и не был включен :
                                logging.debug(str(response_health_check.content))
                                logging.info('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]))
                                JSON_data["backends"][count]["down"] = 'True'
                                logging.info('Меняем значение на: ' +JSON_data["backends"][count]["down"])
                                upstream_changed = upstream_changed + 1
                                count =  count + 1
                                print('Доступных Апстримов:', upstream_status)
                                logging.info('Доступных Апстримов: '+ str(upstream_status))
                            else:
                                logging.debug(str(response_health_check.content))
                                logging.info('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]) + ' и не ответил на HealthCheck')
                                logging.info('Доступных Апстримов: '+ str(upstream_status))
                                count =  count + 1
                        #Ошибки при выполнении хелсчека
                        except TimeoutError as error001:                            
                            logging.error('HTTP_Health_check TimeoutError')
                            logging.exception(error001)
                        except urllib3.exceptions.ConnectTimeoutError as error002:                            
                            logging.error('HTTP_Health_check urllib3.exceptions.ConnectTimeoutError')
                            logging.exception(error002)
                        except urllib3.exceptions.MaxRetryError as error003:                            
                            logging.error('HTTP_Health_check urllib3.exceptions.ConnectTimeoutError')
                            logging.exception(error003)
                        except urllib3.exceptions.ConnectTimeoutError as error004:                            
                            logging.error('HTTP_Health_check urllib3.exceptions.ConnectTimeoutError')
                            logging.exception(error004)
                        except requests.exceptions.ConnectTimeout as error005:
                            count =  count + 1                            
                            logging.critical('HTTP_Health_check upstream_protocol Отправка https трафика на порт ожидающий http')
                            logging.exception(error005)
                        except AttributeError as error006:                            
                            logging.error('HTTP_Health_check проверь Headers которые отправляешь на апстрим ')
                            logging.critical(error006)
                        except requests.exceptions.SSLError as error008:
                            logging.critical('HTTP_Health_check Check variable upstream_protocol Отправка https трафика на порт ожидающий http')
                            logging.exception(error008)
                    else: #Если порт закрыт то
                        logging.debug('UPSTREAM_NETWORK если порт закрыт то ')
                        logging.warning('UPSTREAM_NETWORK ' + str(JSON_data["backends"][count]["address"]) +':'+ str(JSON_data["backends"][count]["port"])+' Port is Closed')
                        if str(JSON_data["backends"][count]["down"]) == 'False' : # если был включен то выключить
                            logging.debug('UPSTREAM_NETWORK порт апстрима закрыт но до проврки апстрим был включен')
                            logging.info('UPSTREAM_NETWORK Апстрим выключен?: ' + str(JSON_data["backends"][count]["down"]))
                            JSON_data["backends"][count]["down"] = 'True'
                            logging.info('UPSTREAM_NETWORK Меняем значение на:' +JSON_data["backends"][count]["down"])
                            upstream_changed = upstream_changed + 1
                            count =  count + 1
                            logging.info('Доступных Апстримов: '+ str(upstream_status))
                        else : #если был выключен то ничего не делаем
                            logging.debug('UPSTREAM_NETWORK порт апстрима закрыт и до проверки был выключен')
                            logging.info('UPSTREAM_NETWORK Апстрим выключен?: ' + str(JSON_data["backends"][count]["down"]) + ' Действие не требуется')
                            logging.info('UPSTREAM_NETWORK Доступных Апстримов: '+ str(upstream_status))
                            count =  count + 1
                    sock.close()
                if (upstream_status >= 1) and (upstream_changed >= 1) :    #Если после проверок включенных апстримов >= 1 и изменено больше одного апстрима то.
                    logging.debug('Если после проверок включенных апстримов >= 1 и изменено больше одного апстрима то.')
                    logging.warn('Доступных апстримов больше >= 1 :' + str(upstream_status) + ' Требуется изменить конфигурацию для' + str(upstream_changed))
                    payload_ptaf = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'
                    Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_ptaf, data=payload_ptaf, verify=False)
                    if  Upstream_Down.status_code == 200:
                        logging.info('Настройки применены код ответа от WAF:' + str(Upstream_Down.status_code))
                        resp_code = str(Upstream_Down.content)
                        logging.debug('ответ от WAF:' + resp_code)
                    else:
                        logging.error('Настройки не применены из за ошибки')
                        logging.error('ответ от WAF:'+ str(Upstream_Down.status_code) +' '+ str(Upstream_Down.content))
                elif (upstream_status >= 1) and (upstream_changed == 0 ) :
                    logging.info('Апстримов доступно ' + str(upstream_status) + ' изменений нет')
                else:    #Если после проверок включенных апстримов 0
                    logging.critical('Нет доступных Апстримов, настройки не применены')
        else: #код ответа при запросе апстримов не 200
            logging.error('Проверь headers_ptaf или логин\пароль для подключения к mgmt '+'Код ответа: '+str(response_upstream.status_code))
            logging.error(str(response_upstream.text))
    except TimeoutError as error011:
        logging.critical('PTAF_JSON TimeoutError')
        logging.exception(error011)
    except urllib3.exceptions.ConnectTimeoutError as error012:
        logging.critical('PTAF_JSON urllib3.exceptions.ConnectTimeoutError')
        logging.exception(error012)
    except urllib3.exceptions.MaxRetryError as error013:
        logging.critical('PTAF_JSON urllib3.exceptions.MaxRetryError')
        logging.exception(error013)
    except urllib3.exceptions.ConnectTimeoutError as error014:
        logging.critical('PTAF_JSON urllib3.exceptions.ConnectTimeoutError')
        logging.exception(error014)
    except requests.exceptions.ConnectTimeout as error015:
        logging.critical('PTAF_JSON mgmt порт закрыт, невозможно извлечь конфиг upstreams')
        logging.exception(error015)
    except KeyError as error016:
        logging.critical('PTAF_JSON Ошибка в кредах, проверь значение переменной headers_ptaf')
        logging.exception(error016)
#    except InsecureRequestWarning as error017:
#        logging.critical('PTAF_JSON Неудалось проверить сертификат?')
#        logging.exception(error017)


else:   #Порт mgmt недоступен 
    logging.critical('PTAF_NETWORK' + str(ip_mgmt) +' Порт MGMT закрыт, проверь в чем дело')
