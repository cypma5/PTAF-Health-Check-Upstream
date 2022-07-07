#v1.1.9 
#Исправил logging на logging
#Исправил 225 строку
#Исправил exeption error17
#Добавил в лог hostname

import requests
import datetime
import urllib3
import json
import os
import socket
import logging
import platform
import traceback



#import logging

file_log = logging.FileHandler('ptaf-healthcheck.log')
console_out = logging.StreamHandler()

#Creating and Configuring logging
hostname = platform.node()
print(hostname)

Log_Format = "%(asctime)s |{}|v1.1.9|%(levelname)s|%(message)s|".format(socket.gethostname())

logging.basicConfig(handlers=(file_log, console_out),
                    #filename = "/var/log/ptaf-healthcheck.log",
                    #filemode = "a", #Добавление строк в лог
                    #filemode = "w", #перезаписывать файл
                    format = Log_Format,
                    level = logging.DEBUG) 
                    #level = logging.INFO)

logging = logging.getLogger()


#Testing our logging

logging.debug("________________________________Start Script________________________________")
logging.debug('ВКЛЮЧЕН РЕЖИМ ДЕБАГА')

# Данный скрипт должен запускаться на PTAF по крону
# продумать логирование в файл, и отправку с SIEM Для анализа.
#создавать бекап конфига перед изменением
#Добавить заголовок host
# проверять настройку протокола в сервисах
#Менять конфиг только когда есть изменения в доступности апстримов
# сравнивать содержимое ответа от апстрима

# Нужно уйти от этой переменной.
#now = datetime.datetime.now().strftime('%d-%m-%y %H:%M:%S')

#Настройка Окружения
path = './' 

#Настройка подключения к PTAF

ip_mgmt ="192.168.56.102"   #крашиться при неправильном параметре.
id_upstreams = "62b4697e95f57367fa9c25ad"
headers_ptaf = {'Authorization':'Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42' , 'Content-Type':'application/json'}
payload_ptaf={}

#Настройка HealthCheck
healthcheck_path = '/'
#healthcheck_path = '/health'
healthcheck_host = "example.com"
payload_healthcheck={}
headers_health_check = { "User-Agent": "HealthChecker_PTAF", "Host": healthcheck_host }
upstream_protocol = "http://"




#Создание директории
logging.debug("Создаём директорию")
try:
    os.makedirs(path)
except OSError:
    logging.debug('Создать директорию %s не удалось, возможно она уже создана')
else:
    logging.debug(" Успешно создана директория %s " % path)

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
list_upstream = str(path) + 'config_upstream_' + str(id_upstreams)  + '_ .json'

mgmt_ptaf = ip_mgmt + ":8443"

#Запрашиваем список Upstreams
socket_mgmt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Таймаут недоступности mgmt 3.0 секунды
socket_mgmt.settimeout(3.0)
mgmt_adr = (ip_mgmt , 8443)
try: 
    result_mgmt = socket_mgmt.connect_ex(mgmt_adr)
except :
    logging.critical(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|close|fall')
    logging.exception(traceback.format_exc())

if result_mgmt == 0:    #Если порт mgmt открыт , то переходим к загрузке JSON с апстримами
    logging.debug("PTAF_NETWORK Порт mgmt открыт")
    file_upstream=open( str(list_upstream) ,"wb")
    try:    #Пробуем выгрузить апстримы в JSON
        logging.debug('PTAF_JSON Пробуем выгрузить апстримы в JSON')
        response_upstream = requests.request("GET", url_upstreams, headers=headers_ptaf, data=payload_ptaf, verify=False)
        if response_upstream.status_code == 200:
            logging.info(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|ok|'+str(response_upstream.status_code)+'|Получили JSON с Upstreams')
            #logging.debug("PTAF_JSON Получен JSON код ответа: " + str(response_upstream.status_code) )
            file_upstream.write(response_upstream.content)
            file_upstream.close()
            #Открываем JSON 
            with open( str(list_upstream), encoding = 'UTF-8') as file_upstream:
                logging.debug("PTAF_JSON Открываем JSON")
                JSON_data = json.load(file_upstream)
                logging.debug('PTAF_JSON JSON с Апстримами ' + str(JSON_data["addresses"]))
                for n in JSON_data['addresses']:    #Запускаем цикл проверки
                    #logging.info(str(id_upstreams) + '|' + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) +'|ok|ok|Получили JSON с Upstreams')
                    logging.debug('Проверка Апстрима: '+ str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) +' Проверка доступности порта')
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3.0)
                    result_upstream = sock.connect_ex((JSON_data["backends"][count]["address"],JSON_data["backends"][count]["port"]))
                    #Если порт открыт, то переходим к проверке http
                    if result_upstream == 0: #Если порт открыт то
                        logging.debug('UPSTREAM_NETWORK Порт открыт, переходим к проверке http')
                        logging.debug('UPSTREAM_NETWORK ' + str(JSON_data["backends"][count]["address"]) +':'+ str(JSON_data["backends"][count]["port"])+' Port is Open')
                        #Генерируем URL для проверки, добавляем порт если необходимо.
                        if ((JSON_data["backends"][count]["port"] == 80) or (JSON_data["backends"][count]["port"] == 443)):            
                            url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+ healthcheck_path
                        else:
                            url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) + healthcheck_path
                        logging.debug('URL Для проверки доступности Апстрима ' + url_healthcheck)
                        try:
                            logging.debug('Пробуем сделать хелчек')
                            response_health_check =  requests.request("GET", url_healthcheck, headers=headers_health_check, data=payload_healthcheck, timeout=1 ,  verify=False)
                            logging.debug('Проверяем URL ' + url_healthcheck + ' Код HTTP ответа:' + str(response_health_check.status_code))
                            if  (response_health_check.status_code == 200) and (JSON_data["backends"][count]["down"] == True): #Апстрим доступен, но был выключен                                
                                logging.debug('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]))                            
                                JSON_data["backends"][count]["down"] = 'False'                           
                                logging.debug( 'Включили Апстрим ' + str(JSON_data["backends"][count]["address"]))
                                logging.info(str(id_upstreams) + '|' + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) +'|ok|'+str(response_health_check.status_code)+'|Включаем апстрим')
                                upstream_changed = upstream_changed + 1
                                count =  count + 1
                                upstream_status = upstream_status + 1
                                logging.debug('Доступных Апстримов: ' + str(upstream_status))
                            elif (response_health_check.status_code == 200) and (JSON_data["backends"][count]["down"] == False): # Если апстрим доступен, и не был выключен
                                logging.debug('Апстрим ' + str(JSON_data["backends"][count]["address"]) +' доступен и был включен, действий не требуется ')
                                logging.info(str(id_upstreams) + '|' + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) +'|ok|'+str(response_health_check.status_code)+'|Действий не требуется')
                                count =  count + 1
                                upstream_status = upstream_status + 1
                                logging.debug('Доступных Апстримов: '+ str(upstream_status))
                            elif (response_health_check.status_code != 200) and (JSON_data["backends"][count]["down"] == False): # Если апстрим недоступен, и не был включен :
                                logging.debug(str(response_health_check.content))
                                logging.debug('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]))
                                JSON_data["backends"][count]["down"] = 'True'
                                logging.debug('Меняем значение на: ' +JSON_data["backends"][count]["down"])
                                logging.error(str(id_upstreams) + '|' + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) +'|ok|'+str(response_health_check.status_code)+'|Выключаем апстрим')
                                upstream_changed = upstream_changed + 1
                                count =  count + 1
                                logging.info('Доступных Апстримов: '+ str(upstream_status))
                            else:
                                logging.debug(str(response_health_check.content))
                                logging.debug('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]) + ' и не ответил на HealthCheck')
                                logging.debug('Доступных Апстримов: '+ str(upstream_status))
                                logging.warning(str(id_upstreams) + '|' + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) +'|ok|'+str(response_health_check.status_code)+'|Апстрим был выключен, Действий не требуется')
                                count =  count + 1
                        #Ошибки при выполнении хелсчека
                        except requests.exceptions.ConnectTimeout as error005:
                            count =  count + 1                            
                            logging.critical(str(id_upstreams) + '|' + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) +'|ok|false|Отправка https трафика на порт ожидающий http')
                            logging.exception(traceback.format_exc())
                        except AttributeError as error006:                            
                            logging.critical(str(id_upstreams) + '|' + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) +'|ok|false|Некорректные заголовки для upstrams')
                            logging.exception(traceback.format_exc())
                        except requests.exceptions.SSLError as error008:
                            logging.critical(str(id_upstreams) + '|' + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) +'|ok|false|Отправка https трафика на порт ожидающий http')
                            logging.exception(traceback.format_exc())
                        except:
                            logging.exception(traceback.format_exc())
                    else: #Если порт апстрима закрыт то
                        logging.debug('UPSTREAM_NETWORK если порт закрыт то ')
                        logging.debug('UPSTREAM_NETWORK ' + str(JSON_data["backends"][count]["address"]) +':'+ str(JSON_data["backends"][count]["port"])+' Port is Closed')
                        if str(JSON_data["backends"][count]["down"]) == 'False' : # если был включен то выключить
                            logging.debug('UPSTREAM_NETWORK порт апстрима закрыт но до проврки апстрим был включен')
                            logging.debug('UPSTREAM_NETWORK Апстрим выключен?: ' + str(JSON_data["backends"][count]["down"]))
                            JSON_data["backends"][count]["down"] = 'True'
                            logging.debug('UPSTREAM_NETWORK Меняем значение на:' +JSON_data["backends"][count]["down"])
                            logging.info(str(id_upstreams) + '|' + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) +'|false|false|Выключаем апстрим')
                            upstream_changed = upstream_changed + 1
                            count =  count + 1
                            logging.debug('Доступных Апстримов: '+ str(upstream_status))
                        else : #если был выключен то ничего не делаем
                            logging.debug('UPSTREAM_NETWORK порт апстрима закрыт и до проверки был выключен')
                            logging.debug('UPSTREAM_NETWORK Апстрим выключен?: ' + str(JSON_data["backends"][count]["down"]) + ' Действие не требуется')
                            logging.debug('UPSTREAM_NETWORK Доступных Апстримов: '+ str(upstream_status))
                            logging.warning(str(id_upstreams) + '|' + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) +'|false|false|Действие не требуется')
                            count =  count + 1
                    sock.close()
                if (upstream_status >= 1) and (upstream_changed >= 1) :    #Если после проверок включенных апстримов >= 1 и изменено больше одного апстрима то.
                    logging.warning(str(id_upstreams) + '|' + str(mgmt_ptaf) + 'Доступных апстримов:' + str(upstream_status) + ' Требуется изменить конфигурацию для:' + str(upstream_changed))
                    payload_ptaf = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'
                    Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_ptaf, data=payload_ptaf, verify=False)
                    if  Upstream_Down.status_code == 200: # При отправке конфига на PTAF получили код 200
                        logging.debug('Настройки применены код ответа от WAF:' + str(Upstream_Down.status_code))
                        logging.info(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|ok|'+ str(Upstream_Down.status_code) +'|Настройки применены')
                        #resp_code = str(Upstream_Down.content)
                        #logging.debug('ответ от WAF:' + resp_code)
                    else:
                        logging.error(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|ok|'+ str(Upstream_Down.status_code) +'|Настройки не применены из-за ошибки')
                        logging.debug('ответ от WAF:'+ str(Upstream_Down.content))
                elif (upstream_status >= 1) and (upstream_changed == 0 ) : # есть доступные апстримы и нет изменений в конфиге                    
                    logging.info(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|ok|200|Есть доступные апстримы и нет изменений в конфиге')
                    logging.debug('Апстримов доступно ' + str(upstream_status) + ' изменений нет')
                else:    #Если после проверок включенных апстримов 0
                    logging.debug('Нет доступных Апстримов, настройки не применены')
                    logging.critical(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|ok|false|Нет доступных Апстримов, настройки не применены')
        elif response_upstream.status_code == 404: #код ответа при запросе апстримов не 200
            logging.critical(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|ok|'+str(response_upstream.status_code)+'|Проверь URL для подключения к mgmt')
            logging.debug(str(response_upstream.text))
        else: #код ответа при запросе апстримов не 200
            logging.critical(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|ok|'+str(response_upstream.status_code)+'|Проверь headers_ptaf или логин\пароль для подключения к mgmt')
            logging.debug(str(response_upstream.text))
    # Ошибки при выгрузке JSON
    except requests.exceptions.ConnectTimeout as error015:
        logging.critical(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|false|false|mgmt порт закрыт, невозможно извлечь конфиг upstreams')
        logging.exception(traceback.format_exc())
    except KeyError as error016:
        logging.critical(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|ok|false|Ошибка в кредах, проверь значение переменной headers_ptaf')
        logging.exception(traceback.format_exc())
    except requests.exceptions.InvalidSchema as error016:
        logging.critical(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|ok|false|Ошибка в url, проверь значение переменной url_upstreams')
        logging.exception(traceback.format_exc())
    except:
        logging.exception(traceback.format_exc())
else:   #Порт mgmt недоступен 
    logging.critical(str(id_upstreams) + '|' + str(mgmt_ptaf) +'|close|fall|Порт MGMT закрыт, проверь в чем дело')
