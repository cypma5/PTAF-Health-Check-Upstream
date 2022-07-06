#v1.1.2
#Исправил logging на logger
import requests
import datetime
import urllib3
import json
import os
import socket
import logging

#Creating and Configuring Logger

Log_Format = " %(asctime)s [%(levelname)s] - %(message)s"

logging.basicConfig(filename = "/var/log/ptaf-healthcheck.log",
                    filemode = "a", #Добавление строк в лог
                    #filemode = "w", #перезаписывать файл
                    format = Log_Format,
                    level = logging.DEBUG) 
                    #level = logging.INFO)

logger = logging.getLogger()


#Testing our Logger

logger.info("________________________________Start Script________________________________")
logger.debug('ВКЛЮЧЕН РЕЖИМ ДЕБАГА')

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
ip_mgmt ="192.168.56.102"
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
logger.info("Создаём директорию")
try:
    os.makedirs(path)
except OSError:
    print (" Создать директорию %s не удалось, возможно она уже создана" % path)
    logger.debug('Создать директорию %s не удалось, возможно она уже создана')
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
    logger.critical('PTAF_NETWORK Указан некорректный IP адрес')
    logger.exception(error)

if result_mgmt == 0:    #Если порт mgmt открыт , то переходим к загрузке JSON с апстримами
    logger.debug("PTAF_NETWORK Порт mgmt открыт")
    file_upstream=open( str(list_upstream) ,"wb")
    try:    #Пробуем выгрузить апстримы в JSON
        logger.debug('PTAF_JSON Пробуем выгрузить апстримы в JSON')
        response_upstream = requests.request("GET", url_upstreams, headers=headers_ptaf, data=payload_ptaf, verify=False)
        if response_upstream.status_code == 200:
            print(' Код ответа от PTAF: ' ,response_upstream.status_code)
            logger.info("PTAF_JSON Код ответа от PTAF: " + str(response_upstream.status_code) )
            file_upstream.write(response_upstream.content)
            file_upstream.close()
            #Открываем JSON 
            with open( str(list_upstream), encoding = 'UTF-8') as file_upstream:
                logger.debug("PTAF_JSON Открываем JSON")
                JSON_data = json.load(file_upstream)
                logger.debug('PTAF_JSON JSON с Апстримами  ' + str(JSON_data["addresses"]))
                for n in JSON_data['addresses']:    #Запускаем цикл проверки
                    logger.info('Проверка Апстрима: '+ str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]))
                    logger.debug('Проверка доступности порта')
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3.0)
                    result_upstream = sock.connect_ex((JSON_data["backends"][count]["address"],JSON_data["backends"][count]["port"]))
                    #Если порт открыт, то переходим к проверке http
                    if result_upstream == 0: #Если порт открыт то
                        logger.debug('Порт открыт, то переходим к проверке http')
                        logger.info(str(JSON_data["backends"][count]["address"]) +':'+ str(JSON_data["backends"][count]["port"])+' Port is Open')
                        #Генерируем URL для проверки
                        #Есть проблемы если указан порт не стандартный, нужно указывать из Service. Большая доработка. Если перепутаны протоколы, сыпет ошибками когда на hhttp ломишься по https, и тому подобное.
                        #В настройках сервиса указывается       "upstream_protocol": "http",
                        if ((JSON_data["backends"][count]["port"] == 80) or (JSON_data["backends"][count]["port"] == 443)):            
                            url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+ healthcheck_path
                        else:
                            url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) + healthcheck_path
                        #print('Получили URL после условий ' , url_healthcheck)
                        logger.debug('URL Для проверки доступности Апстрима ' + url_healthcheck)
                        try:
                            logger.debug('Пробуем сделать хелчек')
                            response_health_check =  requests.request("GET", url_healthcheck, headers=headers_health_check, data=payload_healthcheck, timeout=1 ,  verify=False)
                            logger.info('Проверяем URL ' + url_healthcheck + ' Код HTTP ответа:' + str(response_health_check.status_code))
                            #logger.debug(str(response_health_check.content))
                            if  (response_health_check.status_code == 200) and (JSON_data["backends"][count]["down"] == True): #Апстрим доступен, но был выключен                                
                                #print('Апстрим выключен?:' ,JSON_data["backends"][count]["down"] )
                                #logger.info(str(JSON_data["backends"][count]["address"]) +':'+ str(JSON_data["backends"][count]["port"])+' Port is Open HTTP: OK')
                                logger.debug('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]))                            
                                JSON_data["backends"][count]["down"] = 'False'                           
                                #print('Включили Апстрим', JSON_data["backends"][count]["address"])
                                logger.debug( 'Включили Апстрим ' + str(JSON_data["backends"][count]["address"]))
                                upstream_changed = upstream_changed + 1
                                count =  count + 1
                                upstream_status = upstream_status + 1
                                logger.debug('Доступных Апстримов: ' + str(upstream_status))
                            elif (response_health_check.status_code == 200) and (JSON_data["backends"][count]["down"] == False): # Если апстрим доступен, и не был выключен
                                logger.info('Апстрим ' + str(JSON_data["backends"][count]["address"]) +' доступен и был включен, действий не требуется ')
                                count =  count + 1
                                upstream_status = upstream_status + 1
                                logger.info('Доступных Апстримов: '+ str(upstream_status))
                            elif (response_health_check.status_code != 200) and (JSON_data["backends"][count]["down"] == False): # Если апстрим недоступен, и не был включен :
                                logger.debug(str(response_health_check.content))
                                logger.info('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]))
                                JSON_data["backends"][count]["down"] = 'True'
                                logger.info('Меняем значение на: ' +JSON_data["backends"][count]["down"])
                                upstream_changed = upstream_changed + 1
                                count =  count + 1
                                print('Доступных Апстримов:', upstream_status)
                                logger.info('Доступных Апстримов: '+ str(upstream_status))
                            else:
                                logger.debug(str(response_health_check.content))
                                logger.info('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]) + ' и не ответил на HealthCheck')
                                logger.info('Доступных Апстримов: '+ str(upstream_status))
                                count =  count + 1
                        #Ошибки при выполнении хелсчека
                        except TimeoutError as error001:                            
                            logger.error('HTTP_Health_check TimeoutError')
                            logger.exception(error001)
                        except urllib3.exceptions.ConnectTimeoutError as error002:                            
                            logger.error('HTTP_Health_check urllib3.exceptions.ConnectTimeoutError')
                            logger.exception(error002)
                        except urllib3.exceptions.MaxRetryError as error003:                            
                            logger.error('HTTP_Health_check urllib3.exceptions.ConnectTimeoutError')
                            logger.exception(error003)
                        except urllib3.exceptions.ConnectTimeoutError as error004:                            
                            logger.error('HTTP_Health_check urllib3.exceptions.ConnectTimeoutError')
                            logger.exception(error004)
                        except requests.exceptions.ConnectTimeout as error005:
                            count =  count + 1                            
                            logger.critical('HTTP_Health_check Check variable upstream_protocol Отправка https трафика на порт ожидающий http')
                            logger.exception(error005)
                        except AttributeError as error006:                            
                            logger.error('HTTP_Health_check проверь Headers которые отправляешь на апстрим ')
                            logger.critical(error006)
                        except requests.exceptions.SSLError as error008:
                            logger.critical('HTTP_Health_check Check variable upstream_protocol Отправка https трафика на порт ожидающий http')
                            logger.exception(error008)
                    else: #Если порт закрыт то
                        logger.debug('инче если порт апстима закрыт ')
                        logger.warning(str(JSON_data["backends"][count]["address"]) +':'+ str(JSON_data["backends"][count]["port"])+' Port is Closed')
                        if str(JSON_data["backends"][count]["down"]) == 'False' : # если был включен то выключить
                            logger.debug(' порт апстрима закрыт но до проврки апстрим был включен')
                            logger.info('Апстрим выключен?: ' + str(JSON_data["backends"][count]["down"]))
                            JSON_data["backends"][count]["down"] = 'True'
                            logger.info('Меняем значение на:' +JSON_data["backends"][count]["down"])
                            upstream_changed = upstream_changed + 1
                            count =  count + 1
                            logger.info('Доступных Апстримов: '+ str(upstream_status))
                        else : #если был выключен то ничего не делаем
                            logger.debug('порт апстрима закрыт и до проверки был выключен')
                            logger.info('Апстрим выключен?: ' + str(JSON_data["backends"][count]["down"]) + ' Действие не требуется')
                            logger.info('Доступных Апстримов: '+ str(upstream_status))
                            count =  count + 1
                    sock.close()
                if (upstream_status >= 1) and (upstream_changed >= 1) :    #Если после проверок включенных апстримов >= 1 и изменено больше одного апстрима то.
                    logger.debug('Если после проверок включенных апстримов >= 1 и изменено больше одного апстрима то.')
                    logger.warn('Доступных апстримов больше >= 1 :' + str(upstream_status) + ' Требуется изменить конфигурацию для' + str(upstream_changed))
                    payload_ptaf = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'
                    Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_ptaf, data=payload_ptaf, verify=False)
                    if  Upstream_Down.status_code == 200:
                        logger.info('Настройки применены код ответа от WAF:' + str(Upstream_Down.status_code))
                        resp_code = str(Upstream_Down.content)
                        logger.debug('ответ от WAF:' + resp_code)
                    else:
                        logger.error('Настройки не применены из за ошибки')
                        logger.error('ответ от WAF:'+ str(Upstream_Down.status_code) +' '+ str(Upstream_Down.content))
                elif (upstream_status >= 1) and (upstream_changed == 0 ) :
                    logger.info('Апстримов доступно ' + str(upstream_status) + ' изменений нет')
                else:    #Если после проверок включенных апстримов 0
                    logger.critical('Нет доступных Апстримов, настройки не применены')
        else: #код ответа при запросе апстримов не 200
            logger.error('Проверь headers_ptaf или логин\пароль для подключения к mgmt','Код ответа: ',response_upstream.status_code,'Тело ответа:',response_upstream.content)
    except TimeoutError as error011:
        logger.critical('PTAF_JSON TimeoutError')
        logger.exception(error011)
    except urllib3.exceptions.ConnectTimeoutError as error012:
        logger.critical('PTAF_JSON urllib3.exceptions.ConnectTimeoutError')
        logger.exception(error012)
    except urllib3.exceptions.MaxRetryError as error013:
        logger.critical('PTAF_JSON urllib3.exceptions.MaxRetryError')
        logger.exception(error013)
    except urllib3.exceptions.ConnectTimeoutError as error014:
        logger.critical('PTAF_JSON urllib3.exceptions.ConnectTimeoutError')
        logger.exception(error014)
    except requests.exceptions.ConnectTimeout as error015:
        logger.critical('PTAF_JSON mgmt порт закрыт, невозможно извлечь конфиг upstreams')
        logger.exception(error015)
    except KeyError as error016:
        logger.critical('PTAF_JSON Ошибка в кредах, проверь значение переменной headers_ptaf')
        logger.exception(error016)
    except InsecureRequestWarning as error017:
        logger.critical('PTAF_JSON Неудалось проверить сертификат?')
        logger.exception(error017)


else:   #Порт mgmt недоступен 
    logger.critical('PTAF_NETWORK' + str(ip_mgmt) +' Порт MGMT закрыт, проверь в чем дело')