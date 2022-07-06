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
result_mgmt = socket_mgmt.connect_ex(mgmt_adr)

if result_mgmt == 0:    #Если порт mgmt открыт , то переходим к загрузке JSON с апстримами
    logger.debug("Порт mgmt открыт")
    file_upstream=open( str(list_upstream) ,"wb")
    try:    #Пробуем выгрузить апстримы в JSON
        logger.debug('Пробуем выгрузить апстримы в JSON')
        response_upstream = requests.request("GET", url_upstreams, headers=headers_ptaf, data=payload_ptaf, verify=False)
        if response_upstream.status_code == 200:
            print(' Код ответа от PTAF: ' ,response_upstream.status_code)
            logger.info(" Код ответа от PTAF: " + str(response_upstream.status_code) )
            file_upstream.write(response_upstream.content)
            file_upstream.close()
            #Открываем JSON 
            with open( str(list_upstream), encoding = 'UTF-8') as file_upstream:
                logger.debug("Открываем JSON")
                JSON_data = json.load(file_upstream)
                logging.debug('JSON с Апстримами  ' + str(JSON_data["addresses"]))
                for n in JSON_data['addresses']:    #Запускаем цикл проверки
                    logging.info('Проверка Апстрима: '+ str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]))
                    logging.debug('Проверка доступности порта')
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3.0)
                    result_upstream = sock.connect_ex((JSON_data["backends"][count]["address"],JSON_data["backends"][count]["port"]))
                    #Если порт открыт, то переходим к проверке http
                    if result_upstream == 0: #Если порт открыт то
                        logging.debug('Порт открыт, то переходим к проверке http')
                        logging.info(str(JSON_data["backends"][count]["address"]) +':'+ str(JSON_data["backends"][count]["port"])+' Port is Open')
                        #Генерируем URL для проверки
                        #Есть проблемы если указан порт не стандартный, нужно указывать из Service. Большая доработка. Если перепутаны протоколы, сыпет ошибками когда на hhttp ломишься по https, и тому подобное.
                        #В настройках сервиса указывается       "upstream_protocol": "http",
                        if ((JSON_data["backends"][count]["port"] == 80) or (JSON_data["backends"][count]["port"] == 443)):            
                            url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+ healthcheck_path
                        else:
                            url_healthcheck = upstream_protocol + str(JSON_data["backends"][count]["address"])+':'+ str(JSON_data["backends"][count]["port"]) + healthcheck_path
                        print('Получили URL после условий ' , url_healthcheck)
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
                        except TimeoutError as error1:
                            print('1',error1)
                            logging.error('error1 HTTP_Health_check TimeoutError')
                        except urllib3.exceptions.ConnectTimeoutError as error2:
                            print('2',error2)
                            logging.error('error2 HTTP_Health_check urllib3.exceptions.ConnectTimeoutError')
                        except urllib3.exceptions.MaxRetryError as error3:
                            print('3',error3)
                            logging.error('error3 HTTP_Health_check urllib3.exceptions.ConnectTimeoutError')
                        except urllib3.exceptions.ConnectTimeoutError as error4:
                            print('4',error4)
                            logging.error('error4 HTTP_Health_check urllib3.exceptions.ConnectTimeoutError')
                        except requests.exceptions.ConnectTimeout as error5:
                            print('error5',error5)
                            print('error5','Отправка https трафика на порт ожидающий http')
                            count =  count + 1
                            logging.critical('HTTP_Health_check Check variable upstream_protocol Отправка https трафика на порт ожидающий http')
                        except AttributeError as error6:
                            print('6 проверь Headers которые отправляешь на аптсрим',error6)
                            logging.error('error6 HTTP_Health_check проверь Headers которые отправляешь на аптсрим ')
                        except requests.exceptions.SSLError as error8:
                            print('error8',error8)
                            print('error8','Отправка https трафика на порт ожидающий http')
                            logging.error('error8')
                            logging.critical('HTTP_Health_check Check variable upstream_protocol Отправка https трафика на порт ожидающий http')
                    else: #Если порт закрыт то
                        logging.debug('инче если порт апстима закрыт ')
                        logging.warning(str(JSON_data["backends"][count]["address"]) +':'+ str(JSON_data["backends"][count]["port"])+' Port is Closed')
                        if str(JSON_data["backends"][count]["down"]) == 'False' : # если был включен то выключить
                            logging.debug(' порт апстрима закрыт но до проврки апстрим был включен')
                            print(now ,'Апстрим выключен?:' ,JSON_data["backends"][count]["down"] )
                            logging.info('Апстрим выключен?: ' + str(JSON_data["backends"][count]["down"]))
                            JSON_data["backends"][count]["down"] = 'True'
                            print(now , 'Меняем значение на:' ,JSON_data["backends"][count]["down"] )
                            logging.info('Меняем значение на:' +JSON_data["backends"][count]["down"])
                            upstream_changed = upstream_changed + 1
                            count =  count + 1
                            print(now , 'Доступных Апстримов:', upstream_status)
                            logging.info('Доступных Апстримов: '+ str(upstream_status))
                        else : #если был выключен то ничего не делаем
                            logging.debug('порт апстрима закрыт и до проверки был выключен')
                            logging.info('Апстрим выключен?: ' + str(JSON_data["backends"][count]["down"]) + ' Действие не требуется')
                            logging.info('Доступных Апстримов: '+ str(upstream_status))
                            count =  count + 1
                    sock.close()
                if (upstream_status >= 1) and (upstream_changed >= 1) :    #Если после проверок включенных апстримов >= 1 и изменено больше одного апстрима то.
                    logging.debug('Если после проверок включенных апстримов >= 1 и изменено больше одного апстрима то.')
                    logging.warn('Доступных апстримов больше >= 1 :' + str(upstream_status) + ' Требуется изменить конфигурацию для' + str(upstream_changed))
                    payload_ptaf = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'
                    Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_ptaf, data=payload_ptaf, verify=False)
                    if  Upstream_Down.status_code == 200:
                        print(now , 'Настройки применены код ответа от WAF:' + str(Upstream_Down.status_code) )
                        logging.info('Настройки применены код ответа от WAF:' + str(Upstream_Down.status_code))
                        resp_code = str(Upstream_Down.content)
                        print(now , 'ответ от WAF:' + resp_code )
                        logging.debug('ответ от WAF:' + resp_code)
                    else:
                        logging.error('Настройки не применены из за ошибки')
                        logging.error('ответ от WAF:'+ str(Upstream_Down.status_code) +' '+ str(Upstream_Down.content))
                elif (upstream_status >= 1) and (upstream_changed == 0 ) :
                    logging.info('Апстримов доступно ' + str(upstream_status) + ' изменений нет')
                else:    #Если после проверок включенных апстримов 0
                    logging.critical('Нет доступных Апстримов, настройки не применены')
        else: #код ответа при запросе апстримов не 200
            print('Проверь логин\пароль для подключения к mgmt')
            print('Код ответа: ',response_upstream.status_code)
            print(response_upstream.content)
            logging.error('Проверь логин\пароль для подключения к mgmt','Код ответа: ',response_upstream.status_code,'Тело ответа:',response_upstream.content)
    except TimeoutError as error:
        print(error)
        logging.critical('error9 PTAF_JSON TimeoutError')
        logging.critical(error)
    except urllib3.exceptions.ConnectTimeoutError as error:
        print(error)
        logging.critical('error10 PTAF_JSON urllib3.exceptions.ConnectTimeoutError')
        #logging.exception(error)
    except urllib3.exceptions.MaxRetryError as error:
        print(error)
        logging.critical('error11 PTAF_JSON urllib3.exceptions.MaxRetryError')
        logging.critical(error)
    except urllib3.exceptions.ConnectTimeoutError as error:
        print(error)
        logging.critical('error12 PTAF_JSON urllib3.exceptions.ConnectTimeoutError')
        logging.critical(error)
    except requests.exceptions.ConnectTimeout as error:
        print(error)
        logging.critical('error13 PTAF_JSON mgmt порт закрыт, невозможно извлечь конфиг upstreams')
        logging.critical(error)
    except KeyError as error:
        print('Ошибка в кредах, проверь связку логин + пароль')
        logging.critical('error14 PTAF_JSON Ошибка в кредах, проверь связку логин + пароль')
        logging.critical(error)
    except InsecureRequestWarning as error:
        print('Неудалось проверить сертификат?')
        logging.critical('error15 PTAF_JSON Неудалось проверить сертификат?')
        logging.critical(error)


else:   #Порт mgmt недоступен 
    print('Порт MGMT закрыт, проверь в чем дело')
    logging.critical('PTAF_Network Порт MGMT закрыт, проверь в чем дело')


