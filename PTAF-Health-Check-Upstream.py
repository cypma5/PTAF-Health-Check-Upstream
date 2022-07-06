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

#Указываем путь куда класть конфиг
path = './' 
#Тут указываем ID проверяемого upstream
id_upstreams = "62b4697e95f57367fa9c25ad"
#Указываем путь для проверки
healthcheck_path = '/health'
healthcheck_host = "example.com"

#Количество изменений в конфиге
upstream_changed = 0

#IP адрес mgmt интерфейса PTAF
ip_mgmt ="192.168.56.102"

#Указываем upstream_protocol http:// или https:// нужно глянуть какой параметр указан в сервисе, возможно стоит начинать проверку с сервиса.
upstream_protocol = "http://"

#Создание директории
logger.info("Создаём директорию")
try:
    os.makedirs(path)
except OSError:
    print (now + " Создать директорию %s не удалось, возможно она уже создана" % path)
    logger.debug('Создать директорию %s не удалось, возможно она уже создана')
else:
    print (now + " Успешно создана директория %s " % path)

# Отключить warning из-за SSL
urllib3.disable_warnings()

# Создаем переменную с именем файла в который будем записывать upstreams
list_upstream = str(path) + 'config_upstream'  + '.json'

#HealthCheck ={}
HealthCheck = {}
payload_healthcheck={}
#Полезная нагрузка для проверки апстрима ( для метода POST)
payload_upstream={}
#порядковый номер апстрима в словаре
count = 0
#Обнуляем апстримы доступные
upstream_status = 0
#Задаем переменную с URL по которому выгружаем конфиг конкретного upstreams
url_upstreams = "https://"+ ip_mgmt + ":8443/api/waf/v2/upstreams" + '/' + id_upstreams

#Указываем заголовки
headers_ptaf = {'Authorization':'Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42' , 'Content-Type':'application/json'}

headers_health_check = { "User-Agent": "HealthChecker_PTAF", "Host": healthcheck_host }


#Запрашиваем список Upstreams
#v0.9.3 добавил лог ошибок при недоступности mgmt
socket_mgmt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_mgmt.settimeout(3.0)
mgmt_adr = (ip_mgmt , 8443)
result_mgmt = socket_mgmt.connect_ex(mgmt_adr)

if result_mgmt == 0:    #Если порт mgmt открыт , то переходим к загрузке JSON с апстримами
    logger.debug("Порт mgmt открыт")
    file_upstream=open( str(list_upstream) ,"wb")
    try:    #Пробуем выгрузить апстримы в JSON
        logger.debug('Пробуем выгрузить апстримы в JSON')
        response_upstream = requests.request("GET", url_upstreams, headers=headers_ptaf, data=payload_upstream, verify=False)
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
                        print(now ,  'Получили URL после условий ' , url_healthcheck)
                        logging.debug('URL Для проверки доступности Апстрима ' + url_healthcheck)
                        try:
                            logging.debug('Пробуем сделать хелчек')
                            HealthCheck =  requests.request("GET", url_healthcheck, headers=headers_health_check, data=payload_healthcheck, timeout=1 ,  verify=False)
                            logging.info('Проверяем URL ' + url_healthcheck + ' Код HTTP ответа:' + str(HealthCheck.status_code))
                            #logging.debug(str(HealthCheck.content))
                            if  (HealthCheck.status_code == 200) and (JSON_data["backends"][count]["down"] == True): #Апстрим доступен, но был выключен                                
                                #print(now , 'Апстрим выключен?:' ,JSON_data["backends"][count]["down"] )
                                #logging.info(str(JSON_data["backends"][count]["address"]) +':'+ str(JSON_data["backends"][count]["port"])+' Port is Open HTTP: OK')
                                logging.debug('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]))                            
                                JSON_data["backends"][count]["down"] = 'False'
                                #payload_upstream = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'                            
                                #print(now , 'Включили Апстрим', JSON_data["backends"][count]["address"])
                                logging.debug( 'Включили Апстрим ' + str(JSON_data["backends"][count]["address"]))
                                upstream_changed = upstream_changed + 1
                                count =  count + 1
                                upstream_status = upstream_status + 1
                                logging.debug('Доступных Апстримов: ' + str(upstream_status))
                            elif (HealthCheck.status_code == 200) and (JSON_data["backends"][count]["down"] == False): # Если апстрим доступен, и не был выключен
                                logging.info('Апстрим ' + str(JSON_data["backends"][count]["address"]) +' доступен и был включен, действий не требуется ')
                                count =  count + 1
                                upstream_status = upstream_status + 1
                                logging.info('Доступных Апстримов: '+ str(upstream_status))
                            elif (HealthCheck.status_code != 200) and (JSON_data["backends"][count]["down"] == False): # Если апстрим недоступен, и не был включен :
                                logging.debug(str(HealthCheck.content))
                                logging.info('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]))
                                JSON_data["backends"][count]["down"] = 'True'
                                logging.info('Меняем значение на: ' +JSON_data["backends"][count]["down"])
                                upstream_changed = upstream_changed + 1
                                count =  count + 1
                                print(now , 'Доступных Апстримов:', upstream_status)
                                logging.info('Доступных Апстримов: '+ str(upstream_status))
                            else:
                                logging.debug(str(HealthCheck.content))
                                logging.info('Апстрим был выключен: ' + str(JSON_data["backends"][count]["down"]) + ' и не ответил на HealthCheck')
                                logging.info('Доступных Апстримов: '+ str(upstream_status))
                                count =  count + 1
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
                            print(now,'6 проверь Headers которые отправляешь на аптсрим',error6)
                            logging.error('error6 проверь Headers которые отправляешь на аптсрим ')
                        except requests.exceptions.SSLError as error8:
                            print(now,'error8',error8)
                            print(now,'error8','Отправка https трафика на порт ожидающий http')
                            logging.error('error8')
                            logging.critical('Check variable upstream_protocol Отправка https трафика на порт ожидающий http')
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
                    payload_upstream = '{"backends":' + json.dumps(JSON_data["backends"]) + '}'
                    Upstream_Down = requests.request("PATCH", url_upstreams, headers=headers_ptaf, data=payload_upstream, verify=False)
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
        print(now,error)
        logging.critical('error1-1')
        logging.critical(error)
    except urllib3.exceptions.ConnectTimeoutError as error:
        print(now,error)
        logging.critical('error1-2')
        #logging.exception(error)
    except urllib3.exceptions.MaxRetryError as error:
        print(now,error)
        logging.critical('error1-3')
        logging.critical(error)
    except urllib3.exceptions.ConnectTimeoutError as error:
        print(now,error)
        logging.critical('error1-4')
        logging.critical(error)
    except requests.exceptions.ConnectTimeout as error:
        print(now,error)
        logging.critical('mgmt порт закрыт, невозможно извлечь конфиг upstreams')
        logging.critical(error)
    except KeyError as error:
        print('Ошибка в кредах, проверь связку логин + пароль')
        logging.critical('Ошибка в кредах, проверь связку логин + пароль')
        logging.critical(error)
    except InsecureRequestWarning as error:
        print('Неудалось проверить сертификат?')
        logging.critical('Неудалось проверить сертификат?')
        logging.critical(error)


else:   #Порт mgmt недоступен 
    print('Порт MGMT закрыт, проверь в чем дело')
    logging.critical('Порт MGMT закрыт, проверь в чем дело')


