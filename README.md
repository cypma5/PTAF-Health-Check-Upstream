# PTAF-Health-Check-Upstream

Для версии Python 3.9
Для версии PTAF 3.7.3.1200
Для равнозначных фронтов, без бекапов, и весов, работа с sticky не проверялась.

#Указываем путь куда класть конфиг
path = '/Users/USER/Documents/PTAF_HealthCheck' 

#Тут указываем ID проверяемого upstream.
id_upstreams = "62b4697e95f57367fa9c25ad"
#Указываем путь для проверки
healthcheck_path = '/'
#Указываем значение которое будет передаваться в заголовке Host:
healthcheck_host = "example.com"

#IP адрес mgmt интерфейса PTAF
ip_mgmt ="192.168.56.102"

#Указываем upstream_protocol http:// или https:// нужно глянуть какой параметр указан в сервисе, возможно стоит начинать проверку с сервиса.
upstream_protocol = "http://"

#Полезная нагрузка для проверки апстрима ( для метода POST)
payload_upstream={}

#Указываем заголовки для подключения к MGMT PTAF 
headers_ptaf = {'Authorization':'Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42' , 'Content-Type':'application/json'}
