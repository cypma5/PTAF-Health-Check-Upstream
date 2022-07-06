# Мониторинг состояния ElasticSearch в PTAF с помощью Zabbix-Agent
# PTAF-Health-Check-Upstream
# Python3.X PTAF 3.7.3.1200
# Для равнозначных фронтов, без бекапов, и весов, работа с sticky не проверялась.


# Настройка конфига 
1. Путь куда выгружать JSON с параметрами `path = '/Some/Dirrectory'`

`id_upstreams = "62b4697e95f57367fa9c25ad"` - Нужно подставить значение своего апстрима.

` healthcheck_path = '/'` -Указываем путь для проверки

`healthcheck_host = "example.com" `- Указываем значение которое будет передаваться в заголовке Host:

`ip_mgmt ="192.168.56.102"` - IP адрес mgmt интерфейса PTAF



`upstream_protocol = "http://"`  - Указываем upstream_protocol http:// или https:// 

`payload_upstream={}` - (Не проверялось) Полезная нагрузка для проверки апстрима ( для метода POST)

`headers_ptaf = {'Authorization':'Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42' , 'Content-Type':'application/json'}` - Указываем заголовки для подключения к MGMT PTAF 


#Добавляем задачу в крон - это раз в минуту, как чаще сделать пока не думал.
*/1 * * * * python3.5 /home/pt/PTAF-Health-Check-Upstream/PTAF-Health-Check-Upstream.py
