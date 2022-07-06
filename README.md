# Общее описание
Скрипт проверяющий состояние апстримов. В случае недоступности через API переводит апстрим в статус DOWN.
Создано на Python3.X 
Прверено на PTAF 3.7.3.1200

#Применимость
Для равнозначных фронтов, без бекапов, и весов, работа с sticky не проверялась.

#Подготовительные настройки

1. Создать учетную запись на PTAF с правами на редактирование Upstreams can_edit
Закодировать связку 
`login:password` в Base64
В параметре `headers_ptaf` поменять значение `Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42` на своё


# Описание  переменных в конфиге
1. Путь куда выгружать JSON с параметрами `path = './' `

`id_upstreams = "62b4697e95f57367fa9c25ad"` - Нужно подставить значение своего апстрима.

`healthcheck_path = '/health'` -Указываем путь для проверки

`healthcheck_host = "example.com"`- Указываем значение которое будет передаваться в заголовке Host: на хелсчек

`ip_mgmt ="192.168.56.102"` - IP адрес mgmt интерфейса PTAF

`upstream_protocol = "http://"`  - Указываем upstream_protocol http:// или https:// 

`payload_healthcheck={}` - (Не проверялось) Полезная нагрузка для проверки апстрима ( для метода POST)

`headers_ptaf = {'Authorization':'Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42' , 'Content-Type':'application/json'}` - Указываем заголовки для подключения к MGMT PTAF 

`headers_health_check = { "User-Agent": "HealthChecker_PTAF", "Host": healthcheck_host }` - заголовки передаваемые на апстрим при HealthCheck

#Добавляем задачу в крон - это раз в минуту, как чаще сделать пока не думал.
*/1 * * * * python3.5 /home/pt/PTAF-Health-Check-Upstream/PTAF-Health-Check-Upstream.py
