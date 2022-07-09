# Общее описание
Скрипт проверяющий состояние апстримов. В случае недоступности через API переводит апстрим в статус DOWN.
- Создано на Python3.X 
- Прверено на PTAF 3.7.3.1200

# Применимость
 1. active-active (Не проверялась) не рекомендуется, может некорректно работать если на одной из нод будет недоступен апстрим.
 2. active-standby (Не проверялась)
 3. standalone - проверено, работает

- Работа с включенным sticky sessions : Не проверялась
- Работа c разными весами : Не проверялась
- Работа с включенным transparency : Не проверялась
- При применении изменений не проверялось на прерывание сервиса.

# Подготовительные настройки

1. Создать учетную запись на PTAF с правами на редактирование Upstreams can_edit
2. Закодировать связку `login:password` в Base64
3. В параметре `authorization_cred` поменять значение `Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42` на своё


# Описание  переменных в конфиге config.ini
- Путь куда выгружать JSON с параметрами `path = './' `

- `id_upstreams = "62b4697e95f57367fa9c25ad"` - Нужно подставить значение своего апстрима.

- `healthcheck_path = '/health'` -Указываем путь для проверки

- `healthcheck_host = "example.com"`- Указываем значение которое будет передаваться в заголовке Host: на хелсчек

- `ip_mgmt ="192.168.56.102"` - IP адрес mgmt интерфейса PTAF

- `upstream_protocol = "http://"`  - Указываем upstream_protocol http:// или https:// 

- `payload_healthcheck={}` - (Не проверялось) Полезная нагрузка для проверки апстрима ( для метода POST)


- `authorization_cred = Basic YXBpYzp4WUE3T2dQbDIwRXVpc3UyazRadTYxYm42` - указываем login:password в BASE64

- `headers_health_check = { "User-Agent": "HealthChecker_PTAF", "Host": healthcheck_host }` - заголовки передаваемые на апстрим при HealthCheck

# Выполнение по рассписанию
crontab

*/1 * * * * python3.5 /home/pt/PTAF-Health-Check-Upstream/PTAF-Health-Check-Upstream.py

# Обработка логов
- Сделал разные уровни логирования
- Описал возникающие ошибки

# Доработки в планах
- Вынести задаваемые параметры в конфиг, для запуска проверки апстрима с ключем с указанием конфига.
- включить bypass в случае недоступности всех фронтов
- Добавить тестовый режим
