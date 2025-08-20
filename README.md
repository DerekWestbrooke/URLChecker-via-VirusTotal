# URLChecker-via-VirusTotal
Данный скрипт, написанный на Python, предназначен для проверки URL через API ресурса VirusTotal. Взаимодействие с VirusTotal проходит через requests, позволяющей взаимодействовать с ресурсом через API, который пользователь получает после регистрации на ресурсе. Результаты на сторону пользователя возвращаются в json-формате, с которым отлично справляется библиотека json. Для красоты результатов отображения в консоли используется библиотека PrettyTable, которая представляет результат в виде эрганомичной таблицы.  

В первую очередь переходим на сайт https://www.virustotal.com и регистрируемся. После регистрации будет доступен ключ для API.  
  
![install](images/api.png)  

В скрипт, представленный ниже устанавливаем свой API и запускаем:

```
import json
import requests
from prettytable import PrettyTable

green = '\033[32m'
red = '\033[31m'
blue = '\033[34m'
reset = '\033[0m'

personal_api_key = {API_Key}

input_url = str(input(f"{blue}Enter you URL:{reset} "))

virustotal_url_scan = 'https://www.virustotal.com/vtapi/v2/url/scan'
virustotal_url_report = 'https://www.virustotal.com/vtapi/v2/url/report'

scan_data = {
    'apikey': personal_api_key,
    'url': input_url
}

scan_response = requests.post(virustotal_url_scan, data=scan_data)

if scan_response.status_code == 200:
    scan_id = scan_response.json().get("scan_id")

    report_params = {
        'apikey': personal_api_key,
        'resource': scan_id
    }

    report_response = requests.get(virustotal_url_report, params=report_params)

    if report_response.status_code == 200:
        report_result = report_response.json().get("scans")

        result_table = PrettyTable()
        result_table.field_names = ["test", "detected", "result"]

        for key, value in report_result.items():
            if str(value['detected']) == "True":
                result_table.add_row([key, red + str(value['detected']) + reset, value['result']])
            else:
                result_table.add_row([key, green + str(value['detected']) + reset, value['result']])
        print(result_table)
    else:
        print(f"Ошибка в ходе получения отчета: {report_response.status_code}")

else:
    print(f"Ошибка при проверке url: {response.status_code}")

```

Далее для проверки работы скрипта вводим URL сайта, например GitHub. Результат работы приведен ниже:

![install](images/gh_1.png)  
![install](images/gh_2.png)
![install](images/gh_3.png)
![install](images/gh_4.png)
![install](images/gh_5.png)  

Теперь введем URL сайта, который может вызвать подозрение, например сайт для скачивания игры через торрент. Результат работы приведен ниже:

![install](images/tor_1.png)  
![install](images/tor_2.png)
![install](images/tor_3.png)
![install](images/tor_4.png)
![install](images/tor_5.png)  

Таким образом, в строках со значением "True", выделенных красным цветом, явно указывает на класс угрозы.

