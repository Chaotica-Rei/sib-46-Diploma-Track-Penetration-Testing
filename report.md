# Дипломная работа по профессии «Специалист по информационной безопасности» (SIB-46, Track Penetration Testing)

## Задача

Протестировать сервис на безопасность методом чёрного ящика.\
Адрес тестируемого приложения — 92.51.39.106.

## Этап 1. Разведка

Для получения информации о предоставленном IP адресе 92.51.39.106 были использованы следующие сервисы:

- [Shodan](https://https://www.shodan.io)
- [ZoomEye](https://www.zoomeye.ai/)
- [CriminalIP](https://www.criminalip.io/)
- [Censys Platform](https://platform.censys.io)
  
В ходе разведки была получена следующая информация об IP адресе:

![](pics/92.51.39.106_osint_basic_info.png)

![](pics/92.51.39.106_osint_geo.png)

Местонахождение сервера - Россия, Санкт-Петербург\
Координаты - 59.93863, 30.31413\
Версия ОС - Ubuntu Linux 20.04\
Открытые порты с установленным ПО:
- 22/SSH - OpenBSD OpenSSH 8.2
- 8050/HTTP - веб-сайт NetologyVulnApp.com, веб-сервер Apache HTTPD 2.4.7, язык PHP 5.5.9
- 7788/HTTP - веб-сайт Beemers, веб-сервер TornadoServer 5.1.1

<details>
<summary><b>Скриншоты открытых портов</b></summary>

![](pics/92.51.39.106_osint_open_ports_ssh_22.png)

![](pics/92.51.39.106_osint_open_ports_http_8050.png)

![](pics/92.51.39.106_osint_open_ports_http_7788.png)

</details>

<details>
<summary><b>Скриншоты главных страниц обнаруженных сайтов</b></summary>

![](pics/netologyvulnapp_main_page.png)

![](pics/beemers_main_page.png)

</details>

### Аналитика собранных данных

Основываясь на полученной в ходе разведки информации, на данном этапе можно провести первичный анализ тестируемого приложения и определить вероятные цели для атаки:

- http://92.51.39.106:8050 - сервис NetologyVulnApp.com, запущенный на веб-сервере Apache HTTPD 2.4.7 (ДОПОЛНИТЬ УЯЗВИМОСТИ);
- http://92.51.39.106:7788 - сервис Beemer, запущенный на веб-сервере TornadoServer 5.1.1 (ДОПОЛНИТЬ УЯЗВИМОСТИ)
- OPENSSH?
- использование сервисами NetologyVulnApp и Beemers соединения HTTP, данный протокол не является безопасным, т.к. передаёт данные в открытом (нешифрованном) виде;
- сервис NetologyVulnApp генерирует сессионные cookie PHPSESSID, для которых не установлены флаги HttpOnly, Secure, SameSite - это потенциальный вектор для XSS и Session Hijacking атак.

![](pics/cookie_phpsessid.png)

## Этап 2. Сканирование

Для сканирования хоста использовались Open Source инструменты Nmap, Dirsearch, OWASP ZAP\
В ходе сканирования было обнаружено, что ...

**Nmap**

```sh
$ nmap -sV -T4 -p 22,8050,7788 --script vulners 92.51.39.106
```
Описание команды:

-sV - определение служб и их версий;\
-T4 - агрессивный профиль сканирования;\
-p 22,7788,8050 - список портов для сканирования;\
--script vulners - подключение скрипта для определения уязвимостей.

[Результат сканирования хоста 92.51.39.106](assets/nmap_scan_results.txt)

**Dirsearch**

```sh
$ dirsearch -u http://92.51.39.106:8050 --cookie="PHPSESSID=ccltoo7k0vvc7drerrosabjnp2" 
```
[Результат сканирования сервиса NetologyVulnApp](assets/dirsearch_8050.txt)

```sh
$ dirsearch -u http://92.51.39.105:7788 
```
[Результат сканирования сервиса Beemers](assets/dirsearch_7788.txt)

По результатам проведенного сканирования можно выделить следующие проблемы безопасности:

- неустановленные флаги `HttpOnly`, `Secure` у сессионной cookie PHPSESSID + нет привязки сессии к устройству - потенциал для XSS, CSRF атак;
- отсутствие header'a `X-frame-Options` - возможная уязвимость Clickjacking;
- включена индексация директорий - возможность эксплуатации уязвимости Path Traversal, внедрения shell-скриптов, изучения файлов приложения, конфигураций, паролей и т.д.

## Этап 3. Тестирование

Приложение тестировалось вручную и с помощью автоматического сканера уязвимостей OWASP ZAP.

**Результаты сканирования сервиса NetologyVulnApp:**

![](pics/zap_8050_report.png)

**Результаты сканирования сервиса Beemer:**

![](pics/zap_7788_report.png)

По результатам сканирования были выявлены следующие уязвимости по уровню критичности:

- $${\color{red}Высокий \ уровень}$$
  - Cross site scripting (DOM based);
  - Cross site scripting (Persistent);
  - Cross site scripting (Reflected);
  - SQL Injection;
  - Path Traversal;
  - Remote OS Command Injection.

- $${\color{orange}Средний \ уровень}$$
  - отсутствие токенов против CSRF-атак;
  - не установлен хедер Content Security Policy (CSP);
  - включена индексация директорий;
  - отсутствие хедера для защиты от clickjacking-атак;
  - использование уязвимой JS библиотеки.
  
- $${\color{lime}Низкий \ уровень}$$
  - Cookie без установленных параметров SameSite, HttpOnly;
  - отсутствие хедера X-Content-Type;
  - утечки информации о сервере через поля заголовка X-Powered-By;
  - утечки информации о версиях ПО через поля заголовка Server;
  - отсутствие хедера Strict-Transport-Security;
  

## Этап 4. Выводы