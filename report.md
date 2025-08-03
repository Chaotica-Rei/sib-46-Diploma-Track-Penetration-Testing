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

Уже на данном этапе можно провести первичный анализ тестируемого приложения на уязвимости:

- открытые порты с установленным уязвимым ПО + ДОПОЛНИТЬ
- использование сервисами NetologyVulnApp и Beemers соединения HTTP, данный протокол не является безопасным, т.к. передаёт данные в открытом (нешифрованном) виде;
- сервис NetologyVulnApp генерирует сессионные cookie PHPSESSID, для которых не установлены флаги HttpOnly и Secure - это потенциальный вектор для XSS и Session Hijacking атак.

![](pics/cookie_phpsessid.png)

## Этап 2. Сканирование

Dirsearch

```sh
$ dirsearch -u http://92.51.39.106:8050 --cookie="PHPSESSID=ccltoo7k0vvc7drerrosabjnp2" 
```
[Результат сканирования сервиса NetologyVulnApp](assets/dirsearch_8050.txt)

$ dirsearch -u http://92.51.39.105:7788 [Результат сканирования сервиса Beemers](assets/dirsearch_7788.txt)

## Этап 3. Тестирование

## Этап 4. 