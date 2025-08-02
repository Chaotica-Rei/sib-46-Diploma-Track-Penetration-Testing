# Дипломная работа по профессии «Специалист по информационной безопасности» (SIB-46, Track Penetration Testing)

## Задача

Протестировать сервис на безопасность методом чёрного ящика.\
Известен только адрес тестируемого приложения — 92.51.39.106.\

## Этап 1. Разведка

Для получения информации об адресе 92.51.39.106 были использованы следующие сервисы:

- [Shodan](https://https://www.shodan.io)
- [ZoomEye](https://www.zoomeye.ai/)
- [CriminalIP](https://www.criminalip.io/)
- [Censys Platform](https://platform.censys.io)
  
В ходе разведки была получена следующая информация об адресе:

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


## Этап 2. Сканирование

## Этап 3. Тестирование

## Этап 4. 