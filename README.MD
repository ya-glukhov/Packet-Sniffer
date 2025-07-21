# 🐍 Packet Sniffer (Python)

Консольное приложение на Python для захвата и анализа сетевых пакетов.  
A simple console-based packet sniffer written in **Python**.

---

## Возможности/Features

- Снифинг **TCP / UDP / DNS** трафика / Capture **TCP / UDP / DNS** traffic
- Цветной вывод в терминал / Live **colored console output**
- Подсчёт и итоговая статистика / Packet **statistics** summary
- Сохранение в .pcap и .txt файл / Save traffic to .pcap and log to .txt

---

## Зависимости / Dependencies

- `scapy` — захват и разбор пакетов / packet sniffing and parsing  
- `argparse` — аргументы командной строки / CLI argument parsing  
- `colorama` — цветной вывод в терминал / colored console output  

---

## Аргументы / Arguments
- -i — имя интерфейса(e.g. eth0, lo, etc.) / interface name (e.g. eth0, lo, etc.)
- -c — количество пакетов для захвата (0 = infinite) / number of packets to capture (0 = infinite)
- -p — фильтр протокола: tcp, udp, icmp, or all / protocol filter: tcp, udp, icmp, or all
- --save — путь для сохранения пакетов(.pcap) / path to save packets (.pcap)

---

## Пример запуска / Example usage

```bash
python3 sniffer.py -i eth0 -c 10 -p all --save traffic.pcap

