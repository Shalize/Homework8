import sys
import random
import time
import socket
from scapy.all import *
from urllib.parse import urlparse
import datetime

# 1. Парсинг и подготовка (ОБНОВЛЕННЫЙ БЛОК)
if len(sys.argv) < 2:
    print("Использование: sudo python script.py https://google-gruyere.appspot.com")
    exit()

input_arg = sys.argv[1]
parsed_url = urlparse(input_arg)

# Извлекаем хост и чистим путь
dest_host = parsed_url.netloc if parsed_url.netloc else input_arg.split('/')[0]
path = parsed_url.path if parsed_url.path else "/"
path = path.replace("//", "/") # Убираем двойные слэши

if parsed_url.query:
    path += "?" + parsed_url.query

try:
    dest_ip = socket.gethostbyname(dest_host)
except socket.gaierror:
    print(f"[-] Ошибка: не удалось найти IP для {dest_host}")
    exit()

# Формируем идеальный HTTP-запрос
getStr = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {dest_host}\r\n"
    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
    f"Accept: text/html\r\n"
    f"Connection: close\r\n\r\n"
)

# 2. Обработка пакетов
def process_packet(pkt):
    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        if pkt[TCP].sport == 80:
            payload = pkt[Raw].load.decode(errors='ignore')
            if "HTTP/" in payload:
                print(f"\n[+] ОТВЕТ ОТ {dest_host}:")
                print("-" * 40)
                print(payload[:1500]) # Печатаем побольше данных
                print("-" * 40)

# 3. Запуск
print(f"[*] Цель: {dest_host} ({dest_ip})")
print(f"[*] Путь: {path}")

sniffer = AsyncSniffer(filter=f"host {dest_ip} and tcp src port 80", prn=process_packet, store=True)
sniffer.start()

try:
    # Отправляем 1 запрос (для Gruyere этого достаточно)
    client_port = random.randint(1025, 65500)
    syn = IP(dst=dest_ip) / TCP(sport=client_port, dport=80, flags='S')
    syn_ack = sr1(syn, timeout=2, verbose=False)
    
    if syn_ack and syn_ack.haslayer(TCP):
        my_seq, my_ack = syn_ack[TCP].ack, syn_ack[TCP].seq + 1
        
        # ACK
        send(IP(dst=dest_ip) / TCP(sport=client_port, dport=80, seq=my_seq, ack=my_ack, flags='A'), verbose=False)
        
        # GET
        send(IP(dst=dest_ip) / TCP(sport=client_port, dport=80, seq=my_seq, ack=my_ack, flags='PA') / getStr, verbose=False)
        print("[*] Запрос отправлен. Ждем ответ...")
    else:
        print("[-] Сервер не ответил на SYN")

finally:
    time.sleep(3)
    sniffer.stop()
    
    if sniffer.results:
        # Формируем имя файла с датой и временем
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"gruyere_traffic_{timestamp}.pcap"
        
        # Сохраняем
        wrpcap(filename, sniffer.results)
        print(f"\n[*] Трафик успешно сохранен!")
        print(f"[*] Файл: {os.path.abspath(filename)}") # Выведет полный путь к файлу
        print(f"[*] Всего пакетов в дампе: {len(sniffer.results)}")
    else:
        print("\n[-] Пакеты не были перехвачены. Файл не сохранен.")
    
    print("[*] Сессия завершена.")