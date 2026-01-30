import sys
import random
import time
from scapy.all import *

# 1. Параметры
if len(sys.argv) < 2:
    print("Использование: sudo python script.py example.com")
    exit()

dest = sys.argv[1]
max_req = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 5
port = 80

# ВАЖНО: Добавлен Host и правильные переносы строк
getStr = f"GET / HTTP/1.1\r\nHost: {dest}\r\nUser-Agent: Scapy\r\nConnection: close\r\n\r\n"

def process_packet(pkt):
    if pkt.haslayer(Raw):
        try:
            # Декодируем данные
            payload = pkt[Raw].load.decode(errors='ignore')
            
            # Проверяем, что это начало ответа
            if "HTTP/" in payload and "\r\n\r\n" in payload:
                # Разделяем на заголовки и тело (максимум 1 раз)
                header_part, body_part = payload.split("\r\n\r\n", 1)
                
                print("\n" + "="*50)
                print(" [!] ПОЛУЧЕНЫ ЗАГОЛОВКИ:")
                print(header_part)
                print("="*50)
                
                if body_part.strip():
                    print(" [!] ТЕЛО ОТВЕТА (HTML):")
                    print(body_part)
                else:
                    print(" [!] Тело ответа в этом пакете пусто (возможно, оно в следующем)")
                print("="*50 + "\n")
                
            # Если пакет не содержит HTTP-заголовка, но содержит данные 
            # (это «хвосты» больших ответов)
            elif not payload.startswith("HTTP/"):
                print(" [!] ДОПОЛНИТЕЛЬНЫЕ ДАННЫЕ (ЧАСТЬ ТЕЛА):")
                print(payload)
                
        except Exception as e:
            print(f"Ошибка парсинга: {e}")

# 2. Сниффер (убрали src port для теста, ловим всё от хоста)
print(f"[*] Цель: {dest}, Запросов: {max_req}")
sniffer = AsyncSniffer(filter=f"host {dest}", prn=process_packet, store=False)
sniffer.start()

try:
    for i in range(max_req):
        # Очистка кэша ответов перед новым запросом
        client_port = random.randint(1025, 65500)
        
        # ШАГ 1: SYN
        syn = IP(dst=dest) / TCP(sport=client_port, dport=port, flags='S')
        syn_ack = sr1(syn, timeout=2, verbose=False)
        
        if syn_ack and syn_ack.haslayer(TCP):
            # ШАГ 2: ACK
            my_seq = syn_ack[TCP].ack
            my_ack = syn_ack[TCP].seq + 1
            ack_pkt = IP(dst=dest) / TCP(sport=client_port, dport=port, seq=my_seq, ack=my_ack, flags='A')
            send(ack_pkt, verbose=False)

            # ШАГ 3: GET (отправляем сразу после ACK)
            get_pkt = IP(dst=dest) / TCP(sport=client_port, dport=port, seq=my_seq, ack=my_ack, flags='PA') / getStr
            send(get_pkt, verbose=False)
            print(f"[*] Запрос {i+1} отправлен на порт {client_port}...")
        else:
            print(f"[-] Сервер {dest} не ответил на SYN (Timeout)")
        
        time.sleep(1)

finally:
    time.sleep(2) # Даем время на догрузку данных
    sniffer.stop()
    print("[*] Готово.")