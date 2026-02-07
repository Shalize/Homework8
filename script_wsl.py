from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime
import json

requests = []
responses = []

def analyze_packet(packet):
    if IP not in packet or TCP not in packet or Raw not in packet:
        return
    
    payload = bytes(packet[Raw].load)
    
    try:
        decoded = payload.decode('utf-8', errors='ignore')
        
        # REQUEST
        if decoded.startswith('GET') or decoded.startswith('POST'):
            lines = decoded.split('\r\n')
            req_line = lines[0]
            print(f"\n[REQUEST] {req_line}")
            requests.append({'type': 'REQUEST', 'data': req_line, 'time': datetime.now().isoformat()})
        
        # RESPONSE
        elif decoded.startswith('HTTP'):
            lines = decoded.split('\r\n')
            resp_line = lines[0]
            print(f"[RESPONSE] {resp_line}")
            responses.append({'type': 'RESPONSE', 'data': resp_line, 'time': datetime.now().isoformat()})
    
    except:
        pass

print("\n" + "="*70)
print("АНАЛИЗ ТРАФИКА GRUYERE - СОХРАНЕНИЕ В ФАЙЛ")
print("="*70)
print("\nОткройте Gruyere в браузере и выполняйте действия")
print("Нажми Ctrl+C для остановки и сохранения\n")

try:
    sniff(prn=analyze_packet, filter="tcp port 80 or tcp port 443", store=False)
except KeyboardInterrupt:
    print(f"\n\n✅ Перехвачено запросов: {len(requests)}")
    print(f"✅ Перехвачено ответов: {len(responses)}")
    
    # Сохраняем в JSON
    data = {
        'total_requests': len(requests),
        'total_responses': len(responses),
        'requests': requests,
        'responses': responses
    }
    
    with open('gruyere_traffic.json', 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"✅ Сохранено в gruyere_traffic.json")