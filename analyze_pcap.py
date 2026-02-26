import pyshark
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import json
import csv
from datetime import datetime
from collections import Counter

DHCP_FILE = 'dhcp.pcapng'
DNS_FILE = 'dns_capture.pcapng'


# ==================== ЭТАП 1: загрузка данных ====================

print("=" * 60)
print("ЭТАП 1: Загрузка дампов")
print("=" * 60)

dhcp_cap = pyshark.FileCapture(DHCP_FILE)
dns_cap = pyshark.FileCapture(DNS_FILE)

dhcp_packets = [pkt for pkt in dhcp_cap]
dns_packets = [pkt for pkt in dns_cap]

print(f"Загружен {DHCP_FILE}: {len(dhcp_packets)} пакетов")
print(f"Загружен {DNS_FILE}: {len(dns_packets)} пакетов")

dhcp_cap.close()
dns_cap.close()


# ==================== ЭТАП 2: извлечение артефактов ====================

print("\n" + "=" * 60)
print("ЭТАП 2: Извлечение артефактов")
print("=" * 60)

# --- Анализ DHCP ---

dhcp_types_map = {
    '1': 'Discover', '2': 'Offer', '3': 'Request',
    '4': 'Decline', '5': 'ACK', '6': 'NAK',
    '7': 'Release', '8': 'Inform'
}

dhcp_events = []
all_ip = set()
all_mac = set()

for pkt in dhcp_packets:
    event = {
        'number': int(pkt.number),
        'time': str(pkt.sniff_time),
        'src_ip': str(pkt.ip.src),
        'dst_ip': str(pkt.ip.dst),
        'src_mac': str(pkt.eth.src),
        'dst_mac': str(pkt.eth.dst),
        'length': int(pkt.length)
    }

    all_ip.update([event['src_ip'], event['dst_ip']])
    all_mac.update([event['src_mac'], event['dst_mac']])

    dhcp = pkt.dhcp
    event['dhcp_type'] = dhcp_types_map.get(str(dhcp.option_dhcp), '?')
    event['transaction_id'] = str(dhcp.id)
    event['client_mac'] = str(dhcp.hw_mac_addr)

    if hasattr(dhcp, 'option_requested_ip_address'):
        event['requested_ip'] = str(dhcp.option_requested_ip_address)
    if hasattr(dhcp, 'option_dhcp_server_id'):
        event['server_id'] = str(dhcp.option_dhcp_server_id)
    if hasattr(dhcp, 'option_subnet_mask'):
        event['subnet'] = str(dhcp.option_subnet_mask)
    if hasattr(dhcp, 'option_ip_address_lease_time'):
        event['lease'] = str(dhcp.option_ip_address_lease_time)
    if hasattr(dhcp, 'ip_your') and str(dhcp.ip_your) != '0.0.0.0':
        event['offered_ip'] = str(dhcp.ip_your)

    dhcp_events.append(event)

print(f"\n--- DHCP-анализ ({DHCP_FILE}) ---")
print(f"{'No':<4} {'Время':<26} {'Источник':<18} {'Назначение':<18} {'Тип':<10} {'Байт':<6}")
print("-" * 85)
for e in dhcp_events:
    print(f"{e['number']:<4} {e['time']:<26} {e['src_ip']:<18} {e['dst_ip']:<18} {e['dhcp_type']:<10} {e['length']:<6}")

print("\nDHCP-параметры:")
for e in dhcp_events:
    print(f"  Пакет #{e['number']} ({e['dhcp_type']}): TxID={e['transaction_id']}, MAC={e['client_mac']}", end="")
    if 'offered_ip' in e:
        print(f", IP={e['offered_ip']}", end="")
    if 'server_id' in e:
        print(f", Сервер={e['server_id']}", end="")
    if 'lease' in e:
        print(f", Аренда={e['lease']}с", end="")
    print()

# --- Анализ DNS ---

dns_queries = []
dns_responses = []
dns_domains = []
dns_ips = set()
query_types = Counter()

for pkt in dns_packets:
    dns_ips.update([str(pkt.ip.src), str(pkt.ip.dst)])

    dns = pkt.dns
    entry = {
        'number': int(pkt.number),
        'time': str(pkt.sniff_time),
        'src_ip': str(pkt.ip.src),
        'dst_ip': str(pkt.ip.dst),
        'length': int(pkt.length)
    }

    if hasattr(dns, 'qry_name'):
        entry['query_name'] = str(dns.qry_name)
        dns_domains.append(entry['query_name'])
    if hasattr(dns, 'qry_type'):
        entry['query_type'] = str(dns.qry_type)

    is_response = str(dns.flags_response) in ('1', 'True')

    if is_response:
        entry['type'] = 'response'
        if hasattr(dns, 'a'):
            entry['resolved_ip'] = str(dns.a)
        dns_responses.append(entry)
    else:
        entry['type'] = 'query'
        dns_queries.append(entry)

    if 'query_name' in entry:
        qtype = entry.get('query_type', '?')
        query_types[qtype] += 1

all_ip.update(dns_ips)

print(f"\n--- DNS-анализ ({DNS_FILE}) ---")
print(f"Запросов: {len(dns_queries)}, Ответов: {len(dns_responses)}")
print(f"\nDNS-запросы:")
print(f"{'No':<4} {'Время':<26} {'Клиент':<18} {'DNS-сервер':<18} {'Домен'}")
print("-" * 95)
for q in dns_queries:
    print(f"{q['number']:<4} {q['time']:<26} {q['src_ip']:<18} {q['dst_ip']:<18} {q.get('query_name', '-')}")

print(f"\nDNS-ответы:")
for r in dns_responses:
    resolved = r.get('resolved_ip', 'NXDOMAIN/нет A-записи')
    print(f"  {r.get('query_name', '-')} -> {resolved}")

# --- Сводка по IP и доменам ---

print(f"\n--- Все обнаруженные IP-адреса ---")
for ip in sorted(all_ip):
    print(f"  {ip}")

print(f"\n--- Все обнаруженные MAC-адреса ---")
for mac in sorted(all_mac):
    print(f"  {mac}")

unique_domains = sorted(set(dns_domains))
print(f"\n--- Уникальные запрашиваемые домены ({len(unique_domains)}) ---")
for d in unique_domains:
    print(f"  {d}")


# ==================== ЭТАП 3: визуализация ====================

print("\n" + "=" * 60)
print("ЭТАП 3: Визуализация")
print("=" * 60)

sns.set_theme(style="whitegrid", palette="muted")

fig, axes = plt.subplots(2, 2, figsize=(14, 10))

# 1) Временная шкала DHCP
ax1 = axes[0][0]
dhcp_labels = [f"#{e['number']} {e['dhcp_type']}" for e in dhcp_events]
times_dhcp = [datetime.strptime(e['time'][:26], '%Y-%m-%d %H:%M:%S.%f') for e in dhcp_events]
base = times_dhcp[0]
offsets = [(t - base).total_seconds() * 1000 for t in times_dhcp]

type_colors = {'Discover': '#3498db', 'Offer': '#2ecc71', 'Request': '#e67e22', 'ACK': '#9b59b6'}
colors_dhcp = [type_colors.get(e['dhcp_type'], '#999') for e in dhcp_events]

ax1.barh(dhcp_labels, offsets, color=colors_dhcp, height=0.5)
ax1.set_xlabel('Время от начала (мс)')
ax1.set_title('DHCP: временная шкала обмена')

# 2) DNS: частота запросов по доменам
ax2 = axes[0][1]
domain_counts = Counter(dns_domains)
domains = list(domain_counts.keys())
counts = list(domain_counts.values())

short_names = []
for d in domains:
    parts = d.split('.')
    if len(parts) > 3:
        short_names.append('.'.join(parts[:2]) + '...')
    else:
        short_names.append(d)

sns.barplot(x=counts, y=short_names, ax=ax2, palette="viridis", hue=short_names, legend=False)
ax2.set_xlabel('Количество запросов')
ax2.set_title('DNS: запросы по доменам')

# 3) DNS: временная шкала запросов
ax3 = axes[1][0]
dns_times = []
dns_labels_plot = []
dns_colors = []

for pkt in dns_packets:
    t = datetime.strptime(str(pkt.sniff_time)[:26], '%Y-%m-%d %H:%M:%S.%f')
    dns_times.append(t)
    is_resp = str(pkt.dns.flags_response) in ('1', 'True')
    dns_labels_plot.append('Ответ' if is_resp else 'Запрос')
    dns_colors.append('#e74c3c' if is_resp else '#3498db')

base_dns = dns_times[0]
dns_offsets = [(t - base_dns).total_seconds() for t in dns_times]

ax3.scatter(dns_offsets, dns_labels_plot, c=dns_colors, s=100, zorder=5)
ax3.set_xlabel('Время от начала (с)')
ax3.set_title('DNS: запросы и ответы во времени')

# 4) Размеры пакетов (все)
ax4 = axes[1][1]
all_lengths_dhcp = [e['length'] for e in dhcp_events]
all_lengths_dns = [int(pkt.length) for pkt in dns_packets]

data_sizes = (
    [('DHCP', l) for l in all_lengths_dhcp] +
    [('DNS', l) for l in all_lengths_dns]
)
proto_labels = [d[0] for d in data_sizes]
sizes = [d[1] for d in data_sizes]

sns.boxplot(x=proto_labels, y=sizes, ax=ax4, palette="Set2", hue=proto_labels, legend=False)
ax4.set_ylabel('Размер пакета (байт)')
ax4.set_title('Распределение размеров пакетов')

plt.tight_layout()
plt.savefig('dhcp_analysis.png', dpi=150)
print("Графики сохранены в dhcp_analysis.png")

# --- Сохранение артефактов ---

artifacts = {
    'dhcp_events': dhcp_events,
    'dns_queries': dns_queries,
    'dns_responses': dns_responses,
    'unique_domains': unique_domains,
    'all_ip_addresses': sorted(list(all_ip)),
    'all_mac_addresses': sorted(list(all_mac))
}

with open('artifacts.json', 'w', encoding='utf-8') as f:
    json.dump(artifacts, f, ensure_ascii=False, indent=2)
print("Артефакты сохранены в artifacts.json")

with open('artifacts.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['Тип', 'Номер', 'Время', 'Источник', 'Назначение', 'Протокол', 'Детали'])
    for e in dhcp_events:
        writer.writerow(['DHCP', e['number'], e['time'], e['src_ip'], e['dst_ip'],
                         e['dhcp_type'], f"TxID={e['transaction_id']}"])
    for q in dns_queries:
        writer.writerow(['DNS', q['number'], q['time'], q['src_ip'], q['dst_ip'],
                         'Query', q.get('query_name', '-')])
    for r in dns_responses:
        resolved = r.get('resolved_ip', 'NXDOMAIN')
        writer.writerow(['DNS', r['number'], r['time'], r['src_ip'], r['dst_ip'],
                         'Response', f"{r.get('query_name', '-')} -> {resolved}"])
print("Артефакты сохранены в artifacts.csv")
