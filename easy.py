import json
import ipaddress

def calculate_vlsm(main_network_str, reserved_networks_str, lans_info):
    subnet_details = {}
    main_network = ipaddress.ip_network(main_network_str)
    
    forced_lans = [lan for lan in lans_info if 'forced_netid' in lan]
    flexible_lans = [lan for lan in lans_info if 'forced_netid' not in lan]
    
    all_reserved_networks = [ipaddress.ip_network(r) for r in reserved_networks_str]
    
    # --- LOGICA CORRETTA PER LE LAN CON NetID FORZATO ---
    for lan in forced_lans:
        hosts = lan['hosts_needed']
        # 1. Calcola il prefisso corretto in base agli host richiesti
        required_prefix = 32 - (hosts + 2).bit_length()
        
        # 2. Prende l'indirizzo di rete fornito
        net_address = lan['forced_netid']
        
        # 3. Combina indirizzo e prefisso calcolato per creare la sottorete corretta
        try:
            # strict=False assicura che venga creato l'indirizzo di rete corretto
            forced_net = ipaddress.ip_network(f"{net_address}/{required_prefix}", strict=False)
        except ValueError as e:
            print(f"[ERRORE] Impossibile creare la rete forzata per {lan['name']}: {e}")
            return None

        subnet_details[lan['name']] = {"net": forced_net}
        all_reserved_networks.append(forced_net)

    # Il resto della funzione per le LAN flessibili rimane invariato
    available_networks = [main_network]
    for reserved in all_reserved_networks:
        new_available = []
        for net in available_networks:
            if net.overlaps(reserved):
                new_available.extend(list(net.address_exclude(reserved)))
            else:
                new_available.append(net)
        available_networks = sorted(new_available)

    sorted_flexible_lans = sorted(flexible_lans, key=lambda x: x['hosts_needed'], reverse=True)
    for lan in sorted_flexible_lans:
        hosts = lan['hosts_needed']
        required_prefix = 32 - (hosts + 2).bit_length()
        allocated = False
        for i, net in enumerate(available_networks):
            if net.prefixlen <= required_prefix:
                new_subnet = next(net.subnets(new_prefix=required_prefix))
                subnet_details[lan['name']] = {"net": new_subnet}
                remaining = list(net.address_exclude(new_subnet))
                available_networks.pop(i)
                available_networks.extend(remaining)
                available_networks = sorted(available_networks)
                allocated = True
                break
        if not allocated:
            print(f"[ERRORE] Spazio insufficiente per allocare la LAN '{lan['name']}'.")
            return None
            
    return subnet_details

def print_subnet_table(config, subnet_details):
    content = ""
    header = "| LAN      | Host Richiesti | NetID           | Netmask         | Prefisso | Broadcast       | Range IP Utile                            |"
    print(header)
    print("|----------|----------------|-----------------|-----------------|----------|-----------------|-------------------------------------------|")
    
    content += header + "\n"
    content += "|----------|----------------|-----------------|-----------------|----------|-----------------|-------------------------------------------|\n"
    
    for lan_name, details in sorted(subnet_details.items()):
        net = details['net']
        lan_info = next((lan for lan in config['lans'] if lan['name'] == lan_name), {})
        hosts_needed = lan_info.get('hosts_needed', 'N/A')
        
        usable_hosts = list(net.hosts())
        range_start = str(usable_hosts[0]) if usable_hosts else "N/A"
        range_end = str(usable_hosts[-1]) if usable_hosts else "N/A"
        
        prefix_str = f"/{net.prefixlen}"

        print(f"| {lan_name:<8} | {str(hosts_needed):<14} | {str(net.network_address):<15} | {str(net.netmask):<15} | {prefix_str:<8} | {str(net.broadcast_address):<15} | {range_start} - {range_end} |")
        content += f"| {lan_name:<8} | {str(hosts_needed):<14} | {str(net.network_address):<15} | {str(net.netmask):<15} | {prefix_str:<8} | {str(net.broadcast_address):<15} | {range_start} - {range_end} |\n"

    return content


def main():
    json_path = "./config.json"
    try:
        with open(json_path, 'r') as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[ERRORE] Impossibile leggere o analizzare il file JSON: {e}")
        return
    

    subnet_details = calculate_vlsm(
        config.get('main_network'), 
        config.get('reserved_networks', []), 
        config.get('lans', [])
    )
    
    if subnet_details:
        content = print_subnet_table(config, subnet_details)
        with open("appunti.txt", "w") as f:
            f.write(content)
        

if __name__ == "__main__":
    main()