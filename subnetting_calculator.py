import os
import json
import ipaddress

def calculate_vlsm(main_network, reserved_networks, lans_info):
    """Calcola le sottoreti usando VLSM."""
    print("[INFO] Calcolo del subnetting VLSM in corso...")
    sorted_lans = sorted(lans_info, key=lambda x: x['hosts_needed'], reverse=True)
    
    available_networks = [ipaddress.ip_network(main_network)]
    subnet_details = {}

    for r_net_str in reserved_networks:
        reserved = ipaddress.ip_network(r_net_str)
        new_available = []
        for net in available_networks:
            if net.overlaps(reserved):
                new_available.extend(list(net.address_exclude(reserved)))
            else:
                new_available.append(net)
        available_networks = new_available

    for lan in sorted_lans:
        hosts = lan['hosts_needed']
        required_prefix = 32 - (hosts + 2).bit_length()
        
        allocated = False
        for i, net in enumerate(available_networks):
            if net.prefixlen <= required_prefix:
                new_subnet = next(net.subnets(new_prefix=required_prefix))
                subnet_details[lan['name']] = {
                    "net": new_subnet,
                    "usable_hosts": list(new_subnet.hosts())
                }
                
                remaining = list(net.address_exclude(new_subnet))
                available_networks.pop(i)
                available_networks.extend(remaining)
                available_networks.sort()
                allocated = True
                break
        
        if not allocated:
            print(f"[ERRORE] Spazio di indirizzi insufficiente per LAN '{lan['name']}'.")
            return None
            
    print("[INFO] Calcolo del subnetting completato.")
    return subnet_details

def build_topology_and_ips(config_data, subnet_details):
    """Costruisce la mappa dei dispositivi e assegna gli IP in modo robusto."""
    devices = {}
    ip_map = {}

    # --- PASSO 1: Raccogliere TUTTI i dispositivi da ogni sezione ---
    
    # Da LANs
    for lan_data in config_data.get('lans', []):
        for comp in lan_data.get('components', []):
            if comp not in devices:
                dev_type = 'router' if comp.startswith(('R', 'GW')) else 'host'
                devices[comp] = {'type': dev_type, 'lans': set()}
            devices[comp]['lans'].add(lan_data['name'])
            
    # Da Rete Privata
    if config_data.get('private_network', {}).get('enabled', False):
        for dev in config_data['private_network'].get('components', {}):
            if dev not in devices:
                dev_type = 'router' if dev.startswith(('R', 'GW')) else 'host'
                devices[dev] = {'type': dev_type, 'lans': set()}

    # Da Connessione Esterna
    if config_data.get('external_connection', {}).get('enabled', False):
        ext_conn = config_data['external_connection']
        for dev in ext_conn.get('devices', {}):
             if dev not in devices:
                dev_type = 'router' if dev.startswith(('R', 'GW')) else 'host'
                devices[dev] = {'type': dev_type, 'lans': set()}
        if ext_conn.get('external_device') not in devices:
            devices[ext_conn['external_device']] = {'type': 'host', 'lans': set()}


    # --- PASSO 2: Inizializzare la mappa IP per tutti i dispositivi raccolti ---
    for dev in devices:
        ip_map[dev] = {}

    # --- PASSO 3: Assegnare gli indirizzi IP ---
    
    # Da LANs
    for lan_data in config_data.get('lans', []):
        lan_name = lan_data['name']
        usable = subnet_details[lan_name]['usable_hosts']
        assigned_ips = []
        
        for dev, rule in lan_data.get('assignments', {}).items():
            if rule == 'primo': ip = usable[0]
            elif rule == 'ultimo': ip = usable[-1]
            elif rule == 'penultimo': ip = usable[-2]
            else: continue
            ip_map[dev][lan_name] = str(ip)
            assigned_ips.append(ip)

        host_ips = (ip for ip in usable if ip not in assigned_ips)
        for dev in lan_data.get('components', []):
            if lan_name not in ip_map.get(dev, {}):
                ip_map[dev][lan_name] = str(next(host_ips))

    # Da Rete Privata
    if config_data.get('private_network', {}).get('enabled', False):
        for dev, ip in config_data['private_network'].get('components', {}).items():
            ip_map[dev]['private'] = ip
    
    # Da Connessione Esterna
    if config_data.get('external_connection', {}).get('enabled', False):
        ext_conn = config_data['external_connection']
        gw_dev = ext_conn['gateway_device']
        ext_dev = ext_conn['external_device']
        link_hosts = list(ipaddress.ip_network(ext_conn['link_range']).hosts())
        
        ip_map[gw_dev]['link'] = str(link_hosts[0])
        ip_map[ext_dev]['link'] = str(link_hosts[1])

    return devices, ip_map

def generate_configs(config, subnet_details, devices, ip_map):
    """Genera i file di configurazione."""
    output_dir = "configs_json"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Determina le rotte concrete
    routes = {}
    for dev_name, route_info in config['routing'].items():
        routes[dev_name] = {}
        # Default gateway
        if 'default_gateway' in route_info:
            gw_name = route_info['default_gateway']
            # Trova l'IP del gateway sulla rete condivisa
            shared_lan = next((lan for lan in devices[dev_name]['lans'] if lan in devices[gw_name]['lans']), None)
            if shared_lan:
                routes[dev_name]['default'] = ip_map[gw_name][shared_lan]
            elif gw_name == config.get('external_connection',{}).get('external_device'):
                routes[dev_name]['default'] = ip_map[gw_name]['link']
            elif config.get('private_network',{}).get('enabled') and dev_name in config['private_network']['components'] and gw_name in config['private_network']['components']:
                 routes[dev_name]['default'] = ip_map[gw_name]['private']

        # Static routes
        routes[dev_name]['static'] = {}
        for dest, hop_name in route_info.get('static_routes', {}).items():
            dest_net_str = str(subnet_details[dest]['net']) if dest in subnet_details else config['main_network']
            
            shared_lan = next((lan for lan in devices[dev_name]['lans'] if lan in devices[hop_name]['lans']), None)
            if shared_lan:
                 routes[dev_name]['static'][dest_net_str] = ip_map[hop_name][shared_lan]
            elif hop_name == config.get('external_connection',{}).get('gateway_device'):
                 routes[dev_name]['static'][dest_net_str] = ip_map[hop_name]['link']

    # Scrittura dei file
    for device_name, device_info in devices.items():
        iface_count = 0
        content = "auto lo\niface lo inet loopback\n\n"

        # Interfacce LAN
        for lan_name in sorted(list(device_info['lans'])) :
            content += f"# eth{iface_count} -> {lan_name}\n"
            content += f"auto eth{iface_count}\niface eth{iface_count} inet static\n"
            content += f"    address {ip_map[device_name][lan_name]}\n"
            content += f"    netmask {subnet_details[lan_name]['net'].netmask}\n"
            if device_info['type'] == 'host' and routes.get(device_name, {}).get('default'):
                content += f"    gateway {routes[device_name]['default']}\n"
            content += "\n"
            iface_count += 1
        
        # Interfaccia Privata
        if ip_map.get(device_name, {}).get('private'):
            priv_net = ipaddress.ip_network(config['private_network']['range'])
            content += f"# eth{iface_count} -> Rete Privata\n"
            content += f"auto eth{iface_count}\niface eth{iface_count} inet static\n"
            content += f"    address {ip_map[device_name]['private']}\n"
            content += f"    netmask {priv_net.netmask}\n"
            if device_info['type'] == 'host' and routes.get(device_name, {}).get('default'):
                content += f"    gateway {routes[device_name]['default']}\n"
            content += "\n"
            iface_count += 1

        # Interfaccia Esterna e Loopback Pubblico
        if config.get('external_connection', {}).get('enabled'):
            ext_conf = config['external_connection']
            if device_name in ext_conf['devices']:
                # Loopback
                content += f"# Interfaccia di loopback per IP Pubblico\n"
                content += f"iface lo:0 inet static\n    address {ext_conf['devices'][device_name]['public_ip']}\n    netmask 255.255.255.255\n\n"
                # Link
                content += f"# eth{iface_count} -> Link Esterno\n"
                content += f"auto eth{iface_count}\niface eth{iface_count} inet static\n"
                content += f"    address {ip_map[device_name]['link']}\n"
                content += f"    netmask {ipaddress.ip_network(ext_conf['link_range']).netmask}\n\n"

        # Rotte per Router
        if device_info['type'] == 'router' and device_name in routes:
            content += "# Rotte Statiche\n"
            for dest, via in routes[device_name].get('static', {}).items():
                content += f"up ip route add {dest} via {via}\n"
            if 'default' in routes[device_name]:
                content += f"up ip route add default via {routes[device_name]['default']}\n"
        
        # Rotte per Host Esterno
        if device_name == config.get('external_connection',{}).get('external_device'):
             content += "# Rotta verso la rete aziendale\n"
             dest_net = config['main_network']
             via_ip = routes[device_name]['static'][dest_net]
             content += f"up ip route add {dest_net} via {via_ip}\n"


        with open(os.path.join(output_dir, f"{device_name}.cfg"), "w") as f:
            f.write(content)

    print(f"\n[SUCCESSO] Configurazioni generate nella cartella '{output_dir}'.")

def main():
    json_path = "./config.json"
    try:
        with open(json_path, 'r') as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[ERRORE] Impossibile leggere o analizzare il file JSON: {e}")
        return

    # 1. Calcola Subnetting
    subnet_details = calculate_vlsm(config['main_network'], config.get('reserved_networks', []), config['lans'])
    if not subnet_details: return

    # 2. Mappa topologia e assegna IP
    devices, ip_map = build_topology_and_ips(config, subnet_details)
    
    # 3. Genera i file di configurazione
    generate_configs(config, subnet_details, devices, ip_map)

if __name__ == "__main__":
    main()