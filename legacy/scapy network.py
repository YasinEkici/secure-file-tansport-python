from scapy.all import get_windows_if_list
for iface in get_windows_if_list():
    # iface bir dict, örneğin:
    # {'name': '\\Device\\NPF_{2905622D-293E-487E-940C-BEE486FDF1EF}',
    #  'description': 'Realtek PCIe GBE Family Controller',
    #  'ip': '192.168.1.42', ...}
    print(f"{iface['name']}\n    ↳ {iface['description']}\n    ↳ IP: {iface['ip']}\n")
