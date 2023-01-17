from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
from concurrent.futures import ThreadPoolExecutor
from functions import get_info_config


def test_port_number(host, port):
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.settimeout(5)
        try:
            sock.connect((host, port))
            return True
        except:
            return False


def port_scan(host, top_ports=False):
    open_ports = []

    if top_ports:
        ports_list = get_info_config('ports', 'popularPorts')
    else:
        ports_list = get_info_config('ports', 'deepPorts')
    ports_list_length = len(ports_list)

    with ThreadPoolExecutor(ports_list_length) as executor:
        results = executor.map(test_port_number, [host]*ports_list_length, ports_list)
        for port,is_open in zip(ports_list,results):
            if is_open:
                open_ports.append(port)

    return open_ports