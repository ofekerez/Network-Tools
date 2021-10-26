# Multithreaded Port Scanner
import socket
import threading

target = input("Enter your target IP please ")
queue = []


def instructions():
    """The function prints out the possible modes for the scanner"""
    print("Mode 1: scan all ports from 1-1024\n"
          "Mode 2: scan all ports (not recommended)\n"
          "Mode 3: scan a list of well-known ports(recommended)\n"
          "Mode 4: Interactive - enter a list of ports to scan this way: 80, 3389, 443...")


def port_scan(port: str):
    """The function receives a port and tries to connect to it via TCP, returns True if succeeded else False."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        sock.connect((target, port))
        return True
    except Exception:
        return False


def generate_ports(mode: int):
    """The function loads to the global variable queue the list of ports to check."""
    if mode == 1:
        for port in range(1, 1024):
            queue.append(port)
    elif mode == 2:
        for port in range(1, 65535):
            queue.append(port)
    elif mode == 3:
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 443, 3389, 139, 445, 902, 912]
        for port in ports:
            queue.append(port)
    elif mode == 4:
        ports = input("Enter your ports (separated by comma):")
        ports = ports.split(', ')
        ports = list(map(int, ports))
        for port in ports:
            queue.append(port)


def run_scanner(threads, mode):
    """The function receives a max number of threads and a mode, creates a thread for each port scan."""
    generate_ports(mode)
    thread_list = []
    for t in range(threads):
        thread = threading.Thread(target=main)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()
        thread.join()


def main():
    while queue:
        port = queue.pop()
        if port_scan(port):
            print(f"Port {port} is open!")


if __name__ == '__main__':
    instructions()
    run_scanner(100, int(input("Enter the mode you want to activate the script on ")))
