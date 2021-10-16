import os
import threading

import eel

eel.init('web')


@eel.expose
def scanner_start(ip_address):
    ip = ip_address
    network = ip[:ip.rfind('.') + 1]
    for octet in range(1, 255):
        ip_address = network + str(octet)
        t = threading.Thread(target=scanner, args=(ip_address, LOCK))
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()
    return clients


def scanner(ip_address, lock):
    result = os.popen('ping {0} -n 1'.format(ip_address)).read()
    if "TTL" in result:
        with lock:
            clients.append(ip_address)


clients = []
threads = []
LOCK = threading.Lock()

eel.start('index.html', size=(850, 400), port=0)  # python will select free ephemeral ports.
