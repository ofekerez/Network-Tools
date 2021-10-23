import socket

# Defining socket host and port
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 8000

# Creating a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(1)
print('Listening on port %s ...' % SERVER_PORT)
# Two constants containing the content of the html pages.
HOME_PAGE = open("Site1.html", 'rb').read()
ERROR_PAGE = open("Error.html", 'rb').read()


def HTTP_ANSWER(req: str) -> bytes:
    """The function receives an http request and returns the matching response in bytes."""
    # GET / HTTP/1.1
    header = req[:req.index('\n')].split()  # the header is a list of the segments in the first line of the request
    # split by space.
    if header[1] == '/':
        response = 'HTTP/1.0 200 OK\n\n'.encode() + HOME_PAGE
    elif header[1].startswith('/images/'):
        try:
            img = open(header[1][1:], 'rb').read()
            response = 'HTTP/1.0 200 OK\n\n'.encode() + img
        except FileNotFoundError:
            response = 'HTTP/1.0 404 NOT FOUND\n\n'.encode() + ERROR_PAGE
    else:
        response = 'HTTP/1.0 404 NOT FOUND\n\n'.encode() + ERROR_PAGE
    return response


while True:
    # Wait for client sockets
    client_socket, client_address = server_socket.accept()
    while True:
        # Receive the client request
        request = client_socket.recv(1024).decode()
        print(request)
        # Send an HTTP response
        client_socket.send(HTTP_ANSWER(request))
        client_socket.close()
        break
