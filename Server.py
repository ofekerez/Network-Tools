import socket

# Define socket host and port
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 8200

# Create socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(0)
print('Listening on port %s ...' % SERVER_PORT)




while True:
    # Wait for client connections
    client_socket, client_address = server_socket.accept()

    while True:
        # Get the client request
        request = client_socket.recv(1024).decode()
        print(request)
        if validate_HTTP(request):
            # Send HTTP response
            response = 'HTTP/1.0 200 OK\n\nHello World'
            print(response)
            client_socket.send(response.encode())

    client_socket.close()

    # Close socket


