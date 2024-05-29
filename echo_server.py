import socket
import threading

SERVER_RESPONSE = b"I am The server!!"


def handle_client(client_socket, client_address):
    print(f"Accepted connection from {client_address}")
    try:
        data = client_socket.recv(1024)

        print(f"Echo server recived: {data}")
        print(f"Echo server sent: {SERVER_RESPONSE}")
    
        client_socket.sendall(SERVER_RESPONSE)

    except Exception as e:
        print(f"Error handling client connection: {str(e)}")

    finally:
        client_socket.close()


def start_echo_server(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()

        print(f"Echo server listening on {host}:{port}")

        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()


if __name__ == "__main__":
    # Set the host and port for the echo server
    echo_server_host = '127.0.0.1'
    echo_server_port = 8888

    # Start the echo server
    start_echo_server(echo_server_host, echo_server_port)
