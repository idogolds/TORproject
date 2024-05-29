import json
#pip/pip3 install schedule
import schedule
import socket
import threading
from datetime import datetime, timedelta

import database

HOST = "0.0.0.0"
CLIENT_CONNECTION_PORT = 12345
NODES_CONNECTION_PORT = 9999

# MongoDB connection settings
DB = database.DB("mongodb://localhost:27017/")
DBLock = threading.Lock()

#client request codes
GET='1'

# node request codes
NEW='1'
CHANGE_ONLINE='2'
EDIT='3'
DELETE ='4'

NODE_NOT_RECOGNIZED = "Who are you?"
CODE_NOT_SUPPORTED = "Wrong Code request."
ERR_RESPONSE = "Something wrong with the request."

TERMINAL_MSG="Enter 'exit' to end the program: "
GOODBYE="Tor directory program ended."
END="exit"

def new_node(node_ip, request) -> None:
    data = json.loads(request) #TODO: check that ip is real
    DB.insert_new_node(data["name"], node_ip, data["public_key"], data["bandwidth"], data["OP_port"], data["user"], data["flags"]) 


def change_node_state(node_ip, request) -> tuple[bool, bool]:
    # change node online state ON/OFF
    data = json.loads(request)
    online = data["On"]
    if online:
        connections = data["connections"]
        result = DB.node_ping_online(node_ip, connections)
    else:
        result = DB.turn_node_offline(node_ip)
    return result, online
    

def edit_node(node_ip, request) -> bool:
    data = json.loads(request)

    result = DB.edit_node(node_ip, data)
    return result


def delete_node(node_ip) -> bool:
    result = DB.delete_node(node_ip)
    return result


def handle_node_request(node_socket, node_ip) -> None:
    """
    Handle Node's requests.
    Parameters:
    - node_socket (socket.socket): Node socket for communication.
    Returns:
    None
    """
    ip = node_socket.getpeername()[0]
    node_on = True
    errors = 0
    try:
        while node_on:
            data = ""
            result = True
            code = node_socket.recv(1).decode()
            if not code: # if socket returned none - it was closed
                node_on = False
                break
            request = node_socket.recv(2048).decode()

            try:
                if code == NEW:
                    new_node(ip, request)

                else:
         #           if not DB.is_node_exist(node_ip):
           #             raise database.DBfailure(NODE_NOT_RECOGNIZED)
                    
                    if code == CHANGE_ONLINE:
                        result, on = change_node_state(ip, request)
                        node_on = on

                    elif code == EDIT:
                        result = edit_node(ip, request)

                    elif code == DELETE:
                        result = delete_node(ip)
                        node_on = False

                    else:
                       raise database.DBfailure(CODE_NOT_SUPPORTED)       

            except database.DBfailure as e:
                data = e.message
                result = False
                errors += 1 

            except Exception:
                data = ERR_RESPONSE
                result = False
                errors += 1 

            ans = json.dumps({"OK": result, "Data": data})
            node_socket.sendall(ans.encode())
            if errors >= 3:
                break
    except Exception:
        node_on = False
    finally:
        node_socket.close()
        change_node_state(ip, '{"On": false}')
    print("Close connection with", ip)
    

def listen_for_nodes_connections() -> None:
    """
    Listens for connections from Tor nodes and spawns threads to handle requests.
    """
    # Create a socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, NODES_CONNECTION_PORT))
        server_socket.listen()
        print(f"listen for nodes at {HOST}:{NODES_CONNECTION_PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f">> Accepted NODE connection from {addr}")

            thread = threading.Thread(target=handle_node_request, args=(client_socket, addr[0]))
            thread.start()


def get_data(sock) -> str:
    # recive request from client
    received_data = b'' 
    received_byte = b''
    i = 0 
    # read length, stop when reaching ']' or after 5 bytes to prevent infinite loop (too long)
    while received_byte != b']':
        i += 1
        received_byte = sock.recv(1)  # Receive data from the socket
        received_data += received_byte  # Append the received byte to the received data
        if i > 5:
            break
    
    length = int(received_data.decode()[1:-1])
    data = sock.recv(length).decode()
    return data


def handle_client_request(client_socket) -> None:
    try:
        code = client_socket.recv(1).decode()
        if code == GET:
            data = get_data(client_socket)
            data = json.loads(data)
            blacklist = data["blacklist"]

            # get answer from the DB and send back to the client
            all_nodes = DB.get_all_online_nodes(blacklist)
            msg_to_client = '2[' + str(len(all_nodes)) + ']' + all_nodes
            client_socket.sendall(msg_to_client.encode())

    except Exception as e:
        error_msg = '0[' + str(len(ERR_RESPONSE)) + ERR_RESPONSE
        client_socket.sendall(error_msg.encode())
    finally:
        client_socket.close()
    print("Close connection with client")


def listen_for_client_connections() -> None:
    """
    listen for Clients connections and spawns threads to handle requests.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, CLIENT_CONNECTION_PORT))
        server_socket.listen()
        print(f"listen for clients at {HOST}:{CLIENT_CONNECTION_PORT}")
        while True:
            client_socket, addr = server_socket.accept()
            print(f">> Accepted CLIENT connection from {addr}")
            thread = threading.Thread(target=handle_client_request, args=(client_socket,))
            thread.start()


# Function to listen for terminal input
def listen_for_terminal_input() -> None:
    """
    Listens for terminal input and exits the program if the user enters 'exit'.
    """
    while True:
        user_input = input(TERMINAL_MSG)
        if user_input == END:
            # Close the MongoDB connection and exit the program
            DB.close()
            print(GOODBYE)
            exit()


def main():
    # Listen for client requests
    clients_handling_thread = threading.Thread(target=listen_for_client_connections)
    clients_handling_thread.start()

    # Listen for nodes requests
    nodes_handling_thread = threading.Thread(target=listen_for_nodes_connections)
    nodes_handling_thread.start()

    checking_nodes_thread = threading.Thread(target=lambda: schedule.every().hour.at(":35").do(DB.check_nodes_liveness))
    checking_nodes_thread.start()

    # Create a thread for listening to terminal input
    terminal_input_thread = threading.Thread(target=listen_for_terminal_input)
    terminal_input_thread.start()

    clients_handling_thread.join()
    nodes_handling_thread.join()
    checking_nodes_thread.join()

    
if __name__=="__main__":
    main()