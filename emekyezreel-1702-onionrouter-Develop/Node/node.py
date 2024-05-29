import socket
import json
import threading
import select
import time
import os
import database # type: ignore

from configparser import ConfigParser
from datetime import datetime
# our modules:
import encryptions
import custom_errors

DB = database.DB("mongodb://localhost:27017/")

# Get the directory of the script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, 'config.ini')
CONFIG_LOCK = threading.Lock()

CLOSING_WAITING_TIME = 2
PINGS_WAITING_TIME = 5 * 60
# constants
NOT_RECOGNIZED = "Who are you?"
EXPECTED_VALUES_LIST = {
    '1': {"to_sign": str},
    '3': {"P": int, "G": int, "key": int},
    '5': {"next_ip": str, "next_port": int},
    '7': None
}

# globals
clients = {}
CLIENT_LOCK = threading.Lock()


def get_time():
    # Get the current time
    current_time_utc = datetime.now()

    # Format the time in a log format
    log_format_time = current_time_utc.strftime("%Y-%m-%d %H:%M:%S")
    return log_format_time


# create message in format: code[length]{data}
def create_message(code, data):
    data = json.dumps(data)
    return code + '[' + str(len(data)) + ']' + data


# create message in format: code[length]{data} + encrypt the data using AES
def create_message_encrypted(code, data, key):
    if(type(data) == dict):
        data = json.dumps(data)
    if type(data) != bytes:
        data = data.encode('utf-8')
    cipher = encryptions.aes_encrypt(data, key)
    msg = code + '[' + str(len(cipher)) + ']' + cipher
    return msg.encode('utf-8')


def calc_key_from_diffie_hellman(data):
    P_parameter = data['P']
    G_parameter = data['G']
    recived_key = data['key']

    private_key = encryptions.generate_private_key(P_parameter)
    public_key = encryptions.calc_public_key(private_key, P_parameter, G_parameter)

    shared_key = encryptions.calc_shared_key(private_key, recived_key, P_parameter)
    aes_key = encryptions.int_to_key(shared_key)

    return aes_key, public_key


def read_sock(sock):
    """
    read the data from the socket
    code - one byte
    length - until ']'
    data - read <length>
    return none if failed
    """
    char = ''
    length = ''
    length_count = 0
    try:
        # read code
        code = sock.recv(1).decode('utf-8')
        # read length
        while char != ']' and length_count < 10:
            char = sock.recv(1).decode('utf-8')
            length += char
            length_count += 1
        length = int(length[1:-1])

        data = sock.recv(length).decode('utf-8')

    except (UnicodeDecodeError, ValueError):
        return None
    
    return code, length, data


def extract_data(data, expected_values, aes_key=None):
    """
    check that the data was sent in correct json format
    also check that the json have all the keys with matcing values type.
    """
    try:
        if aes_key is not None:
            data = encryptions.aes_decrypt(data.encode('utf-8'), aes_key)

        if expected_values:
            data = json.loads(data)

            if not all(key in data and isinstance(data[key], value_type) for key, value_type in expected_values.items()):
                raise custom_errors.ProtocolError("Json keys don't match expected values.")
        
    except (json.JSONDecodeError, ValueError):
        raise custom_errors.ProtocolError("Message not in the correct json format.")
    return data
    

def get_msg(sock, expected_code, aes_key=None):
    """
    check that the message follow the protocol rules 
    and disconnect from ths socket if more then 3
    messages without meaning sent.
    """
    errors = 0
    result = None
    expected_values = None

    while result is None and errors < 3:
        try: 
            # read the message
            result = read_sock(sock)

            if result is None:
                raise custom_errors.ProtocolError("Faild to read the message.")
            
            # check the code
            code, _, data = result
            if code != expected_code:
                raise custom_errors.ProtocolError(expected_code + " Wrong Code.")

            # check the data
            if code in EXPECTED_VALUES_LIST.keys():
                expected_values = EXPECTED_VALUES_LIST[code]
                data = extract_data(data, expected_values, aes_key)

        except custom_errors.ProtocolError as e:
            errors += 1
            result = None
            error_msg = create_message('0', {"error": e.message})
            sock.sendall(error_msg.encode('utf-8'))

    if errors >= 3:
        raise custom_errors.BadClient()

    return data


def try_to_connect_to_next_node(sock, address):
    """
    try to connect socket to adress
    return 0/1 for success or fail
    """
    try:
        sock.connect(address)
    except (socket.error, ConnectionError) as e:
        return 0
    else:
        return 1


class ClientHandler:
    def __init__(self, client_sock, addr):
        self.address = addr
        self.client_socket = client_sock
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aes_key = ""
        self.is_exit = False


    def set_up_connection(self):
        # sign message for verification (RSA)
        recived_data = get_msg(self.client_socket, '1')

        signed_data = encryptions.rsa_sign(recived_data["to_sign"], NodeManager.rsa_private_key)
        msg = create_message('2', {"signed": signed_data})
        self.client_socket.sendall(msg.encode('utf-8'))

        # using diffie hellmen to create a key
        recived_data = get_msg(self.client_socket, '3')

        aes_key_result, public_key = calc_key_from_diffie_hellman(recived_data)
        self.aes_key = aes_key_result

        data = {"key": public_key}
        msg = create_message('4', data)
        self.client_socket.sendall(msg.encode('utf-8'))


    def connect_to_next_node(self):
        success = 0
        errors = 0
        # conntinue until finding a node that response
        while success == 0:
            data = get_msg(self.client_socket, '5', self.aes_key)
            
            # get next address from the client
            next_ip = data['next_ip']
            next_port = data['next_port']
            self.is_exit = data['exit']
            if self.is_exit and 'e' not in NodeManager.flags:
                raise custom_errors.BadClient("Node can't be used as exit")
            server_address = next_ip, next_port

            # trying to connect do the server
            success = try_to_connect_to_next_node(self.server_socket, server_address)
            errors += not success 

            if errors >= 3:
                raise custom_errors.BadClient()
            
            msg = create_message_encrypted('6', {"success": success}, self.aes_key)
            self.client_socket.sendall(msg)


    def exchange_loop(self):
        while True:
            # wait until client or remote is available for read
            readable_socks, _, _ = select.select([self.client_socket, self.server_socket], [], [])

            # Client -> Server
            if self.client_socket in readable_socks:
                data = get_msg(self.client_socket, '7', self.aes_key)
                if not data:
                   break
                self.server_socket.sendall(data)

            # Server -> client
            if self.server_socket in readable_socks:
                if self.is_exit:
                    data = b''
                    while True:
                        data_chunk = self.server_socket.recv(4096)
                        data += data_chunk
                        if len(data_chunk) < 4096:
                            break
                    code_pad = '8'
                    if not data:
                        break
                else:
                    ans = read_sock(self.server_socket)
                    if not ans:
                        break
                    code_pad, _, data = ans
                        
                msg = create_message_encrypted(code_pad, data, self.aes_key)
                self.client_socket.sendall(msg)
 

    def handle_client_connection(self):
        global clients
        try:
            # set up connection
            self.set_up_connection()
            
            self.connect_to_next_node()
            # run until client abundant connection
            self.exchange_loop()

        except custom_errors.BadClient as e:
            error_msg = create_message('0', {"error": e.message})
            self.client_socket.sendall(error_msg.encode('utf-8'))

        except (ConnectionResetError, ConnectionAbortedError):
            print("ERROR: socket dissconnected.")

        finally:
            self.client_socket.close()
            self.server_socket.close()

            with CLIENT_LOCK:
                del clients[self]
        print(f"{get_time()} >> Close connection with {self.address}")


class NodeManager:
    rsa_private_key = ""
    flags = ""
    def __init__(self):
        self.host = ""
        self.port = 0
        self.directory_ip = ""
        self.directory_port = 0
        self.node_running = False
        self.run_error = []


    def set_params(self, host, port, directory_ip, directory_port):
        self.host = host
        self.port = port
        self.directory_ip = directory_ip
        self.directory_port = directory_port


    def set_node_off(self):
        self.node_running = False


    def listen_for_connection(self):
        global clients
        try:
            # opening socket for connections
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listening_sock:

                listening_sock.bind((self.host, self.port))
                listening_sock.listen()

                print(f"Node is listening on {self.host}:{self.port}")

                while self.node_running:
                    # timeout every few seconds to check if node is running
                    readable, _, _ = select.select([listening_sock], [], [], CLOSING_WAITING_TIME) 
                    if readable:
                        sock, addr = listening_sock.accept()
                        print(f"{get_time()} >> Connected by {addr}")
                        # creating object for each client and opening him on diffrent thread
                        new_client = ClientHandler(sock, addr)
                        new_client_thread = threading.Thread(target=new_client.handle_client_connection)
                        new_client_thread.start()
                        with CLIENT_LOCK:
                            clients[new_client] = new_client_thread
        except (socket.error, OSError) as e:
            print(e)
            self.run_error.append("Port Already in use.")
            self.node_running = False

        with CLIENT_LOCK:
            for client in clients.values():
                client.join()


    def get_node_properties(self):
        with CONFIG_LOCK:
            config = ConfigParser()
            config.read('config.ini')

            hostname = socket.gethostname()
            IPAddr = socket.gethostbyname(hostname)
            # read the node configuration
            node_properties = {
                "name": config['properties']['node-name'], 
                "ip_address": IPAddr,
                "public_key": config['properties']['RSA-public-key'],
                "bandwidth" : int(config['properties']['bandwidth']),
                "OP_port": int(config['connection']['port']),
                "user": config['properties']['user'],
                "flags": config['properties']['flags']
            }
            #for one device
            DB.insert_new_node(node_properties["name"], "0.0.0.0", node_properties["public_key"], node_properties["bandwidth"], node_properties["OP_port"], node_properties["user"], node_properties["flags"]) 

        return node_properties


    def ping(self, sock):
        global clients
        # ping directory to show the node is online/offline
        online_state = {"On": self.node_running, "connections": len(clients)}
        ping_msg = '2' + json.dumps(online_state)
        sock.sendall(ping_msg.encode())

        ans = sock.recv(1024).decode()
        if not ans:
            raise custom_errors.DirectoryError("Directory not responding.")
        result = json.loads(ans)
        return result
    

    def register_node(self, sock, result):
        data = result["Data"]
        if data == NOT_RECOGNIZED:
            node_properties = self.get_node_properties()
            
            msg = '1' + json.dumps(node_properties)
            sock.sendall(msg.encode())
        
        ans = sock.recv(1024).decode()
        ans = json.loads(ans)
        if not ans["OK"]:
            raise custom_errors.DirectoryError("Failed to register.")
        

    def ping_directory(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as directory_sock:
                try:
                    directory_sock.connect((self.directory_ip, self.directory_port))
                except ConnectionRefusedError:
                    raise custom_errors.DirectoryError("Can't connect to Directory.")
                

                while self.node_running:
                    result = self.ping(directory_sock)
                    ok = result["OK"]

                    if ok:  # wait before pinging again
                        i = 0
                        while i < PINGS_WAITING_TIME and self.node_running:
                            time.sleep(1)
                            i += 1
                    
                    # if the directory doesn't recognize this node, register as new
                    else:
                        self.register_node(directory_sock, result)

                # ping directory to turn node offline
                self.ping(directory_sock)

        except (custom_errors.DirectoryError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError) as e:
            print(e)
            self.run_error.append("Can't connect to Directory.")
            self.node_running = False


    def set_rsa_keys(self):
        with CONFIG_LOCK:
            config = ConfigParser()
            config.read(CONFIG_PATH)
            # if there are no rsa keys generate new one
            rsa_private_key = config['properties']['rsa-private-key']
            rsa_public_key = config['properties']['rsa-public-key']

            if rsa_private_key == 'None' or rsa_public_key == 'None':
                public_key, private_key = encryptions.rsa_generate_key_pair()
                config['properties']['rsa-private-key'] = private_key
                config['properties']['rsa-public-key'] = public_key
                with open(CONFIG_PATH, 'w') as configfile:
                    config.write(configfile)

        NodeManager.rsa_private_key = rsa_private_key


    def run_node(self):
        self.set_rsa_keys()
        self.node_running = True
        # connect to directory
        self.get_node_properties()

        pinging_thread = threading.Thread(target=self.ping_directory)
        pinging_thread.start()

        # Start the connection handling thread
        connection_thread = threading.Thread(target=self.listen_for_connection)
        connection_thread.start()

        connection_thread.join()
        pinging_thread.join()
        print("ended.")


def main():
   NodeManager.flags = "gme"
   port = int(input("[DEBUG] enter port: "))
   main_node = NodeManager()
   main_node.set_params('0.0.0.0', port, "127.0.0.1", 9999)
   main_node.run_node()


if __name__ == "__main__":
    main()
