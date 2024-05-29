import ipaddress
import socket
import json
import threading
import select
import winreg
import random
import string
import encryptions
import custom_errors

SOCKS_VERSION = 5
PROXY_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
# Proxy replay errors:
GENERAL_FAILURE = 1 # general SOCKS server failure
NETWORK_FAILURE = 3 # Network unreachable
HOST_UNREACHABLE = 4 # Host unreachable
CONNECTION_REFUSED = 5 # Connection refused
COMMAND_NOT_SUPPORTED = 7 # Command not supported
ADDRESS_TYPE_NOT_SUPPORTED = 8 # Address type not supported

DIRECTORY_IP = "127.0.0.1"
DIRECTORY_PORT = 12345


def read_sock(sock):
    """
    read the data from the socket
    returns:
    code - first byte
    length - data length (found by reading until ']')
    data - read <length>
    return none if failed
    """     
    char = ''
    length = ''
    try:
        # read code
        code = sock.recv(1).decode('utf-8')

        # read length
        while char != ']':
            char = sock.recv(1).decode('utf-8')
            length += char
        length = int(length[1:-1])

        data = sock.recv(length).decode('utf-8')

    except (UnicodeDecodeError, ValueError, OSError):
        return None
    
    return code, length, data


def get_available_nodes(blacklist):
    # connect to directory and ask for list of all available nodes
    data = '{"blacklist":' + str(blacklist) + '}'
    get_msg = '1[' + str(len(data)) + ']' + data
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as directory_sock:
            directory_sock.connect((DIRECTORY_IP, DIRECTORY_PORT))            
            directory_sock.sendall(get_msg.encode())

            directory_ans = read_sock(directory_sock)
    except Exception:
        raise custom_errors.directoryUnReachable()

    if not directory_ans:
        raise custom_errors.directoryUnReachable("Directory not responding")
    
    code, _, nodes_list_str = directory_ans
    if code == '0':
        raise custom_errors.directoryUnReachable("Directory returned error.")
    
    nodes_list = json.loads(nodes_list_str)
    if len(nodes_list) < 3:
        raise custom_errors.directoryNoNodes("Not enough nodes: " + str(len(nodes_list)))
        
    return nodes_list


# Choose a random node based on the least connections
def get_random_node(nodes_list):
    weights = [1 / (node["connections"] + 1) for node in nodes_list]
    
    chosen_dict = random.choices(nodes_list, weights=weights, k=1)[0]

    return chosen_dict


def choose_nodes_load_balancer(nodes_list):
    # Separate nodes containing each flag
    suitable_for_guard = [n for n in nodes_list if 'g' in n['flags']]
    suitable_for_middle = [n for n in nodes_list if 'm' in n['flags']]
    suitable_for_exit = [n for n in nodes_list if 'e' in n['flags']]

    # randomly choose node for each rule (prevent repetition)
    guard = get_random_node(suitable_for_guard)
    if guard in suitable_for_middle:
        suitable_for_middle.remove(guard)
    if guard in suitable_for_exit:
        suitable_for_exit.remove(guard)

    middle = get_random_node(suitable_for_middle)
    if middle in suitable_for_exit:
        suitable_for_exit.remove(middle)

    exit = get_random_node(suitable_for_exit)
    
    return guard, middle, exit


def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def create_message(code, data, use_json=True):
    if use_json:
        data = json.dumps(data)
    return code + '[' + str(len(data)) + ']' + data


def create_message_encrypted(code, data, key):
    cipher = encryptions.aes_encrypt(data.encode('utf-8'), key)
    msg = code + '[' + str(len(cipher)) + ']' + cipher
    return msg.encode('utf-8')


def create_diffie_hellman_param_msg():
    P, G = encryptions.get_diffie_hellman_parameters()
    
    private_key = encryptions.generate_private_key(P)
    public_key = encryptions.calc_public_key(private_key, P, G)

    data = {"P": P, "G": G, "key": public_key}
    msg = create_message('3', data)

    return msg, (P, private_key)


# objcect that handle the establishment of the connection eith the nodes
class Node:
    def __init__(self, connection_handler, ip, port, next_ip, next_port, rsa_public_key, is_exit):
        self.connection_handler = connection_handler
        self.ip = ip
        self.port = port
        self.next_ip = next_ip
        self.next_port = next_port
        self.rsa_key = rsa_public_key 
        self.aes_key = ""
        self.is_exit = is_exit

    def __str__(self):
        return self.ip
    
    def verify_node(self):
        """
        check that the node isn't fake using RSA verification
        with the key provided by the directory
        """
        secret = generate_random_string(16) # random string with length 16
        msg = create_message('1', {"to_sign": secret}, True)

        data = self.connection_handler.send_and_recive(msg)
 
        data = json.loads(data)
        sign = data["signed"]
        try:
            verification_result = encryptions.rsa_verify(secret, sign, self.rsa_key)
        except (UnicodeDecodeError, TypeError):
            verification_result = False

        if not verification_result:
            raise custom_errors.NodeNotVerified()

    def coordinate_aes_key(self):
        """
        coordinate aes key with the node
        using diffie hellman method
        """
        diffie_hellamn_params_msg, privte_dh_params = create_diffie_hellman_param_msg()
        data = self.connection_handler.send_and_recive(diffie_hellamn_params_msg)

        data = json.loads(data)
        recived_key = data["key"]
        self.aes_key = encryptions.get_aes_key(recived_key, privte_dh_params[0], privte_dh_params[1])

    def send_next_adress(self):
        """
        send to the node the next adress in the circuit 
        it needs to connect to
        """
        next_node_adress_msg = {"next_ip": self.next_ip, "next_port": self.next_port, "exit": self.is_exit}
        next_node_adress_msg = json.dumps(next_node_adress_msg)

        next_node_msg = create_message_encrypted('5', next_node_adress_msg, self.aes_key)
        data = self.connection_handler.send_and_recive(next_node_msg)

        data = encryptions.aes_decrypt(data, self.aes_key)
        data = json.loads(data)
        
        if data["success"] == 0:
            raise custom_errors.TargetUnReachable(f"Can't reach node at {self.next_ip}:{self.next_port}.")

    def connect(self):
        self.verify_node()

        self.coordinate_aes_key()

        self.send_next_adress()


# object that manage the nodes + socket connections to the guard node and proxy client
class TorConnectionHandler:
    def __init__(self):
        self.guard_node_sock=0
        self.nodes = []
        self.nodes_blacklist = []
        self.layer = 0

    def set_route(self, server_adress):
        nodes_list = get_available_nodes(self.nodes_blacklist)

        guard, middle, exit = choose_nodes_load_balancer(nodes_list)

        exit = Node(self, exit["ip_address"], exit["OP_port"], server_adress[0], server_adress[1], exit["public_key"], True)
        middle = Node(self, middle["ip_address"], middle["OP_port"], exit.ip, exit.port, middle["public_key"], False)
        guard = Node(self, guard["ip_address"], guard["OP_port"], middle.ip, middle.port, guard["public_key"], False)

        self.nodes = [guard, middle, exit]

    def set_nodes_connection(self):
        for node in self.nodes:
            node.connect()
            self.layer += 1

    def connect_to_tor(self, server_adress):
        connection_failed_count = 0
        failed_nodes_black_list = []
        while connection_failed_count < 3:
            try:
                # get nodes route 
                self.set_route(server_adress)

                if self.nodes[0].ip.count('.') == 3  :
                    self.guard_node_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.guard_node_sock.settimeout(1)  # 5 seconds timeout
                    self.guard_node_sock.connect((self.nodes[0].ip, self.nodes[0].port))
                else:
                    self.guard_node_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM,0)
                    self.guard_node_sock.settimeout(1)  # 5 seconds timeout
                    print(self.nodes[0].ip)
                    self.guard_node_sock.connect((self.nodes[0].ip, self.nodes[0].port,0,0))

                self.guard_node_sock.settimeout(None)  # disable timeout
                # establish connection with the 3 nodes
                self.set_nodes_connection()

                return True
            
            except (ConnectionRefusedError, socket.timeout):
                failed_nodes_black_list.append(self.nodes[0])

            except custom_errors.ProtocolError as e:
                print("ERROR: ", e)
                failed_nodes_black_list.append(self.nodes[self.layer])

            except custom_errors.TargetUnReachable as e:
                print("ERROR: ", e)
                # 2 means it's the server that not responding
                if self.layer == 2: 
                    return False
                failed_nodes_black_list.append(self.nodes[self.layer])

            except custom_errors.NodeNotVerified as e:
                print("ERROR: ", e)
                failed_nodes_black_list.append(self.nodes[self.layer])

            except custom_errors.directoryUnReachable as e:
                print("ERROR: ", e)
                return False
        
            except custom_errors.directoryNoNodes as e:
               print("ERROR: ", e)
               return False
            # this part only run if exception occurred
            connection_failed_count += 1
            print("retry")
            self.guard_node_sock.close()
            self.guard_node_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.nodes.clear()
        return False

    def add_layers(self, msg, nodes):
        """
        add mulitple encryption layers based on the node we communicate with
        """
        if type(msg) != bytes:
            msg = msg.encode('utf-8')
        
        for i in reversed(range(self.layer)):
            cipher = encryptions.aes_encrypt(msg, nodes[i].aes_key)
            msg = '7' + '[' + str(len(cipher)) + ']' + cipher
            msg = msg.encode('utf-8')

        return msg
    
    def remove_layers(self, encrypted_msg, nodes):
        """
        remove mulitple encryption layers based on the node we communicate with
        encrypted_msg (bytes) - the message to decrypt
        nodes (Node object) - the nodes with the keys
        """
        for i in range(self.layer):
            decipher = encryptions.aes_decrypt(encrypted_msg, nodes[i].aes_key)
            if decipher[0] == b'8' and decipher[1] == b'[':
                encrypted_msg = decipher[decipher.find(b']') + 1:]
            else:
                encrypted_msg = decipher

        return encrypted_msg

    def send(self, msg):
        encrypted_msg = self.add_layers(msg, self.nodes)
        self.guard_node_sock.sendall(encrypted_msg)

    def recive(self):
        answer = read_sock(self.guard_node_sock)
        if answer is None:
            raise custom_errors.ProtocolError()
        code, _, data_encrypted = answer
        data_decrypted = self.remove_layers(data_encrypted.encode('utf-8'), self.nodes)

        if code == '0':
            raise custom_errors.ProtocolError("code 0 recived:" + data_decrypted)
        return data_decrypted

    def send_and_recive(self, msg):
        """
        send messages through the guard node socket,
        add encryptions layers based on the node we communicating
        with, also remove the encryptions layers from the result.
        """
        self.send(msg)
        ans = self.recive().decode('utf-8')
        return ans


class AppHandler:
    def __init__(self):
        self.server_address = None
        self.tor_connection = None

    def socks5(self, app_socket):
        address_type = 0
        try:
        # client sends a version identifier/method selection message
            version, nmethods = app_socket.recv(2)
            
            if version != SOCKS_VERSION:
                raise custom_errors.ProxyErrors("We only use version 5! not " + str(version), CONNECTION_REFUSED)
            
            # get available methods [0, 1, 2]
            methods = self.get_available_methods(nmethods, app_socket)
            if 0 not in methods:
                raise custom_errors.ProxyErrors("Missing 'NO AUTHENTICATION REQUIRED' method.", COMMAND_NOT_SUPPORTED)
            
            # send METHOD selection message
            app_socket.sendall(bytes([SOCKS_VERSION, 0]))

            # client sends the request details
            version, cmd, _, address_type = app_socket.recv(4)

            if version != SOCKS_VERSION:
                raise custom_errors.ProxyErrors("We only use version 5! not " + str(version), CONNECTION_REFUSED)

            if address_type == 1:  # IPv4
                address = socket.inet_ntoa(app_socket.recv(4))

            elif address_type == 3:  # Domain name
                domain_length = app_socket.recv(1)[0]
                address = app_socket.recv(domain_length)
                address = socket.gethostbyname(address)

            elif address_type == 4: #IPv6
                address = socket.inet_ntop(socket.AF_INET6, app_socket.recv(16))
            
            else:
                raise custom_errors.ProxyErrors("Ip address type not supported", ADDRESS_TYPE_NOT_SUPPORTED)
            

            # convert bytes to unsigned short array
            port = int.from_bytes(app_socket.recv(2), 'big', signed=False)

            self.server_address = (address, port)

            #TODO: add support for more options then just 'CONNECT'
            if cmd == 1:  # CONNECT 
                self.tor_connection = TorConnectionHandler()
                if not self.tor_connection.connect_to_tor(self.server_address):
                    raise custom_errors.ProxyErrors("Connection to tor failed.", NETWORK_FAILURE)
            else:
                raise custom_errors.ProxyErrors("command not supported yet.", COMMAND_NOT_SUPPORTED)

            addr = int.from_bytes(socket.inet_aton(self.server_address[0]), 'big', signed=False)
            port = self.server_address[1]

            # replay with success  message
            reply = self.generate_reply(0, address_type,addr, port)
            app_socket.sendall(reply)

            # establish data exchange
            self.exchange_loop(app_socket)

        except custom_errors.ProxyErrors as e:
            print("proxy error: ", e)
            reply = self.generate_reply(e.error_num, address_type)
            app_socket.sendall(reply)

        except (ConnectionResetError, ConnectionAbortedError):
            print("connection error: Connection Close unexpectedly.")

        except NameError as e:
            print("general error: ", e)
            reply = self.generate_reply(GENERAL_FAILURE, 0)
            app_socket.sendall(reply)

        finally:
            print("Connection Close.")
            app_socket.close()
            if self.tor_connection and self.tor_connection.guard_node_sock !=0 :
                self.tor_connection.guard_node_sock.close()

    def socks4(self, app_socket):
        try:
            version, cmd = app_socket.recv(2)

            if version != 4:
                raise custom_errors.ProxyErrors("We only use version 4/5! not " + str(version), CONNECTION_REFUSED)

            port = int.from_bytes(app_socket.recv(2), 'big', signed=False)
            ip = socket.inet_ntoa(app_socket.recv(4))


            user_id = b''
            while True:
                chunk = app_socket.recv(1024)
                if not chunk:
                    break 
                user_id += chunk
                if b'\x00' in chunk:
                    break
            
            self.server_address = (ip, port)
            if cmd == 1:  # CONNECT 
                self.tor_connection = TorConnectionHandler()
                if not self.tor_connection.connect_to_tor(self.server_address):
                    raise custom_errors.ProxyErrors("Connection to tor failed.", NETWORK_FAILURE)
            else:
                raise custom_errors.ProxyErrors("command not supported yet." + str(cmd), COMMAND_NOT_SUPPORTED)
            
            replay_field = 90
            addr = int.from_bytes(socket.inet_aton(self.server_address[0]), 'big', signed=False)

            replay = b''.join([
                int(0).to_bytes(1, 'big'),
                replay_field.to_bytes(1, 'big'),
                port.to_bytes(2, 'big'),
                addr.to_bytes(4, 'big')
            ])
            app_socket.sendall(replay)

            self.exchange_loop(app_socket)

        except custom_errors.ProxyErrors as e:
           print("proxy error:", e)

        except ConnectionResetError:
            print("connection error: Connection Close unexpectedly.")

        except Exception as e:
            print("general error: ", e)

        finally:
            print("Connection Close.")
            app_socket.close()
            if self.tor_connection:
                self.tor_connection.guard_node_sock.close()

    def handle_client(self, app_socket):
        try:
            version = app_socket.recv(1, socket.MSG_PEEK)[0]
        except socket.error:
            app_socket.close()

        if version == 5:
            self.socks5(app_socket)
        elif version == 4:
            self.socks4(app_socket)
        else:
            app_socket.close()
     
    def exchange_loop(self, app_socket):
        while True:
            # wait until client or remote is available for read
            readable_socks, _, _ = select.select([app_socket, self.tor_connection.guard_node_sock], [], [])

            if app_socket in readable_socks:
                data = app_socket.recv(4096)
                if not data:
                    break
                self.tor_connection.send(data)

            if self.tor_connection.guard_node_sock in readable_socks:
                data = self.tor_connection.recive()
                if not data:
                    break
                app_socket.send(data)

    def generate_reply(self, replay_field, address_type, bound_address=0, bound_port=0):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            replay_field.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'), # RSV
            address_type.to_bytes(1, 'big'),
            bound_address.to_bytes(4, 'big'),
            bound_port.to_bytes(2, 'big')
        ])

    def get_available_methods(self, nmethods, app_socket):
        methods = []
        for _ in range(nmethods):
            methods.append(ord(app_socket.recv(1)))
        return methods


class ProxyServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.service_on = True
        self.apps = dict()
        self.app_mutex = threading.Lock()

    def set_proxy_settings_on(self):
        """
        set the windows registery setting to have this proxy 
        as the main proxy for this computer
        """
        try:
            socks_address = "socks=" + self.host + ':' + str(self.port)

            # Open the registry key
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_KEY_PATH, 0, winreg.KEY_SET_VALUE)

            # Set the proxy server
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_SZ, '1')
            winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, u'*.local;<local>')
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, socks_address)
            
            # Close the registry key
            winreg.CloseKey(key)

            print(f"Proxy set to {self.host}:{self.port}")
        except Exception as e:
            print(f"Error setting proxy: {e}")
        finally:
            winreg.CloseKey(key)

    def set_proxy_settings_off(self):
        """
        set the windows registery setting to stop using this proxy 
        as the main proxy for this computer
        """
        try:
            # Open the registry key
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_KEY_PATH, 0, winreg.KEY_SET_VALUE)

            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_SZ, '0')
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, '')

            print("############### Proxy set off ###############")
        except Exception as e:
            print(f"Error setting off proxy: {e}")
        finally:
            winreg.CloseKey(key)

    # remove threads that already ended.
    def check_threads(self):
        with self.app_mutex:
            self.apps = dict(filter(lambda item: item[1].is_alive(), self.apps.items()))

    def run(self):
        listening_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listening_sock.bind((self.host, self.port))
        listening_sock.listen()

        #self.set_proxy_settings_on()
        
        print(f"* Socks5 proxy server is running on {self.host}:{self.port}")

        while self.service_on:
            conn, addr = listening_sock.accept()
            print(f"* new app_socket from {addr}")

            app = AppHandler()
            app_thread = threading.Thread(target=app.handle_client, args=(conn,))
            app_thread.start()
            with self.app_mutex:
                self.apps[app] = app_thread
            self.check_threads()

    def stop(self):
        self.service_on = False
        # wait for active app_sockets to end.
        self.set_proxy_settings_off()
        
        with self.app_mutex:
            for app in self.apps.keys():
                self.apps[app].join()


def main():
    try:
        proxy = ProxyServer("127.0.0.1", 1080)
        proxy.run()
    except Exception as e:
        print(e)
    finally:
        proxy.stop()
        print("##--STOP--##")


if __name__ == "__main__":
    main()
