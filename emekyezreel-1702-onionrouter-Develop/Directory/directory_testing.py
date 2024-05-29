import ast
import json
import random
import socket

IP = "127.0.0.1"
PORT = 12345

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#     sock.connect((IP, PORT))
#     msg = '1[25]{"blacklist":[]}'

#     sock.sendall(msg.encode())

#     ans = sock.recv(1024).decode()
#     nodes_list_str = ans[ans.find(']') + 1:]
            
#     nodes_list = json.loads(nodes_list_str)
#     #nodes_list = list(map(json.loads, nodes_list))
#     print(nodes_list)
#     # Separate nodes containing each flag
#     suitable_for_guard = [n for n in nodes_list if 'g' in n['flags']]
#     suitable_for_middle = [n for n in nodes_list if 'm' in n['flags']]
#     suitable_for_exit = [n for n in nodes_list if 'e' in n['flags']]
    
#     guard = random.choice(suitable_for_guard)
#     if guard in suitable_for_middle:
#         suitable_for_middle.remove(guard)
#     if guard in suitable_for_exit:
#         suitable_for_exit.remove(guard)
#     middle = random.choice(suitable_for_middle)
#     if middle in suitable_for_exit:
#         suitable_for_exit.remove(middle)
#     exit = random.choice(suitable_for_exit)

#     print(guard["name"])
#     print(middle["name"])
#     print(exit["name"])

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#     #ip = socket.gethostname()
#     ip = "127.0.0.1" #socket.gethostbyname(ip) 
#     sock.connect((IP, PORT))
#     # name, ip_address, public_key, bandwidth, OP_port, user, flags
#     # msg = '1{"name":"YOYO","ip_address":"' + ip +'","public_key":"mimimomo","bandwidth":15000,"OP_port":7007,"user":"user","flags":"mg"}'
#     # msg = '2{"On": true}'
#     msg = '3{"name": "jok", "bandwidth": 777, "yosi": "anonimity"}'
#     # msg = '4{}'

#     print(">>", msg)
#     sock.sendall(msg.encode())

#     ans = sock.recv(1024).decode()
#     print("<<", ans)

def get_random_node(nodes_list):
    weights = [1 / (node["connection"] + 1) for node in nodes_list]
    
    chosen_dict = random.choices(nodes_list, weights=weights, k=1)[0]

    return chosen_dict

nodes = [{
        "connection" : 1
    }, {
        "connection": 2
    }, {
        "connection": 3
    }, {
        "connection": 4
    }, {
        "connection": 7
    }, {
        "connection": 9
    }, {
        "connection": 10
    }, {
        "connection": 12
    }
]

count = dict()
for _ in range(1000):
    n = get_random_node(nodes)["connection"]
    if n in count.keys():
        count[n] += 1
    else:
        count[n] = 1

print(count)