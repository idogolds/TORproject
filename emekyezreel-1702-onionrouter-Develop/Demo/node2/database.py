#pip/pip3 install pymongo
import pymongo
from bson.json_util import dumps
from datetime import datetime, timedelta


DB_ERROR ='Failed to insert information:'
FIELDS_LIST = ["name", "ip_address", "public_key", "bandwidt", "OP_port", "user","flags" ,"online"]


class DBfailure(Exception):
    def __init__(self, error_msg) -> None:
        self.message = error_msg
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


class DB:
    def __init__(self, db_path) -> None:
        # MongoDB connection settings
        self.mongo_client = pymongo.MongoClient(db_path)
        self.db = self.mongo_client["directory"]
        self.nodes_collection = self.db["nodes"]

    def get_all_online_nodes(self, nodes_blacklist) -> list[str]:
        """
        return all nodse that currently online,
        excludes nodes that in 
        - nodes_blacklist (str list) : list of ip's as string
        Return: all the nodes that pass the requirment as Json
        """
        projection = {"_id": False}  # Exclude the "_id" field

        filter_query = {
            "online": True,
            "ip_address": {"$nin": nodes_blacklist}
        }

        online_nodes = self.nodes_collection.find(filter_query, projection)

        # Convert collection to JSON
        json_nodes = dumps(online_nodes)

        return json_nodes

    def is_node_exist(self, node_ip):
        return False
         # Check if a node with the specified IP address exists in the DB
        filter_query = {"OP_port": node_ip}
        node = self.nodes_collection.find_one(filter_query)
        # If node is not None, it means the node exists
        if node:
            return True
        else:
            return False


    # Function to insert node information
    def insert_new_node(self, name, ip_address, public_key, bandwidth, OP_port, user, flags) -> None:
        """
        Insert node information into the MongoDB collection.

        Parameters:
        - name (str): Node name.
        - ip_address (str): IP address of the node.
        - public_key (str): Public key of the node.
        - bandwidth (int): Bandwidth in KB/s.
        - OP_port (int): Port for the Onion Proxy.
        - user (str): User information.
        - flags (str): Flags indicating the type of the node (e.g., 'g' for guard).
        - online (Bool): Node is currently online.
        - connections (int): amount of live connections to the node.
        Returns:
        None
        """
        if self.is_node_exist(ip_address):
            raise DBfailure("Node IP already exist.")
        node = {
            "name": name,
            "ip_address": ip_address,
            "public_key": public_key,
            "bandwidth": bandwidth,  # Bandwidth in KB/s
            "last_seen": datetime.utcnow(),
            "OP_port": OP_port,
            "user": user,
            "flags": flags,
            "online": True, 
            "connections": 0,
        }
        insert_result = self.nodes_collection.insert_one(node)
        if not insert_result.acknowledged:
            raise DBfailure("Failed to insert new node.")


    def node_ping_online(self, node_ip, connections) -> bool:
        # update node to appear online
        filter_query = {"ip_address": node_ip}

        update_query = {"$set": {"online": True, "connections": connections, "last_seen": datetime.utcnow()}}

        # Update one document that matches the filter
        update_result = self.nodes_collection.update_one(filter_query, update_query)

        return update_result.matched_count > 0


    def turn_node_offline(self, node_ip) -> bool:
        # update node to be offline
        filter_query = {"ip_address": node_ip}

        update_query = {"$set": {"online": False, "connections": 0}}

        # Update one document that matches the filter
        update_result = self.nodes_collection.update_one(filter_query, update_query)

        return update_result.matched_count > 0
    

    def edit_node(self, node_ip, update_query) -> bool:
        # check that all the keys in the update query are existing in the db
        # to prevent creation of unwanted new data fields
        if not all(elem in FIELDS_LIST for elem in update_query.keys()):
            raise DBfailure("Some of the fields are not allowed.")
        
        filter_query = {"ip_address": node_ip}

        update_query = {"$set": update_query}

        update_result = self.nodes_collection.update_one(filter_query, update_query)

        return update_result.matched_count > 0


    def check_nodes_liveness(self) -> int:
        """
        change nodes online state with "last_seen" longer than a specified threshold to offline.
        """
        # Define the threshold for node deletion (e.g., nodes not seen in the last 30 minutes)

        threshold_time = datetime.utcnow() - timedelta(minutes=30)
        # turn off nodes with "last_seen" longer than the threshold
        filter_query = {"last_seen": {"$lt": threshold_time}}

        update_query = {"$set": {"online": False, "connections": 0}}

        update_result = self.nodes_collection.update_one(filter_query, update_query)

        return update_result.matched_count


    def delete_node(self, node_ip) -> bool:
        filter_query = {"ip_address": node_ip}

        # Delete one document that matches the filter
        delete_result = self.nodes_collection.delete_one(filter_query)

        return delete_result.matched_count > 0

    def close(self) -> None:
        self.mongo_client.close()
   