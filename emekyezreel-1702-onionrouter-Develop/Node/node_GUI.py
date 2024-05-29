import time
import tkinter as tk
from configparser import ConfigParser
import threading
import node

WINDOW_SIZE = "350x200"  # width x height

class NodeSetUp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Node")
        self.config = ConfigParser()
        self.config.read(node.CONFIG_PATH)
        self.node_gui_state = "Stop"  # start - stop
        self.node = node.NodeManager()

        # Set window starting size
        self.geometry(WINDOW_SIZE)
        
        # Create input fields
        self.ip_field =  tk.Label(self, text="IP:")
        self.ip_field.place(relx=0.1, rely=0.1, anchor=tk.W)
        self.ip_entry = tk.Entry(self)
        self.ip_entry.place(relx=0.3, rely=0.1, anchor=tk.W)
        
        self.port_field =  tk.Label(self, text="Port:")
        self.port_field.place(relx=0.1, rely=0.2, anchor=tk.W)
        self.port_entry = tk.Entry(self)
        self.port_entry.place(relx=0.3, rely=0.2, anchor=tk.W)

        self.name_field =  tk.Label(self, text="Name:")
        self.name_field.place(relx=0.1, rely=0.3, anchor=tk.W)
        self.name_entry = tk.Entry(self)
        self.name_entry.place(relx=0.3, rely=0.3, anchor=tk.W) 

        # Create checkboxes
        self.guard_checkbox_var = tk.BooleanVar()
        self.guard_checkbox = tk.Checkbutton(self, text="Guard", variable=self.guard_checkbox_var)
        self.guard_checkbox.place(relx=0.1, rely=0.5, anchor=tk.W)

        self.middle_checkbox_var = tk.BooleanVar()
        self.middle_checkbox = tk.Checkbutton(self, text="Middle", variable=self.middle_checkbox_var)
        self.middle_checkbox.place(relx=0.4, rely=0.5, anchor=tk.W)

        self.exit_checkbox_var = tk.BooleanVar()
        self.exit_checkbox = tk.Checkbutton(self, text="Exit", variable=self.exit_checkbox_var)
        self.exit_checkbox.place(relx=0.7, rely=0.5, anchor=tk.W)

        # Create text box for errors
        self.bottom_text_field = tk.Label(self, text="")
        self.bottom_text_field.place(relx=0.5, rely=0.65, anchor=tk.CENTER)

        # Create load button
        self.load_button = tk.Button(self, text="Load", background="blue", fg="white", command=self.load_saved_setting)
        self.load_button.place(relx=0.4, rely=0.8, anchor=tk.CENTER)

        # Create start button
        self.start_button = tk.Button(self, text="Start", background="green", fg="white", command=self.start)
        self.start_button.place(relx=0.6, rely=0.8, anchor=tk.CENTER)  


    def load_saved_setting(self):
        if self.node_gui_state == "Stop":
            # Clear the content
            self.ip_entry.delete(0, tk.END)  
            self.port_entry.delete(0, tk.END)  
            self.name_entry.delete(0, tk.END)  

            # set values from config
            with node.CONFIG_LOCK:
                self.ip_entry.insert(tk.END, self.config['connection']['ip']) 
                self.port_entry.insert(tk.END, self.config['connection']['port'])  
                self.name_entry.insert(tk.END, self.config['properties']['node-name']) 
                flags = self.config['properties']['flags']
            self.guard_checkbox_var.set('g' in flags)
            self.middle_checkbox_var.set('m' in flags)
            self.exit_checkbox_var.set('e' in flags)


    def save_setting(self, ip, port, name, flags):
        with node.CONFIG_LOCK:
            self.config['connection']['ip'] = ip
            self.config['connection']['port'] = port
            self.config['properties']['node-name'] = name
            self.config['properties']['flags'] = flags

            with open(node.CONFIG_PATH, 'w') as configfile:
                self.config.write(configfile)


    def check_input_fields(self, ip, port, name, flags):
        error_msg_fields = []

        if ip.count('.') != 3:
            error_msg_fields.append("ip")
        if not (port.isdigit() and 1 <= int(port) <= 65535):
            error_msg_fields.append("port")
        if name == "":
            error_msg_fields.append("name")
        if flags == "":
            error_msg_fields.append("flags")

        if len(error_msg_fields) > 0:
            error_msg = "Problem with fields: " + ', '.join(error_msg_fields) + "."
            return error_msg
        
        return ""
        

    def change_start_stop(self):
        self.bottom_text_field.config(text="")

        self.node_gui_state = "Stop" if self.node_gui_state == "Running" else "Running" 
        # switch button state: Start <-> Stop
        if self.node_gui_state == "Stop":
            self.start_button.config(text="Run", background="green", state="normal", command=self.start)
            inputs_state = "normal"
        else:
            self.start_button.config(text="Stop", background="red", state="normal", command=self.stop)
            inputs_state = "disabled"

        self.ip_entry.config(state=inputs_state)
        self.port_entry.config(state=inputs_state)
        self.name_entry.config(state=inputs_state)

        self.guard_checkbox.config(state=inputs_state)
        self.middle_checkbox.config(state=inputs_state)
        self.exit_checkbox.config(state=inputs_state)


    def check_node_state(self):
        while self.node_gui_state == "Running":
            time.sleep(1)
            if self.node.run_error:
                self.change_start_stop()
                error_msg = self.node.run_error.pop(0)
                self.bottom_text_field.config(text=error_msg, fg="red")
                break
            


    def start_node(self, ip, port, flags):
        directory_ip = "127.0.0.1"
        directory_port = 9999
        node.NodeManager.flags = flags
        self.node.set_params(ip, int(port), directory_ip, int(directory_port))
        self.node_thread = threading.Thread(target=self.node.run_node)
        self.node_thread.start()

        check_state_thread = threading.Thread(target=self.check_node_state)
        check_state_thread.start()


    def start(self):
        # Get the values from the input fields
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        name = self.name_entry.get()

        # read checkboxs
        flags = ""
        flags += 'g' if self.guard_checkbox_var.get() else ""
        flags += 'm' if self.middle_checkbox_var.get() else ""
        flags += 'e' if self.exit_checkbox_var.get() else ""

        error_msg = self.check_input_fields(ip, port, name, flags)
        self.bottom_text_field.config(text=error_msg, fg="red")
        
        if not error_msg:
            self.change_start_stop()
            self.start_node(ip, port, flags)
            self.save_setting(ip, port, name, flags)
            self.bottom_text_field.config(text="running", fg="green")


    def stop(self):
        self.bottom_text_field.config(text="stopping...", fg="black")
        self.start_button.config(state="disabled")
        self.node.set_node_off()
        # convert to milisecond
        self.after(node.CLOSING_WAITING_TIME * 1000, self.change_start_stop)


if __name__ == "__main__":
    app = NodeSetUp()
    app.mainloop()
