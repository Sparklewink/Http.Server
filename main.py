import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import http.server
import socketserver
import threading
import socket
import os
import sys
import base64
import functools
from urllib.parse import unquote
import html
import json  # Added for config file handling

try:
    import psutil  # Needed for listing network interfaces
except ImportError:
    messagebox.showerror("缺少依赖", "请先安装 'psutil' 库才能选择网络接口。\n在终端运行: pip install psutil")
    sys.exit(1)  # Exit if psutil is not available

CONFIG_FILE = "simple_http_server_config.json" # Configuration file name

def resource_path(relative_path):
    """ 获取资源的绝对路径，适用于开发环境和 PyInstaller 打包环境 """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- 全局变量 ---
server_thread = None
server_shutdown_thread = None # Thread for shutdown operation
httpd = None
selected_directory = "" # Will be loaded from config or set by user
server_running = False
USERNAME = "" # Will be loaded from config
PASSWORD = "" # Will be loaded from config

# --- 自定义请求处理器 (带基本认证和目录服务) ---
class AuthHandler(http.server.SimpleHTTPRequestHandler):
    AUTH_ENABLED = False
    EXPECTED_USERNAME = ""
    EXPECTED_PASSWORD = ""
    SHARED_DIRECTORY = "."

    def __init__(self, *args, **kwargs):
        # Use functools.partial to set the directory late, allowing it to be changed
        # This is better than modifying the class variable directly during runtime if multiple instances existed
        # However, since we restart the server each time, modifying the class variable is currently acceptable.
        # Sticking with the original class variable approach for simplicity here.
        super().__init__(*args, directory=self.SHARED_DIRECTORY, **kwargs)

    def do_HEAD(self):
        if not self.handle_auth():
            return
        super().do_HEAD()

    def do_GET(self):
        if not self.handle_auth():
            return
        try:
            path = self.translate_path(self.path)
            shared_abs = os.path.abspath(self.SHARED_DIRECTORY)
            path_abs = os.path.abspath(path)

            # Security Check: Ensure the requested path is within the shared directory
            # Using os.path.commonpath (or similar logic) is more robust
            # For simplicity, using startswith after normalization
            normalized_shared = os.path.normpath(shared_abs)
            normalized_path = os.path.normpath(path_abs)

            # Check if the common prefix of the normalized path and shared dir is the shared dir itself
            # This helps prevent escaping the shared directory via tricks like '.../' etc.
            if os.path.commonprefix([normalized_path, normalized_shared]) != normalized_shared:
                 self.log_message(f"Forbidden access attempt: {self.path} resolved to {normalized_path}, outside of {normalized_shared}")
                 self.send_error(403, "Forbidden")
                 return

        except Exception as e:
            self.send_error(404, f"Path error: {e}")
            return

        super().do_GET()

    def handle_auth(self):
        if not self.AUTH_ENABLED:
            return True

        auth_header = self.headers.get('Authorization')
        if auth_header is None:
            self.send_auth_required()
            return False

        auth_type, _, credentials = auth_header.partition(' ')
        if auth_type.lower() != 'basic':
            self.send_auth_required()
            return False

        try:
            decoded_credentials = base64.b64decode(credentials).decode('utf-8')
            username, password = decoded_credentials.split(':', 1)
        except (ValueError, TypeError, base64.binascii.Error, UnicodeDecodeError):
            self.send_auth_required()
            return False

        if username == self.EXPECTED_USERNAME and password == self.EXPECTED_PASSWORD:
            return True
        else:
            self.send_auth_required()
            return False

    def send_auth_required(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Restricted Area"')
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(b'<html><head><title>Authentication required</title></head>')
        self.wfile.write(b'<body><h1>401 Unauthorized</h1>')
        self.wfile.write(b'<p>Authentication required to access this resource.</p>')
        self.wfile.write(b'</body></html>')

    def list_directory(self, path):
        try:
            list_dir = os.listdir(path)
        except OSError:
            self.send_error(404, "No permission to list directory or directory not found")
            return None
        list_dir.sort(key=lambda a: a.lower())

        enc = "utf-8"
        displaypath = html.escape(unquote(self.path, errors='surrogatepass'), quote=False)
        title = f'Directory listing for {displaypath}'

        r = []
        r.append('<!DOCTYPE html>')
        r.append(f'<html lang="en"><head><meta charset="{enc}">')
        r.append(f'<title>{title}</title></head>')
        r.append(f'<body><h1>{title}</h1><hr><ul>')

        # Add link to parent directory
        if self.path != '/' and self.path != '\\':
             # Ensure the parent link is correctly formed
             parent_path = os.path.normpath(os.path.join(self.path, '..')) + '/'
             # Basic check to prevent going above root if path manipulation happens,
             # though translate_path should ideally handle it earlier.
             if not parent_path.startswith('//') and parent_path != '//':
                 r.append(f'<li><a href="{html.escape(parent_path, quote=True)}">.. (Parent Directory)</a></li>')


        for name in list_dir:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"

            quoted_linkname = html.escape(linkname, quote=True)
            escaped_displayname = html.escape(displayname)
            r.append(f'<li><a href="{quoted_linkname}">{escaped_displayname}</a></li>')

        r.append('</ul><hr></body></html>')
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')

        self.send_response(200)
        self.send_header("Content-type", f"text/html; charset={enc}")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()

        try:
            self.wfile.write(encoded)
        except BrokenPipeError:
            self.log_message("Client closed connection during directory listing.")
        return None


# --- GUI 应用类 ---
class HttpServerApp:
    def __init__(self, root):
        self.root = root
        root.title("文件共享")
        # Default geometry, will be overridden by config if available
        root.geometry("550x550") # Increased height slightly for log/address area

        # --- 文件夹选择 ---
        self.dir_frame = tk.Frame(root)
        self.dir_frame.pack(pady=10, padx=10, fill=tk.X)
        self.dir_label = tk.Label(self.dir_frame, text="共享文件夹:")
        self.dir_label.pack(side=tk.LEFT)
        self.dir_entry = tk.Entry(self.dir_frame, width=40)
        self.dir_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.browse_button = tk.Button(self.dir_frame, text="浏览", command=self.select_directory)
        self.browse_button.pack(side=tk.LEFT)

        # --- 网络设置 ---
        self.net_frame = tk.Frame(root)
        self.net_frame.pack(pady=5, padx=10, fill=tk.X)

        # Interface Selection
        self.interface_label = tk.Label(self.net_frame, text="监听接口:")
        self.interface_label.pack(side=tk.LEFT, padx=(0, 5))
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(self.net_frame, textvariable=self.interface_var, state="readonly", width=25)
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        self.populate_interfaces() # Populate the combobox

        self.port_label = tk.Label(self.net_frame, text="端口:")
        self.port_label.pack(side=tk.LEFT, padx=(10, 5)) # Add padding
        self.port_entry = tk.Entry(self.net_frame, width=7) # Adjust width
        self.port_entry.insert(0, "1314") # Default port
        self.port_entry.pack(side=tk.LEFT)

        # --- 认证设置 ---
        self.auth_frame = tk.LabelFrame(root, text="登录认证 (可选)")
        self.auth_frame.pack(pady=10, padx=10, fill=tk.X)
        self.user_label = tk.Label(self.auth_frame, text="用户名:")
        self.user_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.user_entry = tk.Entry(self.auth_frame, width=25)
        self.user_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.pass_label = tk.Label(self.auth_frame, text="密  码:")
        self.pass_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.pass_entry = tk.Entry(self.auth_frame, show="*", width=25)
        self.pass_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        # --- 服务器控制 ---
        self.control_frame = tk.Frame(root)
        self.control_frame.pack(pady=10)
        self.toggle_button = tk.Button(self.control_frame, text="启动服务器", command=self.toggle_server, width=15)
        self.toggle_button.pack()

        # --- 状态和地址显示 ---
        self.status_frame = tk.LabelFrame(root, text="服务器状态与访问地址")
        self.status_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.status_label = tk.Label(self.status_frame, text="状态: 已停止", fg="red")
        self.status_label.pack(pady=5)

        self.address_label = tk.Label(self.status_frame, text="访问地址将在此显示", justify=tk.LEFT, anchor='nw', wraplength=500) # Allow wrapping
        self.address_label.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)

        # --- Load Configuration ---
        self.load_config() # Load settings after GUI elements are created

        # --- Update display based on loaded/default settings ---
        self.update_address_display() # Initial display update

        # --- Bind interface selection change ---
        self.interface_combo.bind("<<ComboboxSelected>>", self.update_address_display)

        # --- 关闭窗口处理 ---
        root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def get_network_interfaces(self):
        """获取网络接口及其 IPv4 地址 (排除 127.0.0.1 和 APIPA)"""
        interfaces = {}
        try:
            all_interfaces = psutil.net_if_addrs()
            for name, addrs in all_interfaces.items():
                for addr in addrs:
                    # 只关心 IPv4, 非回环, 非 APIPA
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.') and not addr.address.startswith('169.254.'):
                         display_name = f"{name} ({addr.address})"
                         interfaces[display_name] = addr.address
        except Exception as e:
            self.log(f"获取网络接口时出错: {e}")
        return interfaces

    def populate_interfaces(self):
        """填充网络接口下拉列表, 移除 127.0.0.1 选项"""
        self.interfaces_map = self.get_network_interfaces() # Store map for later use
        # Start with "All Interfaces" as the primary option
        interface_list = ["所有接口 (0.0.0.0)"] + sorted(list(self.interfaces_map.keys())) # Sort specific interface names
        self.interface_combo['values'] = interface_list

        # Set default selection - prioritize "All Interfaces"
        current_selection = self.interface_var.get() # Get potential value loaded from config
        if current_selection in interface_list:
             self.interface_combo.set(current_selection) # Keep loaded value if valid
        elif "所有接口 (0.0.0.0)" in interface_list:
             self.interface_combo.set("所有接口 (0.0.0.0)")
        elif interface_list: # Fallback if "All" is somehow missing
             self.interface_combo.set(interface_list[0])
        else: # No interfaces found
            self.interface_combo.set("未找到接口")
            self.interface_combo['values'] = ["未找到接口"]


    def select_directory(self):
        global selected_directory
        # Suggest starting directory based on current entry or default
        initial_dir = self.dir_entry.get() if os.path.isdir(self.dir_entry.get()) else '/'
        directory = filedialog.askdirectory(initialdir=initial_dir)
        if directory:
            selected_directory = os.path.normpath(directory)
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, selected_directory)
            self.log(f"已选择文件夹: {selected_directory}")
            # Update global variable if needed immediately (though start_server uses entry value)
            # self.selected_directory = selected_directory # If using instance variable

    def update_address_display(self, event=None): # Accept optional event argument
        """更新界面上的访问地址信息"""
        global server_running
        try:
            port = int(self.port_entry.get())
            if not (0 < port < 65536): port = 1314 # Default if invalid
        except ValueError:
            port = 1314 # Default if non-integer

        selected_interface_display = self.interface_var.get()
        # Refresh map in case interfaces changed since startup? Maybe not needed unless requested.
        # current_interfaces_map = self.get_network_interfaces() # Use self.interfaces_map populated earlier

        bind_ip = "未知"
        display_ips = []

        if selected_interface_display == "所有接口 (0.0.0.0)":
            bind_ip = "0.0.0.0"
            # Get all non-loopback IPs from the stored map
            display_ips = list(self.interfaces_map.values())
        elif selected_interface_display in self.interfaces_map:
            bind_ip = self.interfaces_map[selected_interface_display]
            display_ips = [bind_ip] # Only this specific IP
        elif selected_interface_display == "未找到接口":
             bind_ip = "无效"
        else:
             # Handle case where saved interface no longer exists
             bind_ip = "选择无效"
             display_ips = []


        address_text = f"监听接口: {selected_interface_display}\n"
        address_text += f"绑定地址: {bind_ip}:{port}\n\n"

        if not server_running:
            address_text += "服务器状态: 已停止\n\n"
            self.status_label.config(text="状态: 已停止", fg="red")
        else:
            address_text += "服务器状态: 运行中\n\n"
            self.status_label.config(text="状态: 运行中", fg="green")


        address_text += "可能的访问地址:\n"
        # Always show loopback address for local testing
        address_text += f"  - 本机测试: http://127.0.0.1:{port}\n"

        if server_running:
            if bind_ip == "0.0.0.0":
                 if display_ips:
                      address_text += "  - 局域网内 (尝试):\n"
                      for ip in sorted(list(set(display_ips))): # Show unique IPs sorted
                          address_text += f"      http://{ip}:{port}\n"
                 else:
                      address_text += "  - 局域网内: 未找到可用 IP 地址\n"
                      address_text += "     (请检查网络连接或防火墙设置)\n"
            elif bind_ip not in ["未知", "无效", "选择无效"]:
                address_text += f"  - 局域网内: http://{bind_ip}:{port}\n"
            else:
                address_text += "  - 局域网内: (监听接口选择无效)\n"
        else:
             address_text += "  - 局域网内: (服务器停止时无法访问)\n"

        address_text += "\n注意: 其他设备访问需确保防火墙允许此端口。"
        self.address_label.config(text=address_text)


    def toggle_server(self):
        global server_running
        if server_running:
            self.stop_server()
        else:
            self.start_server()

    def start_server(self):
        global server_thread, httpd, selected_directory, server_running, USERNAME, PASSWORD

        if server_shutdown_thread and server_shutdown_thread.is_alive():
            messagebox.showwarning("请稍候", "服务器仍在关闭中，请稍后再试。")
            return

        # Get selected directory directly from entry widget
        current_selected_directory = self.dir_entry.get()
        if not current_selected_directory or not os.path.isdir(current_selected_directory):
            messagebox.showerror("错误", "请先选择一个有效的共享文件夹！")
            return
        # Update the global/class variable used by the handler
        selected_directory = current_selected_directory
        AuthHandler.SHARED_DIRECTORY = selected_directory


        try:
            port = int(self.port_entry.get())
            if not (0 < port < 65536):
                raise ValueError("端口号无效")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的端口号 (1-65535)！")
            return

        # Get selected interface IP
        selected_interface_display = self.interface_var.get()
        # Use the map populated at init
        # self.interfaces_map = self.get_network_interfaces() # Refresh map? Maybe not needed.
        bind_ip = ""

        if selected_interface_display == "所有接口 (0.0.0.0)":
            bind_ip = "0.0.0.0"
        elif selected_interface_display in self.interfaces_map:
            bind_ip = self.interfaces_map[selected_interface_display]
        else:
             messagebox.showerror("错误", f"选择的网络接口 '{selected_interface_display}' 无效或不可用。请重新选择。")
             self.populate_interfaces() # Refresh interfaces list
             self.update_address_display() # Update display based on new selection
             return

        # Get user/pass from entries
        USERNAME = self.user_entry.get().strip()
        PASSWORD = self.pass_entry.get()

        # Configure AuthHandler class variables
        AuthHandler.EXPECTED_USERNAME = USERNAME
        AuthHandler.EXPECTED_PASSWORD = PASSWORD
        if USERNAME and PASSWORD:
            AuthHandler.AUTH_ENABLED = True
            self.log(f"认证已启用，用户名: {USERNAME}")
        else:
            AuthHandler.AUTH_ENABLED = False
            self.log("认证未启用 (用户名或密码为空)")


        try:
            address = (bind_ip, port)
            socketserver.TCPServer.allow_reuse_address = True
            # Pass the AuthHandler CLASS, not an instance
            httpd = socketserver.TCPServer(address, AuthHandler)

            server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            server_thread.start()

            server_running = True
            self.toggle_button.config(text="停止服务器")
            self.log(f"服务器尝试启动于 {bind_ip}:{port}")
            self.log(f"共享目录: {AuthHandler.SHARED_DIRECTORY}")
            self.update_address_display() # Update address and status

            # Disable input fields
            self.dir_entry.config(state=tk.DISABLED)
            self.browse_button.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            self.user_entry.config(state=tk.DISABLED)
            self.pass_entry.config(state=tk.DISABLED)
            self.interface_combo.config(state=tk.DISABLED)

        except OSError as e:
            messagebox.showerror("错误", f"启动服务器失败！\n{e}\n地址 {bind_ip}:{port} 可能已被占用、无效或权限不足。")
            httpd = None
            server_running = False
            self.update_address_display()
        except Exception as e:
            messagebox.showerror("错误", f"启动服务器时发生未知错误: {e}")
            httpd = None
            server_running = False
            self.update_address_display()

    def stop_server(self):
        global server_thread, httpd, server_running, server_shutdown_thread
        if httpd and server_running:
            self.log("正在请求停止服务器...")
            self.toggle_button.config(state=tk.DISABLED)

            def shutdown_task():
                global httpd, server_running, server_thread
                local_httpd_ref = httpd
                try:
                    if local_httpd_ref:
                       local_httpd_ref.shutdown()
                       self.log("服务器 shutdown() 调用完成。")
                       local_httpd_ref.server_close()
                       self.log("服务器 server_close() 调用完成。")
                except Exception as e:
                    self.log(f"关闭服务器时出错 (shutdown/close): {e}")
                finally:
                    server_running = False
                    httpd = None
                    server_thread = None
                    self.root.after(0, self.finalize_stop_gui) # Schedule GUI update

            server_shutdown_thread = threading.Thread(target=shutdown_task, daemon=True)
            server_shutdown_thread.start()

            # Immediate GUI feedback
            self.status_label.config(text="状态: 正在停止...", fg="orange")

        elif not server_running:
             self.log("服务器已经停止。")
             self.finalize_stop_gui() # Ensure GUI is correct
        else:
            self.log("服务器对象不存在，无法停止。")
            self.finalize_stop_gui() # Ensure GUI is correct

    def finalize_stop_gui(self):
        """Updates the GUI after the server has stopped."""
        global server_running
        server_running = False
        self.toggle_button.config(text="启动服务器", state=tk.NORMAL)
        self.log("服务器已停止。")
        self.update_address_display() # Update address and status label

        # Enable input fields
        self.dir_entry.config(state=tk.NORMAL)
        self.browse_button.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
        self.user_entry.config(state=tk.NORMAL)
        self.pass_entry.config(state=tk.NORMAL)
        # Ensure combobox state is correct (readonly)
        self.interface_combo.config(state='readonly')


    def log(self, message):
        """简单的日志记录 (打印到控制台)"""
        print(f"[LOG] {message}") # Added prefix for clarity

    # --- Configuration Loading/Saving ---
    def load_config(self):
        global selected_directory, USERNAME, PASSWORD # Allow modification
        self.log(f"尝试从 {CONFIG_FILE} 加载配置...")
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            self.log("配置加载成功。")

            # Restore window geometry
            if 'geometry' in config_data:
                try:
                    self.root.geometry(config_data['geometry'])
                except tk.TclError as e:
                    self.log(f"无法设置窗口位置 (可能在不同屏幕布局下): {e}")


            # Restore directory - check if it still exists
            saved_dir = config_data.get('directory', '')
            if saved_dir and os.path.isdir(saved_dir):
                selected_directory = saved_dir
                self.dir_entry.insert(0, selected_directory)
                self.log(f"恢复共享文件夹: {selected_directory}")
            elif saved_dir:
                 self.log(f"警告: 保存的文件夹 '{saved_dir}' 不再有效。")


            # Restore credentials
            USERNAME = config_data.get('username', '')
            PASSWORD = config_data.get('password', '') # WARNING: Plain text password
            self.user_entry.insert(0, USERNAME)
            self.pass_entry.insert(0, PASSWORD)
            if USERNAME:
                self.log("恢复用户名。")
            if PASSWORD:
                self.log("警告: 已从配置文件恢复明文密码。")

            # Restore port
            saved_port = config_data.get('port', '1314')
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, saved_port)
            self.log(f"恢复端口: {saved_port}")

            # Restore interface selection
            saved_interface = config_data.get('interface', "所有接口 (0.0.0.0)")
            # Check if saved interface is still valid in the current list
            if saved_interface in self.interface_combo['values']:
                 self.interface_var.set(saved_interface)
                 self.log(f"恢复监听接口: {saved_interface}")
            else:
                 self.log(f"警告: 保存的接口 '{saved_interface}' 不再可用，使用默认值。")
                 # Default will be set by populate_interfaces logic later if needed
                 self.interface_var.set("所有接口 (0.0.0.0)") # Explicitly set default


        except FileNotFoundError:
            self.log(f"配置文件 {CONFIG_FILE} 未找到，使用默认设置。")
        except json.JSONDecodeError:
            self.log(f"配置文件 {CONFIG_FILE} 格式错误，使用默认设置。")
        except Exception as e:
            self.log(f"加载配置时发生未知错误: {e}")

        # Ensure AuthHandler reflects loaded credentials initially
        AuthHandler.EXPECTED_USERNAME = USERNAME
        AuthHandler.EXPECTED_PASSWORD = PASSWORD
        AuthHandler.AUTH_ENABLED = bool(USERNAME and PASSWORD)
        # Ensure shared directory is set initially if loaded
        if selected_directory:
             AuthHandler.SHARED_DIRECTORY = selected_directory


    def save_config(self):
        """Saves current settings to the configuration file."""
        global selected_directory, USERNAME, PASSWORD # Use current globals/inputs
        config_data = {
            'geometry': self.root.geometry(),
            'directory': self.dir_entry.get(), # Get current value from entry
            'username': self.user_entry.get().strip(),
            'password': self.pass_entry.get(), # WARNING: Saving plain text password
            'port': self.port_entry.get(),
            'interface': self.interface_var.get()
        }
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4, ensure_ascii=False)
            self.log(f"配置已保存到 {CONFIG_FILE}")
        except IOError as e:
            self.log(f"错误：无法保存配置到 {CONFIG_FILE}: {e}")
            messagebox.showwarning("保存配置失败", f"无法将配置写入文件 {CONFIG_FILE}。\n请检查权限或磁盘空间。\n错误: {e}")
        except Exception as e:
             self.log(f"保存配置时发生未知错误: {e}")
             messagebox.showwarning("保存配置失败", f"保存配置时发生未知错误。\n错误: {e}")


    def on_closing(self):
        """Handle window closing: save config, stop server if running."""
        self.log("关闭窗口请求...")
        self.save_config() # Save current settings first

        if server_running:
            if messagebox.askokcancel("退出", "服务器正在运行。确定要退出并停止服务器吗？"):
                self.log("用户确认退出，开始停止服务器...")
                self.stop_server()
                # Schedule check for shutdown completion before destroying
                self.root.after(100, self.check_shutdown_and_destroy)
            else:
                self.log("用户取消退出。")
                return # Do not close the window
        else:
             self.log("服务器未运行，直接退出。")
             self.root.destroy()

    def check_shutdown_and_destroy(self):
        """Helper for on_closing to wait for shutdown before destroying window."""
        if server_shutdown_thread and server_shutdown_thread.is_alive():
            self.log("等待服务器关闭...")
            self.root.after(100, self.check_shutdown_and_destroy)
        else:
            self.log("服务器已停止 (或从未运行)，销毁窗口。")
            self.root.destroy()


# --- 主程序入口 ---
if __name__ == "__main__":
    root = tk.Tk()
    try:
        # Attempt to load icon
        icon_path = resource_path("xz.ico")
        if os.path.exists(icon_path):
             root.iconbitmap(icon_path)
        else:
             print(f"[警告] 图标文件未找到: {icon_path}")
    except Exception as e:
        print(f"[警告] 设置图标时出错: {e}")

    app = HttpServerApp(root)
    root.mainloop()