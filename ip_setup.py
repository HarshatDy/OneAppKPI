import http.server
import socketserver
import json
import urllib.parse
import os
import subprocess
import re
import threading
import socket
import webbrowser
import time
import sys

def get_server_url():
    """Returns the actual server URL that should be used for connections"""
    try:
        # Get hostname or IP address dynamically
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 53))  # Doesn't need to be reachable
        local_ip = s.getsockname()[0]
        s.close()
        return f"http://{local_ip}:{PORT}"
    except:
        # Fallback to hostname
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return f"http://{local_ip}:{PORT}"
        except:
            # Ultimate fallback
            return f"http://localhost:{PORT}"

# Import functions from SIT_SERVER_SPACE.py
try:
    from SIT_SERVER_SPACE import ssh_login, bash_command
    print("[INFO] Successfully imported functions from SIT_SERVER_SPACE")
except ImportError as e:
    print(f"[ERROR] Failed to import from SIT_SERVER_SPACE: {str(e)}")
    # Define fallback functions if import fails
    def ssh_login(ip):
        print(f"[MOCK] Would connect to SSH at {ip}")
        return None
        
    def bash_command(ssh, cmd):
        print(f"[MOCK] Would execute: {cmd}")
        return ["Command could not be executed - SIT_SERVER_SPACE module not available"]

# Default port for the setup server
PORT = 8080
# Add this constant at the top of the file where PORT is defined
DASHBOARD_PATH = "/dashboard"  # New path prefix for dashboard content
# Flag to track if browser has been opened
BROWSER_OPENED = False

class SetupRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        """Serve the setup HTML page and dashboard content"""
        
        # Handle dashboard requests
        if self.path.startswith(DASHBOARD_PATH):
            # Extract the path after /dashboard
            dashboard_file_path = self.path[len(DASHBOARD_PATH):]
            
            # Strip query parameters (anything after ?)
            if '?' in dashboard_file_path:
                dashboard_file_path = dashboard_file_path.split('?')[0]
            
            # Clean up the path
            dashboard_file_path = dashboard_file_path.lstrip('/')
            
            # Construct the absolute file path using os.path.join for proper slashes
            script_dir = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(script_dir, dashboard_file_path)
            
            print(f"[DEBUG] Looking for dashboard file: {file_path}")
            
            # Check if file exists
            if os.path.exists(file_path) and os.path.isfile(file_path):
                # Determine content type
                content_type = 'application/json' if file_path.endswith('.json') else 'text/html'
                
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    
                    self.send_response(200)
                    self.send_header('Content-Type', content_type)
                    self.send_header('Content-Length', str(len(content)))
                    self.send_cors_headers()
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception as e:
                    print(f"[ERROR] Error reading file {file_path}: {str(e)}")
            else:
                # If JSON file is requested but doesn't exist, return empty JSON object
                if dashboard_file_path.endswith('.json'):
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_cors_headers()
                    self.end_headers()
                    self.wfile.write(b'{}')
                    return
                else:
                    print(f"[ERROR] Dashboard file not found: {file_path}")
                    self.send_response(404)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'<html><body>Dashboard file not found</body></html>')
                    return
        
        # Handle ping request
        if self.path.startswith('/ping'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'pong')
            return
            
        # Add new endpoint to get active sessions
        if self.path == '/active_sessions':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            
            # Get active sessions
            sessions = self.get_active_sessions()
            self.wfile.write(json.dumps(sessions).encode())
            return
            
        if self.path == '/' or self.path == '/index.html':
            # Define the absolute path to setup.html
            script_dir = os.path.dirname(os.path.abspath(__file__))
            setup_html_path = os.path.join(script_dir, 'setup.html')
            
            # Check if the file exists
            if os.path.exists(setup_html_path):
                try:
                    # Read the file content first to avoid partial header sending
                    with open(setup_html_path, 'rb') as file:
                        content = file.read()
                    
                    # Now send the complete response
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.send_header('Content-Length', str(len(content)))
                    # Add CORS headers after sending response but before ending headers
                    self.send_cors_headers()
                    self.end_headers()
                    
                    # Write content after headers are complete
                    self.wfile.write(content)
                    print(f"[INFO] Successfully served setup.html ({len(content)} bytes)")
                    return
                except Exception as e:
                    print(f"[ERROR] Error reading setup.html: {str(e)}")
                    self.send_response(500)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'<html><body>Error reading setup file</body></html>')
                    return
            else:
                print(f"[ERROR] setup.html not found at {setup_html_path}")
                # Try alternative locations
                alt_path = os.path.join(os.path.dirname(script_dir), 'setup.html')
                if os.path.exists(alt_path):
                    try:
                        # Read the file first
                        with open(alt_path, 'rb') as file:
                            content = file.read()
                        
                        # Send complete response
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/html')
                        self.send_header('Content-Length', str(len(content)))
                        self.send_cors_headers()
                        self.end_headers()
                        self.wfile.write(content)
                        print(f"[INFO] Served setup.html from alt location ({len(content)} bytes)")
                        return
                    except Exception as e:
                        print(f"[ERROR] Error reading alternative setup.html: {str(e)}")
                
                # If we reach here, we couldn't find setup.html
                self.send_response(404)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<html><body>Setup file not found</body></html>')
                return
        
        # For other requests, use the parent class handler
        try:
            super().do_GET()
        except Exception as e:
            print(f"[ERROR] Error in parent do_GET handler: {str(e)}")
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Internal server error')

    def send_cors_headers(self):
        """Add CORS headers to the response"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
    
    def do_POST(self):
        """Handle form submission with IP address"""
        if self.path == '/setup':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')
                form_data = urllib.parse.parse_qs(post_data)
                
                ip_address = form_data.get('ip', [''])[0].strip()
                print(f"[INFO] Received IP address: {ip_address}")
                
                # Check if IP address is valid
                if not self.is_valid_ip(ip_address):
                    print(f"[ERROR] Invalid IP format: {ip_address}")
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.send_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'success': False,
                        'message': 'Invalid IP address format'
                    }).encode())
                    return
                
                # Check procmon status before updating IP
                procmon_status = self.check_procmon_status(ip_address)
                if not procmon_status['running']:
                    print(f"[ERROR] Procmon is not running on {ip_address}")
                    self.send_response(200)  # Send 200 but with error message
                    self.send_header('Content-Type', 'application/json')
                    self.send_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'success': False,
                        'message': f"Procmon is not active on {ip_address}. Cannot initiate KPI tracking.",
                        'status': procmon_status.get('status_text', 'Status Check Failed'),
                        'procmon_active': False
                    }).encode())
                    return
                
                # Update IP in start.py file only if procmon is active
                if self.update_ip_in_start_py(ip_address):
                    # Start the monitoring script
                    threading.Thread(target=self.start_monitoring_script, daemon=True).start()
                    
                    # Return success response
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'success': True,
                        'message': 'Successfully updated IP and started monitoring',
                        'status': procmon_status.get('status_text', 'PROCMON: ACTIVE'),
                        'procmon_active': True
                    }).encode())
                    print("[INFO] Sent successful response")
                else:
                    self.send_response(500)
                    self.send_header('Content-Type', 'application/json')
                    self.send_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'success': False,
                        'message': 'Failed to update IP address in script'
                    }).encode())
            except Exception as e:
                print(f"[ERROR] Error in do_POST: {str(e)}")
                self.send_response(500)
                self.send_header('Content-Type', 'text/html')
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(f'<html><body>Server error: {str(e)}</body></html>'.encode())
        elif self.path == '/end_session':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')
                session_data = json.loads(post_data)
                
                ip_address = session_data.get('ip', '')
                pid = session_data.get('pid', 0)
                
                result = self.end_monitoring_session(ip_address, pid)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
            except Exception as e:
                print(f"[ERROR] Error ending session: {str(e)}")
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    'success': False,
                    'message': f'Server error: {str(e)}'
                }).encode())
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body>Not found</body></html>')
    
    def do_OPTIONS(self):
        """Handle preflight CORS requests"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def is_valid_ip(self, ip):
        """Validate IP address format"""
        ip_pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
        match = ip_pattern.match(ip)
        
        if not match:
            return False
        
        # Check if each octet is between 0 and 255
        for i in range(1, 5):
            octet = int(match.group(i))
            if octet < 0 or octet > 255:
                return False
        
        return True
    
    def update_ip_in_start_py(self, new_ip):
        """Update the IP address in start.py"""
        try:
            # Get the path to start.py
            script_dir = os.path.dirname(os.path.abspath(__file__))
            start_py_path = os.path.join(script_dir, 'start.py')
            
            # Read the current content
            with open(start_py_path, 'r') as file:
                content = file.read()
            
            # Replace the IP address using regex
            new_content = re.sub(r'ip\s*=\s*"[^"]+"', f'ip="{new_ip}"', content)
            
            # Write the updated content back
            with open(start_py_path, 'w') as file:
                file.write(new_content)
            
            print(f"[INFO] Updated IP address in start.py to {new_ip}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to update IP in start.py: {str(e)}")
            return False

    def start_monitoring_script(self):
        """Start the monitoring script in a new process and track the session"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            start_py_path = os.path.join(script_dir, 'start.py')
            
            # Wait a brief moment to ensure the response is sent
            time.sleep(1)
            
            # Execute the start.py script
            print("[INFO] Starting monitoring script...")
            
            # Get the Python executable that's running this script
            python_exe = sys.executable
            
            # Start the process using the same Python interpreter
            process = subprocess.Popen([python_exe, start_py_path])
            process_id = process.pid
            print(f"[INFO] Monitoring script started with PID: {process_id}")
            
            # Get the IP address from start.py
            ip_address = self.get_ip_from_start_py()
            
            # Record this session in the global active sessions file
            self.update_active_sessions(ip_address, process_id)
            
        except Exception as e:
            print(f"[ERROR] Failed to start monitoring script: {str(e)}")

    def get_ip_from_start_py(self):
        """Extract the current IP address from start.py"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            start_py_path = os.path.join(script_dir, 'start.py')
            
            with open(start_py_path, 'r') as file:
                content = file.read()
                
            # Use regex to find the IP assignment
            match = re.search(r'ip\s*=\s*"([^"]+)"', content)
            if match:
                return match.group(1)
            else:
                print("[WARNING] Could not find IP address in start.py")
                return "unknown"
        except Exception as e:
            print(f"[ERROR] Failed to extract IP from start.py: {str(e)}")
            return "unknown"

    def update_active_sessions(self, ip_address, process_id):
        """Update the global active sessions file with this new session"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            sessions_file_path = os.path.join(script_dir, 'global_active_sessions.json')
            
            # Create or load the sessions data
            sessions = {}
            if os.path.exists(sessions_file_path):
                try:
                    with open(sessions_file_path, 'r') as file:
                        sessions = json.load(file)
                except json.JSONDecodeError:
                    print("[WARNING] Invalid sessions file format, creating new one")
                    sessions = {}
            
            # Check which processes are still running and clean up stale entries
            active_sessions = {}
            for ip, session_info in sessions.items():
                pid = session_info.get('pid')
                if pid:
                    # Check if process is still running
                    try:
                        # Different ways to check process on Windows vs Linux
                        if sys.platform == 'win32':
                            # On Windows
                            import ctypes
                            kernel32 = ctypes.windll.kernel32
                            handle = kernel32.OpenProcess(1, 0, pid)
                            if handle:
                                active_sessions[ip] = session_info
                                kernel32.CloseHandle(handle)
                        else:
                            # On Linux/Unix
                            os.kill(pid, 0)  # This raises an exception if process is not running
                            active_sessions[ip] = session_info
                    except (OSError, AttributeError, ImportError):
                        # Process not running, exclude from active sessions
                        print(f"[INFO] Process for IP {ip} (PID {pid}) is no longer running")
                        continue
            
            # Add the new session
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            active_sessions[ip_address] = {
                'pid': process_id,
                'started_at': timestamp,
                'last_checked': timestamp
            }
            
            # Save the updated sessions data
            with open(sessions_file_path, 'w') as file:
                json.dump(active_sessions, file, indent=2)
            
            print(f"[INFO] Updated active sessions file: {len(active_sessions)} active sessions")
        except Exception as e:
            print(f"[ERROR] Failed to update active sessions file: {str(e)}")

    def shutdown_server(self):
        """Shutdown the server to close the browser"""
        try:
            print("[INFO] Shutting down setup server...")
            # Get the server instance
            server = self.server
            # Schedule shutdown
            server.shutdown()
        except Exception as e:
            print(f"[ERROR] Failed to shutdown server: {str(e)}")
    
    def check_procmon_status(self, ip):
        """
        Checks if procmon is running on the specified IP and returns the status.
        Similar to check_procmon_status in start.py
        
        Returns:
            dict: Dictionary containing 'running' (bool), 'status_text' (str),
                  'disable_charts' (bool), and 'message' (str)
        """
        try:
            # Try to establish SSH connection
            ssh = ssh_login(ip)
            
            if ssh is None:
                return {
                    'running': False, 
                    'status_text': 'SSH Connection Failed', 
                    'disable_charts': True, 
                    'message': 'SSH Connection Failed. Please check IP address and network.'
                }
            
            # Check if procmon is running using same method as in start.py
            result = bash_command(ssh, "systemctl status procmon")
            
            # Check if the command was successful
            if not result or not result[0]:
                return {
                    'running': False, 
                    'status_text': 'Status Check Failed', 
                    'disable_charts': True, 
                    'message': 'Failed to check procmon status.'
                }
            
            # Parse the status
            status_text = result[0]
            is_running = "Active: active (running)" in status_text
            
            status = {
                'running': is_running,
                'status_text': "PROCMON: ACTIVE" if is_running else "PROCMON: INACTIVE",
                'timestamp': time.time(),
                'disable_charts': not is_running,
                'message': "Procmon is active" if is_running else "PROCMON IS DOWN - Cannot proceed with setup."
            }
            
            print(f"[INFO] Procmon status: {status['status_text']}")
            return status
            
        except Exception as e:
            print(f"[ERROR] Error checking procmon status: {str(e)}")
            return {
                'running': False,
                'status_text': f'Error: {str(e)}',
                'disable_charts': True,
                'message': f'Error checking procmon status: {str(e)}'
            }

    def get_active_sessions(self):
        """Get all active monitoring sessions from the global_active_sessions.json file"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            sessions_file_path = os.path.join(script_dir, 'global_active_sessions.json')
            
            if not os.path.exists(sessions_file_path):
                print("[INFO] No active sessions file found")
                return {}
            
            with open(sessions_file_path, 'r') as f:
                sessions = json.load(f)
            
            # Check which sessions are still active
            active_sessions = {}
            for ip, session_info in sessions.items():
                pid = session_info.get('pid')
                if pid:
                    # Check if process is still running
                    try:
                        # Different ways to check process on Windows vs Linux
                        if sys.platform == 'win32':
                            # On Windows
                            import ctypes
                            kernel32 = ctypes.windll.kernel32
                            handle = kernel32.OpenProcess(1, 0, pid)
                            if handle:
                                active_sessions[ip] = session_info
                                kernel32.CloseHandle(handle)
                        else:
                            # On Linux/Unix
                            os.kill(pid, 0)  # This raises an exception if process is not running
                            active_sessions[ip] = session_info
                    except (OSError, AttributeError, ImportError):
                        # Process not running, exclude from active sessions
                        print(f"[INFO] Process for IP {ip} (PID {pid}) is no longer running")
                        continue
            
            # If the active sessions differ from the file, update the file
            if len(active_sessions) != len(sessions):
                with open(sessions_file_path, 'w') as f:
                    json.dump(active_sessions, f, indent=2)
                print(f"[INFO] Updated active sessions file: {len(active_sessions)} active sessions")
            
            return active_sessions
        
        except Exception as e:
            print(f"[ERROR] Failed to get active sessions: {str(e)}")
            return {}

    def end_monitoring_session(self, ip_address, pid):
        """End a monitoring session by killing its process"""
        try:
            if not ip_address or not pid:
                return {'success': False, 'message': 'Invalid IP address or PID'}
            
            # Try to terminate the process
            process_killed = False
            try:
                if sys.platform == 'win32':
                    # On Windows
                    import subprocess
                    subprocess.call(['taskkill', '/F', '/PID', str(pid)])
                    process_killed = True
                else:
                    # On Linux/Unix
                    os.kill(pid, 9)  # SIGKILL
                    process_killed = True
            except (OSError, subprocess.SubprocessError) as e:
                print(f"[ERROR] Failed to kill process {pid}: {str(e)}")
                return {'success': False, 'message': f'Failed to terminate process: {str(e)}'}
            
            # Update the active sessions file
            script_dir = os.path.dirname(os.path.abspath(__file__))
            sessions_file_path = os.path.join(script_dir, 'global_active_sessions.json')
            
            if os.path.exists(sessions_file_path):
                with open(sessions_file_path, 'r') as f:
                    sessions = json.load(f)
                
                # Remove the terminated session
                if ip_address in sessions:
                    del sessions[ip_address]
                
                with open(sessions_file_path, 'w') as f:
                    json.dump(sessions, f, indent=2)
            
            return {
                'success': True,
                'message': f'Successfully terminated monitoring session for {ip_address}'
            }
        
        except Exception as e:
            print(f"[ERROR] Error ending monitoring session: {str(e)}")
            return {'success': False, 'message': f'Server error: {str(e)}'}

    # Add this function to SetupRequestHandler class
    def ensure_data_dirs_exist(self, ip_address):
        """Makes sure the IP-specific directory exists and contains empty data files"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            clean_ip = ip_address.replace('.', '_')
            ip_dir = os.path.join(script_dir, clean_ip)
            
            # Create directory if it doesn't exist
            if not os.path.exists(ip_dir):
                os.makedirs(ip_dir)
                print(f"[INFO] Created directory for IP {ip_address}: {ip_dir}")
            
            # List of JSON files to ensure exist in the IP directory
            required_files = [
                f"procmon_status_{clean_ip}.json",
                f"cell_info_{clean_ip}.json",
                f"cell_selection_{clean_ip}.json",
                f"ue_info_{clean_ip}.json",
                f"ue_selection_{clean_ip}.json",
                f"du_chart_data_{clean_ip}.json",
                f"l1_chart_data_{clean_ip}.json",
                f"la_chart_data_{clean_ip}.json",
                f"ue_chart_data_{clean_ip}.json",
                f"error_logs_{clean_ip}.json",
                f"server_info_{clean_ip}.json",
                f"ue_count_{clean_ip}.json"
            ]
            
            # Initialize each file if it doesn't exist
            for file_name in required_files:
                file_path = os.path.join(ip_dir, file_name)
                if not os.path.exists(file_path):
                    with open(file_path, 'w') as f:
                        f.write('{}')
                    print(f"[INFO] Initialized empty file: {file_path}")
                    
            return True
        except Exception as e:
            print(f"[ERROR] Failed to ensure data directories exist: {str(e)}")
            return False

def main():
    """Main function that runs the setup server"""
    global BROWSER_OPENED
    
    print(f"[INFO] Starting setup server on port {PORT}...")
    
    # Set the current directory to the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Check if setup.html exists and create it if not found
    setup_html_path = os.path.join(script_dir, 'setup.html')
    if os.path.exists(setup_html_path):
        try:
            with open(setup_html_path, 'r', encoding='utf-8') as test_file:
                # Just check if we can read the file
                test_file.read(10)
            print(f"[INFO] Found setup.html at: {setup_html_path}")
        except Exception as e:
            print(f"[WARNING] Found setup.html but couldn't read it: {str(e)}")
            try:
                os.remove(setup_html_path)
                print("[INFO] Removed unreadable setup.html")
            except:
                pass
    
    # If setup.html doesn't exist or was removed due to errors, create it
    if not os.path.exists(setup_html_path) or not os.access(setup_html_path, os.R_OK):
        # First check if it exists in the parent directory
        parent_path = os.path.join(os.path.dirname(script_dir), 'setup.html')
        if os.path.exists(parent_path):
            print(f"[INFO] Found setup.html in parent directory: {parent_path}")
            # Copy the file to the current directory
            try:
                import shutil
                shutil.copy2(parent_path, setup_html_path)
                print(f"[INFO] Copied setup.html to the current directory")
            except Exception as e:
                print(f"[ERROR] Failed to copy setup.html: {str(e)}")
    
    # Create the server with retry mechanism
    retry_count = 0
    max_retries = 3
    while retry_count < max_retries:
        try:
            handler = SetupRequestHandler
            # Bind to all interfaces (0.0.0.0) instead of just localhost
            httpd = socketserver.TCPServer(("0.0.0.0", PORT), handler)
            
            # Get the actual server IP address for display purposes
            hostname = socket.gethostname()
            server_ip = socket.gethostbyname(hostname)
            
            print(f"[INFO] Server running at:")
            print(f"  - Local URL: http://localhost:{PORT}")
            print(f"  - Network URL: http://{server_ip}:{PORT}")
            
            # Make sure the server is ready before opening the browser
            def server_ready_check():
                global BROWSER_OPENED
                time.sleep(2)  # Give server more time to initialize
                
                if not BROWSER_OPENED:
                    print("[INFO] Opening setup page in web browser...")
                    webbrowser.open(f"http://localhost:{PORT}")
                    BROWSER_OPENED = True
            
            # Start the server ready check in a separate thread
            server_thread = threading.Thread(target=server_ready_check)
            server_thread.daemon = True
            server_thread.start()
            
            # Serve until interrupted
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("[INFO] Server stopped by user")
            break  # If we get here without exceptions, break out of retry loop
                
        except OSError as e:
            if e.errno == 98 or e.errno == 10048:  # Port already in use
                print(f"[ERROR] Port {PORT} is already in use. The server may already be running.")
                # Still try to open the browser if the server is already running
                if not BROWSER_OPENED:
                    print("[INFO] Opening setup page in web browser...")
                    webbrowser.open(f"http://localhost:{PORT}")
                break  # Don't retry if port is in use
            else:
                print(f"[ERROR] Failed to start server (attempt {retry_count+1}/{max_retries}): {str(e)}")
                retry_count += 1
                if retry_count < max_retries:
                    print(f"Retrying in 2 seconds...")
                    time.sleep(2)
                else:
                    print("Maximum retries reached. Server could not be started.")


if __name__ == "__main__":
    main()
