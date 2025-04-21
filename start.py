from SIT_SERVER_SPACE import *

import numpy as np
import time
from collections import deque
import sys
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.offline as pyo
import threading
import webbrowser
import os
import http.server
import socketserver
import re  # Add this import at the top if it's not already there
import json  # Make sure json is imported
import shutil  # Add this for file operations

ip="172.30.20.190"

# Initialize base directory and IP-specific directory
output_dir = os.path.dirname(os.path.abspath(__file__))

# Function to prepare IP-specific directory and files
def prepare_ip_directory(ip_address):
    """
    Creates an IP-specific directory if it doesn't exist and returns the path.
    Also ensures all JSON files are properly initialized in that directory.
    
    Args:
        ip_address: The IP address to use for directory naming
    
    Returns:
        str: Path to the IP-specific directory
    """
    # Clean IP address for folder name (replace dots with underscores)
    clean_ip = ip_address.replace('.', '_')
    
    # Create IP-specific directory path
    ip_dir = os.path.join(output_dir, clean_ip)
    
    # Create directory if it doesn't exist
    if not os.path.exists(ip_dir):
        print(f"[INFO] Creating directory for IP {ip_address}: {ip_dir}")
        os.makedirs(ip_dir)
    
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
            print(f"[INFO] Initializing empty file: {file_path}")
            with open(file_path, 'w') as f:
                f.write('{}')
    
    return ip_dir

# Create the IP directory at startup
ip_dir = prepare_ip_directory(ip)
clean_ip = ip.replace('.', '_')

ssh = ssh_login(ip)

#get_du_file(ssh)
#get_cu_file(ssh)

def check_procmon_status():
    """
    Checks if procmon is running and returns the status.
    
    Returns:
        dict: Dictionary containing 'running' (bool), 'status_text' (str),
              'disable_charts' (bool), and 'message' (str)
    """
    global ssh
    
    # Check if SSH connection is still alive
    if ssh is None or not ssh.get_transport() or not ssh.get_transport().is_active():
        print("[ERROR] SSH connection lost. Attempting to reconnect...")
        try:
            ssh = ssh_login(ip)
            if ssh is None:
                return {'running': False, 'status_text': 'SSH Connection Failed', 'disable_charts': True, 'message': 'SSH Connection Failed. Charts are disabled.'}
        except Exception as e:
            print(f"[ERROR] Failed to reconnect: {str(e)}")
            return {'running': False, 'status_text': 'SSH Connection Failed', 'disable_charts': True, 'message': f'SSH Connection Failed: {str(e)}. Charts are disabled.'}
    
    result = bash_command(ssh, "systemctl status procmon")
    
    # Check if the command was successful
    if not result or not result[0]:
        return {'running': False, 'status_text': 'Status Check Failed', 'disable_charts': True, 'message': 'Failed to check procmon status. Charts are disabled.'}
    
    # Parse the status
    status_text = result[0]
    is_running = "Active: active (running)" in status_text
    
    status = {
        'running': is_running,
        'status_text': "PROCMON: ACTIVE" if is_running else "PROCMON: INACTIVE",
        'timestamp': time.time(),
        'disable_charts': not is_running,
        'message': "Charts enabled - Procmon is active" if is_running else "PROCMON IS DOWN - No cells are available. Charts are disabled."
    }
    
    print(f"[INFO] Procmon status: {status['status_text']}")
    return status

# Initial check
procmon_status = check_procmon_status()
print(f" {procmon_status['status_text']}")

clean_config_files(0)

lists = bash_command(ssh,"ls -rt /workspace/logs/ | grep du_stat")

du_stat=lists[0].splitlines()[-1]

print(f" {du_stat}")

cell_tpt = bash_command(ssh,f"cat /workspace/logs/{du_stat} | grep \"Cell Tpt Statistics\" -EA 9")

# print(cell_tpt[0])


def parse_cell_stats(input_string):
    """
    Parses a string containing cell statistics in a tabular format and returns a dictionary.

    Args:
      input_string: The input string containing cell statistics data.

    Returns:
      A dictionary containing extracted metrics for all cells.
    """
    all_cells = {}
    try:
        lines = input_string.splitlines()
        # Find the header line
        header_line_index = next((i for i, line in enumerate(lines) if "CELL-ID" in line), None)
        if header_line_index is None:
            print("Error: Header line not found")
            return {}

        header = lines[header_line_index].split()
        
        # Process all data rows after the header (one row per cell)
        for i in range(header_line_index + 1, len(lines)):
            if not lines[i].strip():  # Skip empty lines
                continue
                
            data = lines[i].split()
            if len(data) < 3:  # Ensure it's a valid data row
                continue
                
            # Extract cell ID from the first column
            try:
                cell_id = int(data[0])
                cell_metrics = {}
                
                # Extract values for this cell
                for j in range(len(header)):
                    if j < len(data) and header[j] != "" and data[j] != "":
                        try:
                            cell_metrics[header[j]] = int(data[j]) if data[j].isdigit() else float(data[j]) if data[j].replace('.', '', 1).isdigit() else data[j]
                        except ValueError:
                            cell_metrics[header[j]] = data[j]
                
                all_cells[cell_id] = cell_metrics
            except (ValueError, IndexError):
                continue  # Skip invalid rows
                
    except (IndexError, ValueError) as e:
        print(f"Error parsing cell statistics string: {e}")
        return {}

    return all_cells


# Update data_points initialization
data_points = []
for i in cell_tpt[0].split("---------------------------------------------------------------------------------------------"):
    result = parse_cell_stats(i)
    if result:  # Only add non-empty results
        print(result)
        data_points.append(result)

# Modify update_data function to return all cells' data
def update_data():
    """
    Updates the data by fetching new cell statistics from the server
    Returns:
        Dictionary containing the latest metrics for all cells and timestamp
    """
    global ssh
    
    # Get latest DU stats file
    lists = bash_command(ssh, "ls -rt /workspace/logs/ | grep du_stat")
    du_stat = lists[0].splitlines()[-1]
    
    # Get cell throughput statistics
    cell_tpt = bash_command(ssh, f"cat /workspace/logs/{du_stat} | grep \"Cell Tpt Statistics\" -EA 9 | tail -n 10")
    
    # Get the uptime information (UpTime : X sec)
    uptime_info = bash_command(ssh, f"cat /workspace/logs/{du_stat} | grep \"UpTime\" | tail -n 1")
    uptime_sec = None
    
    if uptime_info and uptime_info[0]:
        try:
            # Extract seconds from "UpTime : X sec"
            uptime_match = re.search(r'UpTime\s*:\s*(\d+)\s*sec', uptime_info[0])
            if uptime_match:
                uptime_sec = int(uptime_match.group(1))
                print(f"[DEBUG] Extracted DU uptime: {uptime_sec} seconds")
        except Exception as e:
            print(f"[DEBUG] Error parsing uptime: {str(e)}")
    
    # Parse the latest data
    stats_sections = cell_tpt[0].split("---------------------------------------------------------------------------------------------")
    if stats_sections:
        all_cell_stats = parse_cell_stats(stats_sections[-1])
        # Get list of available cell IDs
        cell_ids = list(all_cell_stats.keys())
        
        # Add uptime and cell_ids to the stats
        result = {
            'cells': all_cell_stats,
            'cell_ids': cell_ids,
            'uptime': uptime_sec
        }
        return result
    return {'cells': {}, 'cell_ids': [], 'uptime': None}

def update_l1_data():
    """
    Updates the data by fetching L1 log statistics from the server
    Returns:
        Dictionary containing the latest metrics
    """
    global ssh
    
    # Get latest L1 stats file
    lists = bash_command(ssh, "ls -rt /workspace/logs/ | grep l1_log_")
    if not lists[0].strip():
        print("[DEBUG] No L1 log files found")
        return {}
        
    l1_log = lists[0].splitlines()[-1]
    
    # Get the time information from L1 logs
    time_info = bash_command(ssh, f"cat /workspace/logs/{l1_log} | grep -i 'Time:' | tail -n 1")
    l1_time_str = None
    
    if time_info and time_info[0]:
        try:
            # Extract time from "==== l1app [Time:    2Hr 19Min  0Sec ]"
            time_match = re.search(r'\[Time:\s*(\d+Hr\s+\d+Min\s+\d+Sec)\s*\]', time_info[0])
            if time_match:
                l1_time_str = time_match.group(1)
                print(f"[DEBUG] Extracted L1 time: {l1_time_str}")
                
                # Convert time to seconds for chart
                hr_match = re.search(r'(\d+)Hr', l1_time_str)
                min_match = re.search(r'(\d+)Min', l1_time_str)
                sec_match = re.search(r'(\d+)Sec', l1_time_str)
                
                hours = int(hr_match.group(1)) if hr_match else 0
                minutes = int(min_match.group(1)) if min_match else 0
                seconds = int(sec_match.group(1)) if sec_match else 0
                
                total_seconds = hours * 3600 + minutes * 60 + seconds
                print(f"[DEBUG] Converted L1 time to {total_seconds} seconds")
        except Exception as e:
            print(f"[DEBUG] Error parsing L1 time info: {str(e)}")
    
    # Get L1 throughput statistics for MU 1
    print(f"[DEBUG] Fetching L1 throughput for MU 1 from {l1_log}")
    # Using the correct format for grep with single quotes
    l1_tpt = bash_command(ssh, f"cat /workspace/logs/{l1_log} | grep -i 'MU 1' | tail -n 10")
    
    if not l1_tpt[0].strip():
        print("[DEBUG] No MU 1 data found in L1 log")
        return {}
    
    # Parse the data based on the provided format
    try:
        metrics = {}
        # Example format:
        # 0 (MU 1 / 100,100, 31) |   0  |  0, 0 |  1,116,257     666,331 |     21,457 /     25,630      9.59%      15,734 |      1   2.84     12  |     0     0     0     0 |       0 Db |       3  |     102      1064  |
        
        # Get the latest line
        latest_line = l1_tpt[0].splitlines()[-1]
        print(f"[DEBUG] Parsing L1 line: {latest_line}")
        
        # Split by '|' to get different sections
        sections = latest_line.split('|')
        
        if len(sections) >= 5:
            # DL throughput is in section 3 (index 2) - first number in kbps
            dl_section = sections[3].strip().split()
            if dl_section:
                dl_value_str = dl_section[0].replace(',', '')
                try:
                    metrics["L1-DL"] = float(dl_value_str) / 1000  # Convert from kbps to Mbps
                    print(f"[DEBUG] Extracted DL: {metrics['L1-DL']} Mbps")
                except ValueError as e:
                    print(f"[DEBUG] Error parsing DL value '{dl_section[0]}': {e}")
            
            # UL throughput is in section 4 (index 3) - first number in kbps
            ul_section = sections[4].strip().split()
            if ul_section and len(ul_section) > 0:
                ul_value_str = ul_section[0].replace(',', '')
                try:
                    metrics["L1-UL"] = float(ul_value_str) / 1000  # Convert from kbps to Mbps
                    print(f"[DEBUG] Extracted UL: {metrics['L1-UL']} Mbps")
                except ValueError as e:
                    print(f"[DEBUG] Error parsing UL value '{ul_section[0]}': {e}")
                
                # BLER percentage is in section 4 (index 3) - value with % sign
                if len(ul_section) >= 3:
                    bler_value_str = ul_section[3].replace('%', '')
                    try:
                        metrics["L1-BLER"] = float(bler_value_str)
                        print(f"[DEBUG] Extracted BLER: {metrics['L1-BLER']}%")
                    except ValueError as e:
                        print(f"[DEBUG] Error parsing BLER value '{ul_section[2]}': {e}")
        
        # Add time information to the metrics
        if total_seconds is not None:
            metrics['l1_time'] = total_seconds
        if l1_time_str is not None:
            metrics['l1_time_str'] = l1_time_str
            
        return metrics
    except Exception as e:
        print(f"[DEBUG] Error parsing L1 log data: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return {}

def update_la_data(cell_id=None):
    """
    Updates the data by fetching LA Histogram Statistics from the server for a specific cell
    
    Args:
        cell_id: Cell ID to filter statistics for (optional)
    
    Returns:
        Dictionary containing the latest LA metrics
    """
    global ssh
    
    # Get latest DU stats file
    lists = bash_command(ssh, "ls -rt /workspace/logs/ | grep du_stat")
    if not lists[0].strip():
        print("[DEBUG] No DU stat files found")
        return {}
        
    du_stat = lists[0].splitlines()[-1]
    
    # Get LA Histogram Statistics - filter by cell ID if specified
    la_cmd = f"cat /workspace/logs/{du_stat} | grep \"LA Histogram Statistics\" -EA 4"
    if cell_id is not None:
        # Add cell ID filter - look for lines with the cell ID after the LA Histogram Statistics header
        la_cmd += f" | grep -A 4 \"UE-ID.*CELL-ID.*{cell_id}[^0-9]\""
    
    la_cmd += " | tail -n 5"
    la_stats = bash_command(ssh, la_cmd)
    
    # Get the uptime information (UpTime : X sec)
    uptime_info = bash_command(ssh, f"cat /workspace/logs/{du_stat} | grep \"UpTime\" | tail -n 1")
    uptime_sec = None
    
    if uptime_info and uptime_info[0]:
        try:
            # Extract seconds from "UpTime : X sec"
            uptime_match = re.search(r'UpTime\s*:\s*(\d+)\s*sec', uptime_info[0])
            if uptime_match:
                uptime_sec = int(uptime_match.group(1))
                print(f"[DEBUG] Extracted LA uptime: {uptime_sec} seconds")
        except Exception as e:
            print(f"[DEBUG] Error parsing uptime: {str(e)}")
    
    # Parse the LA statistics data
    metrics = parse_la_stats(la_stats[0])
    
    # Add uptime and cell ID to the metrics
    if uptime_sec is not None:
        metrics['uptime'] = uptime_sec
    if cell_id is not None:
        metrics['cell_id'] = cell_id
        
    return metrics

def parse_la_stats(input_string):
    """
    Parses LA Histogram Statistics data and returns a dictionary of values.
    
    Args:
        input_string: String containing LA Histogram Statistics data
        
    Returns:
        Dictionary with parsed values
    """
    metrics = {}
    try:
        lines = input_string.splitlines()
        # Find the header line (contains "UE-ID  CELL-ID ...")
        header_line_index = next((i for i, line in enumerate(lines) if "UE-ID" in line), None)
        
        if header_line_index is None or header_line_index + 1 >= len(lines):
            print("[DEBUG] Could not find valid LA Histogram Statistics data")
            return metrics
        
        # Extract the header and data rows
        header = lines[header_line_index].split()
        data = lines[header_line_index + 1].split()
        
        # Map header columns to data values
        for i in range(len(header)):
            if i < len(data):
                try:
                    # Try converting numeric values
                    value = float(data[i])
                    metrics[header[i]] = value
                except ValueError:
                    # Keep as string if not numeric
                    metrics[header[i]] = data[i]
        
        print(f"[DEBUG] Parsed LA metrics: {metrics}")
    except Exception as e:
        print(f"[DEBUG] Error parsing LA statistics: {str(e)}")
        import traceback
        print(traceback.format_exc())
    
    return metrics

def fetch_historical_data(num_samples=10, cell_id=None):
    """
    Fetches historical data points from the log files.
    
    Args:
        num_samples: Number of historical samples to fetch (default: 10)
        cell_id: Cell ID to filter data for (optional)
        
    Returns:
        Dictionary containing historical DU, L1, and LA data
    """
    global ssh
    
    print(f"[INFO] Fetching last {num_samples} historical data points{' for cell ' + str(cell_id) if cell_id else ''}...")
    
    # Initialize return structure
    history = {
        'du': {
            'time_points': [],
            'dl_values': [],
            'ul_values': [],
            'num_ue': []  # Add UE count tracking
        },
        'l1': {
            'time_points': [],
            'dl_values': [],
            'ul_values': [],
            'bler_values': []
        },
        'la': {
            'time_points': [],
            'dl_cqi_values': [],
            'dl_mcs_values': [],
            'dl_ri_values': [],
            'ul_snr_values': [],
            'ul_mcs_values': [],
            'ul_ri_values': []
        }
    }
    
    # Get latest DU stats file
    lists = bash_command(ssh, "ls -rt /workspace/logs/ | grep du_stat")
    if not lists[0].strip():
        print("[DEBUG] No DU stat files found")
        return history
        
    du_stat = lists[0].splitlines()[-1]
    
    # Fetch last N entries of cell statistics (each entry has multiple lines)
    print(f"[DEBUG] Fetching historical DU data from {du_stat}")
    
    # First, get uptime entries to establish the timeline
    uptime_entries = bash_command(ssh, f"cat /workspace/logs/{du_stat} | grep \"UpTime\" | tail -n {num_samples}")
    uptime_values = []
    
    if uptime_entries and uptime_entries[0]:
        for line in uptime_entries[0].splitlines():
            try:
                uptime_match = re.search(r'UpTime\s*:\s*(\d+)\s*sec', line)
                if uptime_match:
                    uptime_sec = int(uptime_match.group(1))
                    uptime_values.append(uptime_sec)
            except Exception as e:
                print(f"[DEBUG] Error parsing historical uptime: {str(e)}")
    print(f"[DEBUG] All values are {uptime_entries}")
    
    # Now we need to get entries with timestamp close to these uptimes
    # Get the cell throughput statistics entries that contain "Cell Tpt Statistics"
    cell_tpt_entries = bash_command(ssh, f"cat /workspace/logs/{du_stat} | grep \"Cell Tpt Statistics\" -A 9 | tail -n $(({num_samples}*15))")
    
    if cell_tpt_entries and cell_tpt_entries[0]:
        print(f"[DEBUG] Cell tpt entries obtained")
        # Process the entries to extract cell data
        entries = cell_tpt_entries[0].split("--")
        valid_entries = []
        
        # Group entries and parse valid ones
        for i in range(0, len(entries), 10):
            if i + 9 < len(entries):  # Make sure we have enough lines
                chunk = "--".join(entries[i:i+10])
                if "Cell Tpt Statistics" in chunk:
                    stats = parse_cell_stats(chunk)
                    if stats:
                        # If cell_id is specified, only include data for that cell
                        if cell_id is not None:
                            if cell_id in stats:
                                cell_stats = stats.get(cell_id, {})
                                if 'SCH-DL' in cell_stats and 'SCH-UL' in cell_stats:
                                    valid_entries.append({cell_id: cell_stats})
                        else:
                            # Default to first cell if no cell is specified
                            first_cell_id = next(iter(stats.keys()), None) if stats else None
                            if first_cell_id:
                                cell_stats = stats.get(first_cell_id, {})
                                if 'SCH-DL' in cell_stats and 'SCH-UL' in cell_stats:
                                    valid_entries.append({first_cell_id: cell_stats})
        
        print(f"[DEBUG] Found {len(valid_entries)} valid historical entries")
        
        # Match valid entries with uptime values if available
        if uptime_values and valid_entries:
            # Use the smallest of the two arrays to avoid index errors
            samples_to_use = min(len(uptime_values), len(valid_entries))
            
            for i in range(samples_to_use):
                history['du']['time_points'].append(uptime_values[i])
                
                # Get cell stats
                cell_stats = next(iter(valid_entries[i].values()))
                
                history['du']['dl_values'].append(float(cell_stats.get('SCH-DL', 0)))
                history['du']['ul_values'].append(float(cell_stats.get('SCH-UL', 0)))
                history['du']['num_ue'].append(int(cell_stats.get('NUM-UE', 0)))
                
            print(f"[DEBUG] Loaded {len(history['du']['time_points'])} historical DU data points")
    
    # Rest of the function remains mostly unchanged
    # ...existing code...
    
    # LA metric retrieval needs to be adjusted for cell ID
    # Get LA Histogram Statistics entries, filtered by cell ID if specified
    la_cmd = f"cat /workspace/logs/{du_stat} | grep \"LA Histogram Statistics\" -EA 5"
    if cell_id is not None:
        # Add cell ID filter
        la_cmd += f" | grep -A 5 \"UE-ID.*CELL-ID.*{cell_id}[^0-9]\""
        
    la_cmd += f" | tail -n $(({num_samples}*7))"
    la_entries = bash_command(ssh, la_cmd)
    
    if la_entries and la_entries[0]:
        # Split into individual statistics blocks
        la_blocks = la_entries[0].split("UE SCH: LA Histogram Statistics")
        valid_entries = []
        
        # Process each block to extract data
        for block in la_blocks:
            if block.strip():
                stats = parse_la_stats("UE SCH: LA Histogram Statistics" + block)
                if stats and 'DL-avgCQI' in stats and 'DL-avgMCS' in stats and 'DL-avgRptRI' in stats and 'UL-avgSNR' in stats:
                    valid_entries.append(stats)
        
        # Match with uptime values
        if uptime_values and valid_entries:
            # Use the smallest of the two arrays to avoid index errors
            samples_to_use = min(len(uptime_values), len(valid_entries))
            
            for i in range(samples_to_use):
                history['la']['time_points'].append(uptime_values[i])
                history['la']['dl_cqi_values'].append(float(valid_entries[i].get('DL-avgCQI', 0)))
                history['la']['dl_mcs_values'].append(float(valid_entries[i].get('DL-avgMCS', 0)))
                history['la']['dl_ri_values'].append(float(valid_entries[i].get('DL-avgRptRI', 0)))
                history['la']['ul_snr_values'].append(float(valid_entries[i].get('UL-avgSNR', 0)))
                # Try to get UL-avgMCS if available, otherwise use UL-avgCQI as a fallback
                ul_mcs = valid_entries[i].get('UL-avgMCS', valid_entries[i].get('UL-avgCQI', 0))
                history['la']['ul_mcs_values'].append(float(ul_mcs))
                history['la']['ul_ri_values'].append(float(valid_entries[i].get('UL-avgRI', valid_entries[i].get('DL-avgRI', 0))))
            
            print(f"[DEBUG] Loaded {len(history['la']['time_points'])} historical LA data points for cell {cell_id if cell_id else 'all'}")
    
    return history

def check_error_logs():
    """
    Checks DU and CU log files for ERR logs.
    
    Returns:
        dict: Dictionary containing error logs from DU and CU
    """
    global ssh, ip_dir, clean_ip
    
    # Check if SSH connection is still alive
    if ssh is None or not ssh.get_transport() or not ssh.get_transport().is_active():
        try:
            ssh = ssh_login(ip)
            if ssh is None:
                return {'du_logs': [], 'cu_logs': []}
        except Exception:
            return {'du_logs': [], 'cu_logs': []}
    
    # Find the latest DU log file that contains 'du_25'
    du_list_cmd = bash_command(ssh, "ls -rt /workspace/logs/ | grep du_25 | tail -n 1")
    
    du_logs = []
    if du_list_cmd and du_list_cmd[0]:
        du_file = du_list_cmd[0].strip()
        if du_file:
            # Get error logs from the DU file
            du_err_cmd = bash_command(ssh, f"cat /workspace/logs/{du_file} | grep -i ERR | tail -n 100")
            if du_err_cmd and du_err_cmd[0]:
                # Process the error logs
                for line in du_err_cmd[0].splitlines():
                    if line:
                        # Extract timestamp, log level, and message
                        # Sample format: [2022-04-10 12:34:56.789] [WARN] Message...
                        timestamp_match = re.search(r'\[(.*?)\]', line)
                        level_match = re.search(r'\[(ERR|WARN|ERROR|WARNING)\]', line, re.IGNORECASE)
                        
                        timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"
                        level = level_match.group(1) if level_match else "ERR"
                        
                        # Get the message part - everything after the timestamp and level
                        message = line
                        if timestamp_match:
                            message = message.replace(timestamp_match.group(0), "", 1).strip()
                        if level_match:
                            message = message.replace(level_match.group(0), "", 1).strip()
                            
                        du_logs.append({
                            'timestamp': timestamp,
                            'level': level.upper(),
                            'message': message
                        })
    
    # Find the latest CU log file that contains 'cu_25'
    cu_list_cmd = bash_command(ssh, "ls -rt /workspace/logs/ | grep cu_25 | tail -n 1")
    
    cu_logs = []
    if cu_list_cmd and cu_list_cmd[0]:
        cu_file = cu_list_cmd[0].strip()
        if cu_file:
            # Get error logs from the CU file
            cu_err_cmd = bash_command(ssh, f"cat /workspace/logs/{cu_file} | grep -i ERR | tail -n 100")
            if cu_err_cmd and cu_err_cmd[0]:
                # Process the error logs
                for line in cu_err_cmd[0].splitlines():
                    if line:
                        # Extract timestamp, log level, and message (similar to DU logs)
                        timestamp_match = re.search(r'\[(.*?)\]', line)
                        level_match = re.search(r'\[(ERR|WARN|ERROR|WARNING)\]', line, re.IGNORECASE)
                        
                        timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"
                        level = level_match.group(1) if level_match else "ERR"
                        
                        # Get the message part - everything after the timestamp and level
                        message = line
                        if timestamp_match:
                            message = message.replace(timestamp_match.group(0), "", 1).strip()
                        if level_match:
                            message = message.replace(level_match.group(0), "", 1).strip()
                            
                        cu_logs.append({
                            'timestamp': timestamp,
                            'level': level.upper(),
                            'message': message
                        })
    
    # Combine and sort all logs by timestamp (newest first)
    all_logs = du_logs + cu_logs
    all_logs.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Split back into DU and CU logs for separate filtering in UI
    du_logs = [log for log in all_logs if log in du_logs]
    cu_logs = [log for log in all_logs if log in cu_logs]
    
    result = {
        'du_logs': du_logs,
        'cu_logs': cu_logs,
        'timestamp': time.time()
    }
    
    # Save to JSON file in the IP-specific directory
    error_logs_file = os.path.join(ip_dir, f"error_logs_{clean_ip}.json")
    
    try:
        with open(error_logs_file, 'w') as f:
            json.dump(result, f)
        print(f"[INFO] Updated error logs. Found {len(du_logs)} DU errors and {len(cu_logs)} CU errors.")
    except Exception as e:
        print(f"[ERROR] Failed to save error logs to file: {e}")
    
    return result

def get_server_info():
    """
    Fetches server hardware information using lscpu and dmidecode commands
    
    Returns:
        dict: Dictionary containing system and CPU information
    """
    global ssh, ip_dir, clean_ip
    
    # Check if SSH connection is still alive
    if ssh is None or not ssh.get_transport() or not ssh.get_transport().is_active():
        try:
            ssh = ssh_login(ip)
            if ssh is None:
                return {'system_info': None, 'cpu_info': None}
        except Exception:
            return {'system_info': None, 'cpu_info': None}
    
    # Get system information using dmidecode
    system_info = {}
    try:
        dmidecode_cmd = bash_command(ssh, "dmidecode -t system")
        if dmidecode_cmd and dmidecode_cmd[0]:
            # Extract key system information
            system_output = dmidecode_cmd[0]
            
            # Parse manufacturer
            manufacturer_match = re.search(r'Manufacturer:\s+(.+)', system_output)
            if manufacturer_match:
                system_info['manufacturer'] = manufacturer_match.group(1).strip()
            
            # Parse product name
            product_match = re.search(r'Product Name:\s+(.+)', system_output)
            if product_match:
                system_info['product_name'] = product_match.group(1).strip()
            
            # Parse version
            version_match = re.search(r'Version:\s+(.+)', system_output)
            if version_match:
                system_info['version'] = version_match.group(1).strip()
            
            # Parse serial number
            serial_match = re.search(r'Serial Number:\s+(.+)', system_output)
            if serial_match:
                system_info['serial_number'] = serial_match.group(1).strip()
            
            # Parse UUID
            uuid_match = re.search(r'UUID:\s+(.+)', system_output)
            if uuid_match:
                system_info['uuid'] = uuid_match.group(1).strip()
            
            # Parse status
            status_match = re.search(r'Status:\s+(.+)', system_output)
            if status_match:
                system_info['status'] = status_match.group(1).strip()
    except Exception as e:
        print(f"[ERROR] Failed to get system information: {e}")
    
    # Get CPU information using lscpu
    cpu_info = {}
    try:
        lscpu_cmd = bash_command(ssh, "lscpu")
        if lscpu_cmd and lscpu_cmd[0]:
            # Extract key CPU information
            lscpu_output = lscpu_cmd[0]
            
            # Parse architecture
            arch_match = re.search(r'Architecture:\s+(.+)', lscpu_output)
            if arch_match:
                cpu_info['architecture'] = arch_match.group(1).strip()
            
            # Parse CPU count
            cpus_match = re.search(r'CPU\(s\):\s+(\d+)', lscpu_output)
            if cpus_match:
                cpu_info['cpus'] = cpus_match.group(1).strip()
            
            # Parse model name
            model_match = re.search(r'Model name:\s+(.+)', lscpu_output)
            if model_match:
                cpu_info['model_name'] = model_match.group(1).strip()
            
            # Parse CPU family
            family_match = re.search(r'CPU family:\s+(\d+)', lscpu_output)
            if family_match:
                cpu_info['cpu_family'] = family_match.group(1).strip()
            
            # Parse cores per socket
            cores_match = re.search(r'Core\(s\) per socket:\s+(\d+)', lscpu_output)
            if cores_match:
                cpu_info['cores_per_socket'] = cores_match.group(1).strip()
            
            # Parse threads per core
            threads_match = re.search(r'Thread\(s\) per core:\s+(\d+)', lscpu_output)
            if threads_match:
                cpu_info['threads_per_core'] = threads_match.group(1).strip()
            
            # Parse CPU MHz
            mhz_match = re.search(r'CPU MHz:\s+(.+)', lscpu_output)
            if mhz_match:
                cpu_info['cpu_mhz'] = mhz_match.group(1).strip()
            
            # Parse minimum CPU MHz
            min_mhz_match = re.search(r'CPU min MHz:\s+(.+)', lscpu_output)
            if min_mhz_match:
                cpu_info['min_mhz'] = min_mhz_match.group(1).strip()
            
            # Parse maximum CPU MHz
            max_mhz_match = re.search(r'CPU max MHz:\s+(.+)', lscpu_output)
            if max_mhz_match:
                cpu_info['max_mhz'] = max_mhz_match.group(1).strip()
            
            # Parse virtualization
            virt_match = re.search(r'Virtualization:\s+(.+)', lscpu_output)
            if virt_match:
                cpu_info['virtualization'] = virt_match.group(1).strip()
    except Exception as e:
        print(f"[ERROR] Failed to get CPU information: {e}")
    
    result = {
        'system_info': system_info,
        'cpu_info': cpu_info,
        'timestamp': time.time()
    }
    
    # Save to JSON file in the IP-specific directory
    server_info_file = os.path.join(ip_dir, f"server_info_{clean_ip}.json")
    
    try:
        with open(server_info_file, 'w') as f:
            json.dump(result, f)
        print("[INFO] Server information updated successfully")
    except Exception as e:
        print(f"[ERROR] Failed to save server info to file: {e}")
    
    return result

def get_num_ues_for_cell(cell_id=None):
    """
    Gets the current number of UEs for a specific cell
    
    Args:
        cell_id: Cell ID to check UEs for (optional)
    
    Returns:
        int: Number of UEs for the cell
    """
    global ssh
    
    # Get latest DU stats file
    lists = bash_command(ssh, "ls -rt /workspace/logs/ | grep du_stat")
    if not lists[0].strip():
        print("[DEBUG][get_num_ues_for_cell] No DU stat files found")
        return 0
        
    du_stat = lists[0].splitlines()[-1]
    
    # Get cell throughput stats to determine number of UEs
    cell_tpt = bash_command(ssh, f"cat /workspace/logs/{du_stat} | grep \"Cell Tpt Statistics\" -A 9 | tail -n 10")
    num_ue = 0
    
    if cell_tpt and cell_tpt[0]:
        # Try to extract NUM-UE from cell stats for the specific cell
        parsed_stats = parse_cell_stats(cell_tpt[0])
        if cell_id in parsed_stats:
            num_ue = int(parsed_stats[cell_id].get('NUM-UE', 0))
        else:
            # If not found, use any cell's NUM-UE
            first_cell = next(iter(parsed_stats.values()), {})
            num_ue = int(first_cell.get('NUM-UE', 0))
    
    print(f"[DEBUG][get_num_ues_for_cell] Detected {num_ue} UEs for cell {cell_id}")
    return num_ue

def get_ue_ids_for_cell(cell_id=None, num_ue=0):
    """
    Gets available UE-IDs (CRNTIs) for a specific cell from LA Histogram data
    
    Args:
        cell_id: Cell ID to filter UEs for (optional)
        num_ue: Number of UEs to account for in grep command (default: 0)
    
    Returns:
        List of UE-IDs associated with the cell
    """
    global ssh
    
    # If num_ue wasn't provided or is 0, get the latest count
    if num_ue <= 0:
        num_ue = get_num_ues_for_cell(cell_id)
    
    # Calculate total UEs across all cells from ue_count.json
    output_dir = os.path.dirname(os.path.abspath(__file__))
    ue_count_file = os.path.join(output_dir, "ue_count.json")
    total_ues = num_ue  # Default to the cell-specific count
    
    try:
        with open(ue_count_file, 'r') as f:
            ue_count_data = json.load(f)
            cell_ue_counts = ue_count_data.get('cell_ue_counts', {})
            # Sum up UEs across all cells
            if cell_ue_counts:
                total_ues = sum(int(count) for count in cell_ue_counts.values())
                print(f"[DEBUG][get_ue_ids_for_cell] Total UEs across all cells: {total_ues}")
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        print(f"[DEBUG][get_ue_ids_for_cell] Couldn't read total UE count: {e}")
        # Keep using the cell-specific count as fallback
    
    # Get latest DU stats file
    lists = bash_command(ssh, "ls -rt /workspace/logs/ | grep du_stat")
    if not lists[0].strip():
        print("[DEBUG][get_ue_ids_for_cell] No DU stat files found")
        return []
        
    du_stat = lists[0].splitlines()[-1]
    
    # Ensure we have enough lines to capture all UEs (base of 20 + number of UEs)
    # Now use the total UE count across all cells to ensure we capture everything
    num_lines = max(20, 20 + total_ues * 2)  # Double the total_ues to ensure we capture all entries
    print(f"[DEBUG][get_ue_ids_for_cell] Using num_lines={num_lines} based on total UEs={total_ues}")
    
    # Get UE Instantaneous Statistics instead of LA Histogram for more reliable UE detection
    ue_cmd = f"cat /workspace/logs/{du_stat} | grep \"UE Instantaneous Statistics\" -A {num_lines}"
    if cell_id is not None:
        # Add cell ID filter (PCELL-ID column is typically the 8th column)
        ue_cmd += f" | grep -v \"UE-ID\" | grep -E \"[0-9]+\\s+[0-9]+\\s+[0-9.]+\\s+[0-9.]+\\s+[0-9.]+\\s+[0-9.]+\\s+[0-9]+\\s+{cell_id}\\b\""
    
    ue_stats = bash_command(ssh, ue_cmd)
    
    # Extract UE-IDs from the statistics
    ue_ids = []
    
    if ue_stats and ue_stats[0]:
        lines = ue_stats[0].splitlines()
        for line in lines:
            parts = line.split()
            if len(parts) >= 8:  # Ensure we have at least 8 columns
                try:
                    # The first column should be UE-ID, 8th column is PCELL-ID
                    ue_id = int(parts[0])
                    pcell_id = int(parts[7])
                    # Only add if it matches the requested cell_id or if no cell_id filter
                    if cell_id is None or pcell_id == cell_id:
                        if ue_id not in ue_ids:
                            ue_ids.append(ue_id)
                except (ValueError, IndexError):
                    continue
    
    print(f"[DEBUG][get_ue_ids_for_cell] Found UE-IDs for cell {cell_id}: {ue_ids} (Num UEs: {num_ue})")
    return ue_ids

def get_ue_throughput(ue_id=None, cell_id=None):
    """
    Gets UE-specific throughput and metrics from UE Instantaneous Statistics
    
    Args:
        ue_id: UE-ID (CRNTI) to filter data for
        cell_id: Cell ID to filter data for (optional, for logging)
        
    Returns:
        Dictionary containing UE metrics and historical throughput data
    """
    global ssh
    
    result = {
        'found': False,
        'metrics': {},
        'historical': {
            'time_points': [],
            'dl_values': [],
            'ul_values': []
        }
    }
    
    if ue_id is None:
        print("[DEBUG][get_ue_throughput] No UE-ID provided")
        return result
        
    # Get latest DU stats file
    lists = bash_command(ssh, "ls -rt /workspace/logs/ | grep du_stat")
    if not lists[0].strip():
        print("[DEBUG][get_ue_throughput] No DU stat files found")
        return result
        
    du_stat = lists[0].splitlines()[-1]

    # Get cell throughput stats to determine number of UEs
    cell_tpt = bash_command(ssh, f"cat /workspace/logs/{du_stat} | grep \"Cell Tpt Statistics\" -A 9 | tail -n 10")
    num_ue = 0
    
    if cell_tpt and cell_tpt[0]:
        # Try to extract NUM-UE from cell stats for the specific cell
        parsed_stats = parse_cell_stats(cell_tpt[0])
        if cell_id in parsed_stats:
            num_ue = int(parsed_stats[cell_id].get('NUM-UE', 0))
        else:
            # If not found, use any cell's NUM-UE
            first_cell = next(iter(parsed_stats.values()), {})
            num_ue = int(first_cell.get('NUM-UE', 0))
    
    # Ensure we have at least 5 lines even if num_ue is small
    num_lines = max(5, 5 + num_ue)
    
    # Get UE Instantaneous Statistics
    ue_stats_cmd = f"cat /workspace/logs/{du_stat} | grep \"UE Instantaneous Statistics\" -A {num_lines} | grep -A 1 {ue_id}"
    ue_stats = bash_command(ssh, ue_stats_cmd)

    # Parse the UE statistics
    if ue_stats and ue_stats[0]:
        lines = ue_stats[0].splitlines()
        for i, line in enumerate(lines):
            if str(ue_id) in line:
                # Parse metrics from this line
                parts = line.split()
                if len(parts) >= 8:  # Ensure we have enough columns
                    try:
                        result['found'] = True
                        result['metrics'] = {
                            'UE-ID': int(parts[0]),
                            'IS_REL': int(parts[1]),
                            'DL-TPT': float(parts[2]),
                            'UL-TPT': float(parts[3]),
                            'DL-LC-1': float(parts[4]),
                            'UL-LC-1': float(parts[5]),
                            'BEAM-ID': int(parts[6]),
                            'PCELL-ID': int(parts[7])
                        }
                        
                        # Add additional metrics if they exist
                        if len(parts) >= 9:
                            result['metrics']['NSI-ID'] = int(parts[8])
                        if len(parts) >= 10:
                            result['metrics']['DL-PKT-RX'] = int(parts[9])
                        if len(parts) >= 11:
                            result['metrics']['DL-PKT-DRP'] = int(parts[10])
                        if len(parts) >= 12:
                            result['metrics']['UL-PKT-TX'] = int(parts[11])
                            
                        # Add all additional metrics available
                        for j in range(12, min(19, len(parts))):
                            # Map index to metric names
                            metric_names = ['DL-LC-2', 'DL-LC-3', 'DL-LC-4', 'UL-LC-2', 'UL-LC-3', 'UL-LC-4', 'DL']
                            metric_idx = j - 12
                            if metric_idx < len(metric_names):
                                try:
                                    result['metrics'][metric_names[metric_idx]] = float(parts[j])
                                except ValueError:
                                    result['metrics'][metric_names[metric_idx]] = parts[j]
                    except (ValueError, IndexError) as e:
                        print(f"[DEBUG][get_ue_throughput] Error parsing UE metrics: {e}")
                        continue

    # Get historical data for this UE
    # We'll use the last 10 occurrences of this UE's stats
    history_cmd = f"cat /workspace/logs/{du_stat} | grep \"UE Instantaneous Statistics\" -A {num_lines} | grep {ue_id} | tail -n 10"
    history = bash_command(ssh, history_cmd)
    
    # Get uptime entries to establish the timeline
    uptime_entries = bash_command(ssh, f"cat /workspace/logs/{du_stat} | grep \"UpTime\" | tail -n 10")
    uptime_values = []
    
    if uptime_entries and uptime_entries[0]:
        for line in uptime_entries[0].splitlines():
            try:
                uptime_match = re.search(r'UpTime\s*:\s*(\d+)\s*sec', line)
                if uptime_match:
                    uptime_sec = int(uptime_match.group(1))
                    uptime_values.append(uptime_sec)
            except Exception as e:
                print(f"[DEBUG][get_ue_throughput] Error parsing historical uptime: {str(e)}")

    # Parse historical throughput data
    if history and history[0]:
        lines = history[0].splitlines()
        dl_values = []
        ul_values = []
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:  # Ensure we have enough columns
                try:
                    dl_tpt = float(parts[2])
                    ul_tpt = float(parts[3])
                    dl_values.append(dl_tpt)
                    ul_values.append(ul_tpt)
                except (ValueError, IndexError):
                    continue

        # Match with uptime values if available
        if uptime_values and dl_values:
            # Use the smallest of the two arrays to avoid index errors
            samples_to_use = min(len(uptime_values), len(dl_values))
            
            for i in range(samples_to_use):
                result['historical']['time_points'].append(uptime_values[i])
                result['historical']['dl_values'].append(dl_values[i])
                result['historical']['ul_values'].append(ul_values[i])
        else:
            # Use sequential numbers for time points if no uptime available
            for i in range(len(dl_values)):
                result['historical']['time_points'].append(i)
                result['historical']['dl_values'].append(dl_values[i])
                result['historical']['ul_values'].append(ul_values[i])
    
    return result

def create_chart():
    """
    Creates and displays a Plotly chart for real-time monitoring
    """
    # Initialize data for both charts
    global time_points, dl_values, ul_values, ip_dir, clean_ip
    
    # Setup procmon status monitoring file path in IP-specific directory
    procmon_status_file = os.path.join(ip_dir, f"procmon_status_{clean_ip}.json")
    
    # Store initial status
    with open(procmon_status_file, 'w') as f:
        json.dump(procmon_status, f)
        
    # Create a default cell_selection.json file to avoid the FileNotFoundError
    cell_selection_file = os.path.join(ip_dir, f"cell_selection_{clean_ip}.json")
    
    # Initialize an empty ue_info.json file at startup
    ue_info_file = os.path.join(ip_dir, f"ue_info_{clean_ip}.json")
    with open(ue_info_file, 'w') as f:
        json.dump({
            'available_ues': [],
            'default_ue': None,
            'ue_metrics': {},
            'cell_id': None,
            'no_ues_message': "Initializing UE information...",
            'timestamp': time.time()
        }, f)
    print("[INFO] Initialized empty UE information file at startup")
    
    # Fetch available cells and their data first
    cell_data = update_data()
    available_cells = cell_data.get('cell_ids', [])
    
    # Ensure available_cells is always a list, even if cell_ids is empty or missing
    if not available_cells:
        print("[WARN] No cells detected in the system. Using default cell ID 1")
        available_cells = [1]
    
    print(f"[INFO] Detected {len(available_cells)} cells in the system: {available_cells}")
    
    # Use cell_id=1 as default if available
    default_cell_id = 1 if 1 in available_cells else (available_cells[0] if available_cells else 1)
    
    # Write cell IDs to a JSON file for the web UI in the IP-specific directory
    cell_info_file = os.path.join(ip_dir, f"cell_info_{clean_ip}.json")
    
    with open(cell_info_file, 'w') as f:
        json.dump({
            'available_cells': available_cells,
            'default_cell': default_cell_id,
            'timestamp': time.time()
        }, f)
    
    # Create default ue selection file in the IP-specific directory
    ue_selection_file = os.path.join(ip_dir, f"ue_selection_{clean_ip}.json")
    with open(ue_selection_file, 'w') as f:
        json.dump({
            'selected_ue': None,
            'timestamp': time.time()
        }, f)
    
    print(f"[INFO] Created default UE selection file: {ue_selection_file}")
    
    print(f"[INFO] Written cell information to {cell_info_file}")
    print(f"[INFO] Created default cell selection file: {cell_selection_file}")
    
    # Set up periodic procmon status checking
    def monitor_procmon_status():
        while True:
            try:
                # Check procmon status
                status = check_procmon_status()
                
                # Write status to a file for web page to access in the IP-specific directory
                with open(procmon_status_file, 'w') as f:
                    json.dump(status, f)
                
                print(f"[INFO] Updated procmon status: {status['status_text']}")
                
                # Wait 5 seconds before next check
                time.sleep(5)
                
            except Exception as e:
                print(f"[ERROR] Error in procmon monitoring: {str(e)}")
                time.sleep(5)  # Wait before retry
    
    # Set up periodic error log checking
    def monitor_error_logs():
        while True:
            try:
                # Check for errors in DU and CU logs
                check_error_logs()
                
                # Wait 5 minutes (300 seconds) before next check
                time.sleep(300)
                
            except Exception as e:
                print(f"[ERROR] Error checking error logs: {str(e)}")
                time.sleep(300)  # Wait before retry
    
    # Set up periodic server info checking
    def monitor_server_info():
        while True:
            try:
                # Get server hardware information
                get_server_info()
                
                # Wait 30 minutes before next check
                # (Server information doesn't change frequently)
                time.sleep(1800)
                
            except Exception as e:
                print(f"[ERROR] Error checking server info: {str(e)}")
                time.sleep(1800)  # Wait before retry
    
    # Start procmon monitoring thread
    procmon_thread = threading.Thread(target=monitor_procmon_status)
    procmon_thread.daemon = True
    procmon_thread.start()
    
    # Start error log monitoring thread
    error_logs_thread = threading.Thread(target=monitor_error_logs)
    error_logs_thread.daemon = True
    error_logs_thread.start()
    
    # Start server info monitoring thread
    server_info_thread = threading.Thread(target=monitor_server_info)
    server_info_thread.daemon = True
    server_info_thread.start()
    
    # Fetch available cells and their data first
    cell_data = update_data()
    available_cells = cell_data.get('cell_ids', [])
    
    print(f"[INFO] Detected {len(available_cells)} cells in the system: {available_cells}")
    
    # Use cell_id=1 as default if available
    default_cell_id = 1 if 1 in available_cells else (available_cells[0] if available_cells else None)
    
    # Write cell IDs to a JSON file for the web UI in the IP-specific directory
    with open(cell_info_file, 'w') as f:
        json.dump({
            'available_cells': available_cells,
            'default_cell': default_cell_id,
            'timestamp': time.time()
        }, f)
    
    print(f"[INFO] Written cell information to {cell_info_file}")
    
    # Fetch historical data for the default cell
    historical_data = fetch_historical_data(num_samples=10, cell_id=default_cell_id)
    
    # Initialize with historical data
    time_points = historical_data['du']['time_points']
    dl_values = historical_data['du']['dl_values']
    ul_values = historical_data['du']['ul_values']
    num_ue_values = historical_data['du']['num_ue']
    
    # Add debug prints for DU stats and uptime values
    print("\n[INFO] ---------- Initial DU Stats and Uptime Values ----------")
    print(f"[INFO] Number of time points: {len(time_points)}")
    print(f"[INFO] Time points (seconds): {time_points}")
    print(f"[INFO] Downlink values (Mbps): {dl_values}")
    print(f"[INFO] Uplink values (Mbps): {ul_values}")
    print(f"[INFO] Connected UEs: {num_ue_values}")
    
    if len(time_points) > 0:
        print(f"[INFO] Latest uptime: {time_points[-1]} seconds")
        print(f"[INFO] Latest DL value: {dl_values[-1]} Mbps")
        print(f"[INFO] Latest UL value: {ul_values[-1]} Mbps")
        print(f"[INFO] Latest connected UEs: {num_ue_values[-1]}")
    else:
        print("[WARN] No initial DU stats data available")
    print("[INFO] --------------------------------------------------------\n")
    
    l1_time_points = historical_data['l1']['time_points']
    l1_dl_values = historical_data['l1']['dl_values']
    l1_ul_values = historical_data['l1']['ul_values']
    l1_bler_values = historical_data['l1']['bler_values']
    
    # Add debug prints for L1 stats
    print("[INFO] ---------- Initial L1 Stats Values ----------")
    print(f"[INFO] Number of L1 time points: {len(l1_time_points)}")
    
    if len(l1_time_points) > 0:
        print(f"[INFO] Latest L1 time: {l1_time_points[-1]} seconds")
        print(f"[INFO] Latest L1 DL value: {l1_dl_values[-1]} Mbps")
        print(f"[INFO] Latest L1 UL value: {l1_ul_values[-1]} Mbps")
        print(f"[INFO] Latest L1 BLER value: {l1_bler_values[-1]}%")
    else:
        print("[WARN] No initial L1 stats data available")
    print("[INFO] -------------------------------------------\n")
    
    # Initialize LA data
    la_time_points = historical_data['la']['time_points']
    la_dl_cqi_values = historical_data['la']['dl_cqi_values']
    la_dl_mcs_values = historical_data['la']['dl_mcs_values']
    la_dl_ri_values = historical_data['la']['dl_ri_values']
    la_ul_snr_values = historical_data['la']['ul_snr_values']
    la_ul_mcs_values = historical_data['la']['ul_mcs_values']
    la_ul_ri_values = historical_data['la']['ul_ri_values']
    
    # Add debug prints for LA stats
    print("[INFO] ---------- Initial LA Stats Values ----------")
    print(f"[INFO] Number of LA time points: {len(la_time_points)}")
    
    if len(la_time_points) > 0:
        print(f"[INFO] Latest LA time: {la_time_points[-1]} seconds")
        print(f"[INFO] Latest DL CQI value: {la_dl_cqi_values[-1]}")
        print(f"[INFO] Latest DL MCS value: {la_dl_mcs_values[-1]}")
        print(f"[INFO] Latest DL RI value: {la_dl_ri_values[-1]}")
        print(f"[INFO] Latest UL SNR value: {la_ul_snr_values[-1]} dB")
        print(f"[INFO] Latest UL MCS value: {la_ul_mcs_values[-1]}")
        print(f"[INFO] Latest UL RI value: {la_ul_ri_values[-1]}")
    else:
        print("[WARN] No initial LA stats data available")
    print("[INFO] -------------------------------------------\n")
    
    # Create figure with 3 subplots for L1 (DL, UL, BLER)
    l1_fig = make_subplots(rows=3, cols=1, 
                       subplot_titles=('L1 Downlink Throughput (MU 1)', 'L1 Uplink Throughput (MU 1)', 'L1 BLER (MU 1)'),
                       shared_xaxes=True,
                       vertical_spacing=0.1)  # Add more spacing between subplots
    
    # Add traces for L1 DL, UL, and BLER with historical data
    l1_fig.add_trace(go.Scatter(x=l1_time_points, y=l1_dl_values, mode='lines+markers', 
                           name='L1-DL', line=dict(color='red')), 
                row=1, col=1)
    
    l1_fig.add_trace(go.Scatter(x=l1_time_points, y=l1_ul_values, mode='lines+markers', 
                           name='L1-UL', line=dict(color='orange')), 
                row=2, col=1)
                
    l1_fig.add_trace(go.Scatter(x=l1_time_points, y=l1_bler_values, mode='lines+markers', 
                           name='BLER', line=dict(color='purple')), 
                row=3, col=1)
    
    # Update layout for L1 figure with 3 charts
    l1_fig.update_layout(
        title_text="L1 Throughput Monitoring (MU 1)",
        height=900,  # Make it taller to accommodate 3 charts
        width=1000,
        showlegend=True
    )
    
    l1_fig.update_xaxes(title_text="Time (seconds)", row=1, col=1)
    l1_fig.update_xaxes(title_text="Time (seconds)", row=2, col=1)
    l1_fig.update_xaxes(title_text="Time (seconds)", row=3, col=1)
    l1_fig.update_yaxes(title_text="Downlink Throughput (Mbps)", row=1, col=1)
    l1_fig.update_yaxes(title_text="Uplink Throughput (Mbps)", row=2, col=1)
    l1_fig.update_yaxes(title_text="BLER (%)", row=3, col=1)
    
    # Generate a filename without timestamp to avoid browser caching issues
    chart_filename = f"cell_throughput_chart_{clean_ip}.html"
    chart_path = os.path.join(ip_dir, chart_filename)
    
    # Check if the chart file already exists
    chart_exists = os.path.isfile(chart_path)
    du_data_filename = f"du_chart_data_{clean_ip}.json"
    l1_data_filename = f"l1_chart_data_{clean_ip}.json"
    la_data_filename = f"la_chart_data_{clean_ip}.json"
    du_data_file_path = os.path.join(ip_dir, du_data_filename)
    l1_data_file_path = os.path.join(ip_dir, l1_data_filename)
    la_data_file_path = os.path.join(ip_dir, la_data_filename)
    
    # Path to our template HTML file
    template_html_path = os.path.join(output_dir, "ODU_CHARTS.html")
    
    # Read the template HTML file
    try:
        with open(template_html_path, 'r') as template_file:
            html_template = template_file.read()
    except FileNotFoundError:
        print(f"[ERROR] Template file not found at {template_html_path}")
        print("Please ensure ODU_CHARTS.html exists in the same directory as this script")
        return
    
    # Convert chart data to JSON for embedding in HTML
    l1_chart_json = l1_fig.to_json()
    
    # Replace placeholders in HTML template with our chart data
    html_content = html_template.replace("{{L1_CHART_JSON}}", l1_chart_json.replace("</script>", "<\\/script>"))
    
    # Replace {{CLEAN_IP}} placeholder with the actual clean IP
    html_content = html_content.replace("{{CLEAN_IP}}", clean_ip)
    
    # Only write the HTML file if it doesn't exist yet
    if not chart_exists:
        with open(chart_path, 'w') as f:
            f.write(html_content)
        print(f"[INFO] Generated chart HTML at {chart_path}")
    else:
        print(f"[INFO] Using existing chart HTML at {chart_path}")
    
    # Start an HTTP server to serve files and avoid CORS issues
    PORT = 8000
    
    print(f"[DEBUG] Starting HTTP server on port {PORT}")
    
    # Custom HTTP request handler to allow CORS and handle POST requests
    class CORSHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
        def end_headers(self):
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
            return super(CORSHTTPRequestHandler, self).end_headers()
        
        def do_OPTIONS(self):
            """Handle OPTIONS requests for CORS preflight"""
            self.send_response(200)
            self.end_headers()
            
        def do_POST(self):
            """Handle POST requests to update JSON files"""
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                # Check which file is being updated and update in the IP-specific directory
                if self.path == f"/ue_selection_{clean_ip}.json":
                    with open(os.path.join(ip_dir, f"ue_selection_{clean_ip}.json"), 'wb') as f:
                        f.write(post_data)
                    print(f"[INFO] Updated ue_selection_{clean_ip}.json via POST")
                    
                elif self.path == f"/cell_selection_{clean_ip}.json":
                    with open(os.path.join(ip_dir, f"cell_selection_{clean_ip}.json"), 'wb') as f:
                        f.write(post_data)
                    print(f"[INFO] Updated cell_selection_{clean_ip}.json via POST")
                
                # Send success response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success"}).encode())
                
            except Exception as e:
                print(f"[ERROR] Error processing POST request: {str(e)}")
                # Send error response
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode())
        
        def log_message(self, format, *args):
            # Safely format the log message regardless of number of arguments
            try:
                msg = format % args if args else format
                print(f"[HTTP Server] {msg}")
            except Exception as e:
                print(f"[HTTP Server] Error logging message: {e}")
                print(f"[HTTP Server] Format: {format}, Args: {args}")
    
    # Start the HTTP server in a separate thread
    def start_http_server():
        os.chdir(output_dir)  # Change to the directory with our files
        with socketserver.TCPServer(("", PORT), CORSHTTPRequestHandler) as httpd:
            print(f"HTTP Server started at http://localhost:{PORT}")
            httpd.serve_forever()
    
    # Start HTTP server thread
    http_server_thread = threading.Thread(target=start_http_server)
    http_server_thread.daemon = True
    http_server_thread.start()
    
    # Give the server a moment to start
    time.sleep(1)
    
    # Open the chart in a web browser using HTTP instead of file protocol
    webbrowser.open(f'http://localhost:{PORT}/{clean_ip}/{chart_filename}')
    
    # The update process needs to run in separate threads for both data types
    def update_du_chart():
        global time_points, dl_values, ul_values, ip_dir, clean_ip
        last_dl_value = None
        last_ul_value = None
        last_time_point = None
        last_cell_id = None
        last_num_ue = None
        
        # Don't initialize empty lists if we already have historical data
        if not time_points:
            time_points = []
            dl_values = []
            ul_values = []
            num_ue_values = []
        
        while True:
            try:
                # Get the currently selected cell ID from the cell_selection.json file
                try:
                    with open(os.path.join(ip_dir, f"cell_selection_{clean_ip}.json"), 'r') as f:
                        cell_selection = json.load(f)
                        current_cell_id = cell_selection.get('selected_cell')
                except (FileNotFoundError, json.JSONDecodeError):
                    # Use default if file doesn't exist or is invalid
                    current_cell_id = default_cell_id
                    # Recreate the file with default values
                    with open(os.path.join(ip_dir, f"cell_selection_{clean_ip}.json"), 'w') as f:
                        json.dump({
                            'selected_cell': default_cell_id,
                            'timestamp': time.time()
                        }, f)
                        print(f"[INFO] Recreated missing cell_selection_{clean_ip}.json with default cell {default_cell_id}")
                
                # Check if cell ID changed
                cell_id_changed = last_cell_id != current_cell_id
                if cell_id_changed:
                    print(f"[DEBUG] Cell selection changed to cell {current_cell_id}")
                    # Reset data when cell changes
                    time_points = []
                    dl_values = []
                    ul_values = []
                    num_ue_values = []
                    last_cell_id = current_cell_id
                
                # Get new data for DU stats
                print(f"[DEBUG] Fetching new DU data from server for cell {current_cell_id}...")
                new_data = update_data()
                print(f"[DEBUG] Received DU data: {new_data}")
                
                if new_data and 'cells' in new_data and 'uptime' in new_data:
                    # Get stats for selected cell
                    cell_stats = new_data['cells'].get(current_cell_id, {})
                    
                    if cell_stats and 'SCH-DL' in cell_stats and 'SCH-UL' in cell_stats:
                        # Use the actual uptime from the logs
                        current_time = new_data['uptime']  # in seconds
                        dl_value = float(cell_stats.get('SCH-DL', 0))
                        ul_value = float(cell_stats.get('SCH-UL', 0))
                        num_ue = int(cell_stats.get('NUM-UE', 0))
                        
                        # Only append if the data has changed or it's the first data point
                        if (last_dl_value != dl_value or last_ul_value != ul_value or 
                            last_time_point != current_time or last_num_ue != num_ue or 
                            not time_points or cell_id_changed):
                            time_points.append(current_time)
                            dl_values.append(dl_value)
                            ul_values.append(ul_value)
                            num_ue_values.append(num_ue)
                            
                            # Update last values
                            last_dl_value = dl_value
                            last_ul_value = ul_value
                            last_time_point = current_time
                            last_num_ue = num_ue
                            
                            print(f"[DEBUG] New DU data point added for cell {current_cell_id}: Time: {current_time}s, DL: {dl_value}, UL: {ul_value}, UEs: {num_ue}")
                        else:
                            print(f"[DEBUG] DU values unchanged, not adding new point")
                        
                        # Keep only last 30 data points
                        if len(time_points) > 30:
                            time_points.pop(0)
                            dl_values.pop(0)
                            ul_values.pop(0)
                            num_ue_values.pop(0)
                        
                        # Save the data to a JSON file for the web page to fetch
                        chart_data = {
                            'time_points': time_points,
                            'dl_values': dl_values,
                            'ul_values': ul_values,
                            'num_ue_values': num_ue_values,
                            'cell_id': current_cell_id,
                            'timestamp': time.time(),
                            'current_time': current_time  # Include the current timestamp for display
                        }
                        
                        print(f"[DEBUG] Writing DU data for cell {current_cell_id} to {du_data_file_path}")
                        
                        with open(du_data_file_path, 'w') as f:
                            json.dump(chart_data, f)
                        
                        print(f"[DEBUG] DU file write complete")
                        print(f"Updated DU chart data for cell {current_cell_id} - DL: {dl_value}, UL: {ul_value}, UEs: {num_ue}, UpTime: {current_time}")
                    else:
                        print(f"[DEBUG] No data available for cell {current_cell_id}")
                else:
                    if 'uptime' not in new_data:
                        print(f"[DEBUG] Missing uptime information in response")
                    else:
                        print(f"[DEBUG] Missing required DU data fields in response: {new_data}")
                
                # Wait before next update
                time.sleep(3)
                
            except Exception as e:
                print(f"[DEBUG] Error in update_du_chart: {str(e)}")
                import traceback
                print(traceback.format_exc())
                time.sleep(5)  # Wait a bit longer if there was an error
    
    def update_l1_chart():
        # Use existing historical data if available
        l1_time_points = historical_data['l1']['time_points'] if 'historical_data' in globals() else []
        l1_dl_values = historical_data['l1']['dl_values'] if 'historical_data' in globals() else []
        l1_ul_values = historical_data['l1']['ul_values'] if 'historical_data' in globals() else []
        l1_bler_values = historical_data['l1']['bler_values'] if 'historical_data' in globals() else []
        
        last_dl_value = l1_dl_values[-1] if l1_dl_values else None
        last_ul_value = l1_ul_values[-1] if l1_ul_values else None
        last_bler_value = l1_bler_values[-1] if l1_bler_values else None
        last_time_point = l1_time_points[-1] if l1_time_points else None
        
        while True:
            try:
                # Get new data for L1 stats
                print("[DEBUG] Fetching new L1 data from server...")
                new_data = update_l1_data()
                print(f"[DEBUG] Received L1 data: {new_data}")
                
                if new_data and 'L1-DL' in new_data and 'L1-UL' in new_data:
                    # Use the actual time from the logs if available, otherwise use elapsed time
                    if 'l1_time' in new_data:
                        current_time = new_data['l1_time']  # in seconds
                    else:
                        current_time = time.time() - start_time
                    
                    dl_value = float(new_data.get('L1-DL', 0))
                    ul_value = float(new_data.get('L1-UL', 0))
                    bler_value = float(new_data.get('L1-BLER', 0))  # Get BLER value
                    
                    # Only append if the data has changed or it's the first data point
                    if (last_dl_value != dl_value or last_ul_value != ul_value or 
                        last_bler_value != bler_value or last_time_point != current_time or not l1_time_points):
                        l1_time_points.append(current_time)
                        l1_dl_values.append(dl_value)
                        l1_ul_values.append(ul_value)
                        l1_bler_values.append(bler_value)
                        
                        # Update last values
                        last_dl_value = dl_value
                        last_ul_value = ul_value
                        last_bler_value = bler_value
                        last_time_point = current_time
                        
                        print(f"[DEBUG] New L1 data point added: Time: {current_time}s, DL: {dl_value}, UL: {ul_value}, BLER: {bler_value}")
                    else:
                        print(f"[DEBUG] L1 values unchanged, not adding new point")
                    
                    # Keep only last 30 data points
                    if len(l1_time_points) > 30:
                        l1_time_points.pop(0)
                        l1_dl_values.pop(0)
                        l1_ul_values.pop(0)
                        l1_bler_values.pop(0)
                    
                    # Save the data to a JSON file for the web page to fetch in the IP-specific directory
                    import json
                    chart_data = {
                        'time_points': l1_time_points,
                        'dl_values': l1_dl_values,
                        'ul_values': l1_ul_values,
                        'bler_values': l1_bler_values,
                        'timestamp': time.time(),
                        'current_time': current_time,  # Include the current timestamp for display
                        'current_time_str': new_data.get('l1_time_str', f"{int(current_time // 3600)}Hr {int((current_time % 3600) // 60)}Min {int(current_time % 60)}Sec")
                    }
                    
                    print(f"[DEBUG] Writing L1 data to {l1_data_file_path}")
                    print(f"[DEBUG] L1 data content: Time points: {len(l1_time_points)}, DL: {l1_dl_values[-1]}, UL: {l1_ul_values[-1]}, BLER: {l1_bler_values[-1]}")
                    
                    with open(l1_data_file_path, 'w') as f:
                        json.dump(chart_data, f)
                    
                    print(f"[DEBUG] L1 file write complete")
                    print(f"Updated L1 chart data - DL: {dl_value}, UL: {ul_value}, BLER: {bler_value}, Time: {new_data.get('l1_time_str', 'N/A')}")
                else:
                    print(f"[DEBUG] Missing required L1 data fields in response: {new_data}")
                    
                    # If we don't yet have L1 data, create an empty file to avoid fetch errors
                    if not l1_time_points:
                        import json
                        with open(l1_data_file_path, 'w') as f:
                            json.dump({
                                'time_points': [],
                                'dl_values': [],
                                'ul_values': [],
                                'bler_values': [],
                                'timestamp': time.time(),
                                'current_time_str': "0Hr 0Min 0Sec"
                            }, f)
                
                # Wait before next update
                time.sleep(3)
                
            except Exception as e:
                print(f"[DEBUG] Error in update_l1_chart: {str(e)}")
                import traceback
                print(traceback.format_exc())
                time.sleep(5)  # Wait a bit longer if there was an error
    
    def update_la_chart():
        # Explicitly import json at the beginning of the function
        # to avoid UnboundLocalError
        import json
        
        # Track last values to avoid duplicates
        last_time_point = None
        last_values = {
            'dl_cqi': None,
            'dl_mcs': None,
            'dl_ri': None,
            'ul_snr': None,
            'ul_mcs': None,
            'ul_ri': None
        }
        last_cell_id = None
        
        la_time_points = []
        la_dl_cqi_values = []
        la_dl_mcs_values = []
        la_dl_ri_values = []
        la_ul_snr_values = []
        la_ul_mcs_values = []
        la_ul_ri_values = []
        
        while True:
            try:
                # Get the currently selected cell ID from the cell_selection.json file in the IP-specific directory
                try:
                    with open(os.path.join(ip_dir, f"cell_selection_{clean_ip}.json"), 'r') as f:
                        cell_selection = json.load(f)
                        current_cell_id = cell_selection.get('selected_cell')
                except (FileNotFoundError, json.JSONDecodeError):
                    # Use default if file doesn't exist or is invalid
                    current_cell_id = default_cell_id
                    # Recreate the file with default values
                    with open(os.path.join(ip_dir, f"cell_selection_{clean_ip}.json"), 'w') as f:
                        json.dump({
                            'selected_cell': default_cell_id,
                            'timestamp': time.time()
                        }, f)
                        print(f"[INFO] Recreated missing cell_selection_{clean_ip}.json with default cell {default_cell_id}")
                
                # Check if cell ID changed
                cell_id_changed = last_cell_id != current_cell_id
                if cell_id_changed:
                    print(f"[DEBUG] LA chart: Cell selection changed to cell {current_cell_id}")
                    # Reset data when cell changes
                    la_time_points = []
                    la_dl_cqi_values = []
                    la_dl_mcs_values = []
                    la_dl_ri_values = []
                    la_ul_snr_values = []
                    la_ul_mcs_values = []
                    la_ul_ri_values = []
                    last_cell_id = current_cell_id
                
                # Get new data for LA stats for the selected cell
                print(f"[DEBUG] Fetching new LA data from server for cell {current_cell_id}...")
                new_data = update_la_data(cell_id=current_cell_id)
                print(f"[DEBUG] Received LA data: {new_data}")
                
                if new_data and 'DL-avgCQI' in new_data and 'DL-avgMCS' in new_data and 'UL-avgSNR' in new_data and 'uptime' in new_data:
                    current_time = new_data['uptime']
                    dl_cqi = float(new_data.get('DL-avgCQI', 0))
                    dl_mcs = float(new_data.get('DL-avgMCS', 0))
                    dl_ri = float(new_data.get('DL-avgRptRI', new_data.get('DL-avgRI', 0)))
                    ul_snr = float(new_data.get('UL-avgSNR', 0))
                    ul_mcs = float(new_data.get('UL-avgMCS', new_data.get('UL-avgCQI', 0)))
                    ul_ri = float(new_data.get('UL-avgRI', new_data.get('DL-avgRI', 0)))
                    
                    # Check if values have changed
                    values_changed = (
                        last_time_point != current_time or
                        last_values['dl_cqi'] != dl_cqi or
                        last_values['dl_mcs'] != dl_mcs or
                        last_values['dl_ri'] != dl_ri or
                        last_values['ul_snr'] != ul_snr or
                        last_values['ul_mcs'] != ul_mcs or
                        last_values['ul_ri'] != ul_ri or
                        not la_time_points  # First data point
                    )
                    
                    if values_changed:
                        la_time_points.append(current_time)
                        la_dl_cqi_values.append(dl_cqi)
                        la_dl_mcs_values.append(dl_mcs)
                        la_dl_ri_values.append(dl_ri)
                        la_ul_snr_values.append(ul_snr)
                        la_ul_mcs_values.append(ul_mcs)
                        la_ul_ri_values.append(ul_ri)
                        
                        # Update last values
                        last_time_point = current_time
                        last_values = {
                            'dl_cqi': dl_cqi,
                            'dl_mcs': dl_mcs,
                            'dl_ri': dl_ri,
                            'ul_snr': ul_snr,
                            'ul_mcs': ul_mcs,
                            'ul_ri': ul_ri
                        }
                        
                        print(f"[DEBUG] New LA data point added: Time: {current_time}s, DL CQI: {dl_cqi}, DL MCS: {dl_mcs}, UL SNR: {ul_snr}")
                    else:
                        print(f"[DEBUG] LA values unchanged, not adding new point")
                    
                    # Keep only last 30 data points
                    if len(la_time_points) > 30:
                        la_time_points.pop(0)
                        la_dl_cqi_values.pop(0)
                        la_dl_mcs_values.pop(0)
                        la_dl_ri_values.pop(0)
                        la_ul_snr_values.pop(0)
                        la_ul_mcs_values.pop(0)
                        la_ul_ri_values.pop(0)
                    
                    # Save the data to a JSON file for the web page to fetch
                    import json
                    chart_data = {
                        'time_points': la_time_points,
                        'dl_cqi_values': la_dl_cqi_values,
                        'dl_mcs_values': la_dl_mcs_values,
                        'dl_ri_values': la_dl_ri_values,
                        'ul_snr_values': la_ul_snr_values,
                        'ul_mcs_values': la_ul_mcs_values,
                        'ul_ri_values': la_ul_ri_values,
                        'cell_id': current_cell_id,  # Add cell_id to the data
                        'timestamp': time.time(),
                        'current_time': current_time
                    }
                    
                    print(f"[DEBUG] Writing LA data to {la_data_file_path}")
                    
                    with open(la_data_file_path, 'w') as f:
                        json.dump(chart_data, f)
                    
                    print(f"[DEBUG] LA file write complete")
                    print(f"Updated LA chart data - DL CQI: {dl_cqi}, DL MCS: {dl_mcs}, DL RI: {dl_ri}, UL SNR: {ul_snr}, UL MCS: {ul_mcs}, UL RI: {ul_ri}")
                else:
                    print(f"[DEBUG] Missing required LA data fields in response: {new_data}")
                    
                    # If we don't yet have LA data, create an empty file to avoid fetch errors
                    if not la_time_points:
                        import json
                        with open(la_data_file_path, 'w') as f:
                            json.dump({
                                'time_points': [],
                                'dl_cqi_values': [],
                                'dl_mcs_values': [],
                                'dl_ri_values': [],
                                'ul_snr_values': [],
                                'ul_mcs_values': [],
                                'ul_ri_values': [],
                                'timestamp': time.time(),
                                'current_time': 0
                            }, f)
                
                # Wait before next update
                time.sleep(3)
                
            except Exception as e:
                print(f"[DEBUG] Error in update_la_chart: {str(e)}")
                import traceback
                print(traceback.format_exc())
                time.sleep(5)  # Wait a bit longer if there was an error
    
    def update_ue_chart():
        """
        Updates the UE-specific chart data
        """
        ue_data_filename = f"ue_chart_data_{clean_ip}.json"
        ue_data_file_path = os.path.join(ip_dir, ue_data_filename)
        last_ue_id = None
        last_cell_id = None
        
        # Initialize empty data structure
        ue_time_points = []
        ue_dl_values = []
        ue_ul_values = []
        ue_metrics = {}
        
        while True:
            try:
                # Get the currently selected cell and UE from the IP-specific files
                try:
                    with open(os.path.join(ip_dir, f"cell_selection_{clean_ip}.json"), 'r') as f:
                        cell_selection = json.load(f)
                        current_cell_id = cell_selection.get('selected_cell')
                except (FileNotFoundError, json.JSONDecodeError):
                    current_cell_id = default_cell_id
                
                try:
                    with open(os.path.join(ip_dir, f"ue_selection_{clean_ip}.json"), 'r') as f:
                        ue_selection = json.load(f)
                        current_ue_id = ue_selection.get('selected_ue')
                except (FileNotFoundError, json.JSONDecodeError):
                    current_ue_id = None
                
                # Check if cell or UE selection changed
                selection_changed = (last_ue_id != current_ue_id or last_cell_id != current_cell_id)
                
                if selection_changed:
                    print(f"[DEBUG][update_ue_chart] UE/Cell selection changed: UE={current_ue_id}, Cell={current_cell_id}")
                    # Reset data when selection changes
                    ue_time_points = []
                    ue_dl_values = []
                    ue_ul_values = []
                    ue_metrics = {}
                    
                    last_ue_id = current_ue_id
                    last_cell_id = current_cell_id
                
                # If no UE is selected, just write empty data
                if current_ue_id is None:
                    chart_data = {
                        'found': False,
                        'cell_id': current_cell_id,
                        'ue_id': None,
                        'metrics': {},
                        'time_points': [],
                        'dl_values': [],
                        'ul_values': [],
                        'timestamp': time.time()
                    }
                    
                    with open(ue_data_file_path, 'w') as f:
                        json.dump(chart_data, f)
                    
                    time.sleep(3)
                    continue
                
                # Get UE-specific throughput data
                print(f"[DEBUG][update_ue_chart] Fetching UE data for UE={current_ue_id}, Cell={current_cell_id}")
                ue_data = get_ue_throughput(current_ue_id, current_cell_id)
                
                if ue_data['found']:
                    # Get the metrics
                    ue_metrics = ue_data['metrics']
                    
                    # If we have historical data, use it
                    if ue_data['historical']['time_points']:
                        ue_time_points = ue_data['historical']['time_points']
                        ue_dl_values = ue_data['historical']['dl_values']
                        ue_ul_values = ue_data['historical']['ul_values']
                    # Otherwise, add the current data point
                    elif 'DL-TPT' in ue_metrics and 'UL-TPT' in ue_metrics:
                        # Try to get current uptime
                        current_time = None
                        try:
                            with open(os.path.join(ip_dir, f"du_chart_data_{clean_ip}.json"), 'r') as f:
                                du_data = json.load(f)
                                if 'current_time' in du_data:
                                    current_time = du_data['current_time']
                        except (FileNotFoundError, json.JSONDecodeError):
                            pass
                            
                        # Use uptime if available, otherwise use 0
                        ue_time_points.append(current_time or 0)
                        ue_dl_values.append(float(ue_metrics['DL-TPT']))
                        ue_ul_values.append(float(ue_metrics['UL-TPT']))
                    
                    print(f"[DEBUG][update_ue_chart] UE={current_ue_id} data found. DL={ue_metrics.get('DL-TPT', 'N/A')}, UL={ue_metrics.get('UL-TPT', 'N/A')}")
                else:
                    # Keep previous data but mark as not found
                    print(f"[DEBUG][update_ue_chart] No data found for UE={current_ue_id}")
                
                # Save the data to a JSON file for the web page to fetch
                chart_data = {
                    'found': ue_data['found'],
                    'cell_id': current_cell_id,
                    'ue_id': current_ue_id,
                    'metrics': ue_metrics,
                    'time_points': ue_time_points,
                    'dl_values': ue_dl_values,
                    'ul_values': ue_ul_values,
                    'timestamp': time.time()
                }
                
                print(f"[DEBUG][update_ue_chart] Writing UE data to {ue_data_file_path}")
                
                with open(ue_data_file_path, 'w') as f:
                    json.dump(chart_data, f)
                
                print(f"[DEBUG][update_ue_chart] UE data file write complete")
                
                # Wait before next update
                time.sleep(3)
                
            except Exception as e:
                print(f"[DEBUG][update_ue_chart] Error in update_ue_chart: {str(e)}")
                import traceback
                print(traceback.format_exc())
                time.sleep(5)  # Wait a bit longer if there was an error
    
    # Start the update threads
    du_thread = threading.Thread(target=update_du_chart)
    du_thread.daemon = True
    du_thread.start()
    
    # Start cell info update thread separately
    cell_info_thread = threading.Thread(target=update_cell_info)
    cell_info_thread.daemon = True
    cell_info_thread.start()
    
    # Start UE info update thread
    ue_info_thread = threading.Thread(target=update_ue_info)
    ue_info_thread.daemon = True
    ue_info_thread.start()
    
    l1_thread = threading.Thread(target=update_l1_chart)
    l1_thread.daemon = True
    l1_thread.start()
    
    la_thread = threading.Thread(target=update_la_chart)
    la_thread.daemon = True
    la_thread.start()
    
    ue_thread = threading.Thread(target=update_ue_chart)
    ue_thread.daemon = True
    ue_thread.start()
    
    # Start UE count monitoring thread
    ue_count_thread = threading.Thread(target=monitor_ue_count)
    ue_count_thread.daemon = True
    ue_count_thread.start()
    
    # Keep the main thread running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Chart monitoring stopped by user")

# Add a new function to periodically update cell information
def update_cell_info():
    """Periodically updates the cell information for dropdown in the web UI"""
    global ip_dir, clean_ip
    
    cell_info_file = os.path.join(ip_dir, f"cell_info_{clean_ip}.json")
    cell_selection_file = os.path.join(ip_dir, f"cell_selection_{clean_ip}.json")
    
    last_cell_ids = []
    
    while True:
        try:
            # Fetch latest cell information
            cell_data = update_data()
            available_cells = cell_data.get('cell_ids', [])
            
            # Ensure available_cells is always a list
            if not available_cells:
                available_cells = [1]
            
            # Only update if cell IDs have changed
            if set(available_cells) != set(last_cell_ids):
                print(f"[INFO] Cell IDs changed. New cells: {available_cells}")
                
                # Get current selected cell
                try:
                    with open(cell_selection_file, 'r') as f:
                        selection = json.load(f)
                        current_cell_id = selection.get('selected_cell')
                except (FileNotFoundError, json.JSONDecodeError):
                    current_cell_id = 1 if 1 in available_cells else (available_cells[0] if available_cells else 1)
                
                # If current selected cell is no longer available, switch to first available cell
                if current_cell_id not in available_cells and available_cells:
                    current_cell_id = available_cells[0]
                    # Update cell selection
                    with open(cell_selection_file, 'w') as f:
                        json.dump({
                            'selected_cell': current_cell_id,
                            'timestamp': time.time()
                        }, f)
                    print(f"[INFO] Selected cell no longer available. Switching to cell {current_cell_id}")
                
                # Update cell info file
                with open(cell_info_file, 'w') as f:
                    json.dump({
                        'available_cells': available_cells,
                        'default_cell': current_cell_id,
                        'timestamp': time.time()
                    }, f)
                
                print(f"[INFO] Updated cell information. Available cells: {available_cells}")
                last_cell_ids = available_cells
        
        except Exception as e:
            print(f"[ERROR] Failed to update cell information: {e}")
        
        # Check for cell updates every 10 seconds
        time.sleep(10)

# Add this new function to periodically update UE information
def update_ue_info():
    """Periodically updates the UE information for dropdown in the web UI"""
    global ip_dir, clean_ip
    
    ue_info_file = os.path.join(ip_dir, f"ue_info_{clean_ip}.json")
    ue_selection_file = os.path.join(ip_dir, f"ue_selection_{clean_ip}.json")
    cell_selection_file = os.path.join(ip_dir, f"cell_selection_{clean_ip}.json")
    ue_count_file = os.path.join(ip_dir, f"ue_count_{clean_ip}.json")
    
    last_ue_ids = []
    
    while True:
        try:
            # Get the current selected cell from the IP-specific file
            try:
                with open(cell_selection_file, 'r') as f:
                    selection = json.load(f)
                    current_cell_id = selection.get('selected_cell')
            except (FileNotFoundError, json.JSONDecodeError):
                current_cell_id = 1  # Default cell ID
            
            # Get the number of UEs from the ue_count file
            num_ue = 0
            try:
                with open(ue_count_file, 'r') as f:
                    ue_count_data = json.load(f)
                    num_ue = ue_count_data.get('cell_ue_counts', {}).get(str(current_cell_id), 0)
                    print(f"[DEBUG][update_ue_info] Got num_ue={num_ue} from UE count monitor")
            except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
                print(f"[DEBUG][update_ue_info] Couldn't get num_ue from UE count file: {e}")
                # Fall back to the DU data or update_data if the file doesn't exist yet
                try:
                    with open(os.path.join(ip_dir, f"du_chart_data_{clean_ip}.json"), 'r') as f:
                        du_data = json.load(f)
                        if 'num_ue_values' in du_data and du_data['num_ue_values']:
                            num_ue = du_data['num_ue_values'][-1]  # Get the latest value
                            print(f"[DEBUG][update_ue_info] Got num_ue={num_ue} from DU data")
                except (FileNotFoundError, json.JSONDecodeError, KeyError):
                    # Try to get it directly from the update_data function
                    cell_data = update_data()
                    if cell_data and 'cells' in cell_data and current_cell_id in cell_data['cells']:
                        num_ue = int(cell_data['cells'][current_cell_id].get('NUM-UE', 0))
                        print(f"[DEBUG][update_ue_info] Got num_ue={num_ue} from update_data")
            
            # Always fetch UE IDs, even if num_ue reports 0
            # Sometimes the NUM-UE field might not be updated correctly
            print(f"[DEBUG][update_ue_info] Fetching UE IDs for cell {current_cell_id} (reported num_ue={num_ue})")
            ue_ids = get_ue_ids_for_cell(current_cell_id, max(1, num_ue))  # Try at least 1 UE
            
            # If we didn't find any UEs using standard methods, try a more aggressive approach
            if not ue_ids and current_cell_id is not None:
                print(f"[DEBUG][update_ue_info] No UEs found with standard method, trying alternative approach")
                # Try to get UE IDs from UE Instantaneous Statistics with a larger line count
                ue_cmd = f"cat /workspace/logs/$(ls -rt /workspace/logs/ | grep du_stat | tail -n 1) | grep \"UE Instantaneous Statistics\" -A 50"
                ue_stats = bash_command(ssh, ue_cmd)
                
                if ue_stats and ue_stats[0]:
                    lines = ue_stats[0].splitlines()
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 8:  # Ensure we have at least 8 columns
                            try:
                                # The first column should be UE-ID, 8th column is PCELL-ID
                                ue_id = int(parts[0])
                                pcell_id = int(parts[7])
                                # Only add if it matches the requested cell_id
                                if pcell_id == current_cell_id:
                                    if ue_id not in ue_ids:
                                        ue_ids.append(ue_id)
                                        print(f"[DEBUG][update_ue_info] Found UE {ue_id} for cell {current_cell_id} via alternative method")
                            except (ValueError, IndexError):
                                continue
            
            # Create UE info file regardless of whether UEs are found
            # This ensures the file always exists, even with empty data
            print(f"[DEBUG][update_ue_info] Found {len(ue_ids)} UEs for cell {current_cell_id}: {ue_ids}")
            
            # Update UE info file with UE metrics for each UE
            ue_metrics = {}
            for ue_id in ue_ids:
                ue_data = get_ue_throughput(ue_id, current_cell_id)
                if ue_data['found']:
                    ue_metrics[ue_id] = {
                        'DL-TPT': ue_data['metrics'].get('DL-TPT', 0),
                        'UL-TPT': ue_data['metrics'].get('UL-TPT', 0),
                        'PCELL-ID': ue_data['metrics'].get('PCELL-ID', current_cell_id)
                    }
                    print(f"[DEBUG][update_ue_info] Added metrics for UE {ue_id}: DL={ue_metrics[ue_id]['DL-TPT']}, UL={ue_metrics[ue_id]['UL-TPT']}")
            
            # Always write to the file, even if no UEs are found
            # First, clean (empty) the file by opening it in 'w' mode and immediately closing it
            open(ue_info_file, 'w').close()
            print(f"[DEBUG][update_ue_info] Cleaned ue_info_{clean_ip}.json file before writing new data")
            
            # Now write the new data to the file
            with open(ue_info_file, 'w') as f:
                json.dump({
                    'available_ues': ue_ids,
                    'default_ue': ue_ids[0] if ue_ids else None,
                    'ue_metrics': ue_metrics,
                    'cell_id': current_cell_id,
                    'no_ues_message': "No UEs Connected" if not ue_ids else "",
                    'timestamp': time.time()
                }, f)
            
            print(f"[INFO] Updated UE information. Available UEs: {ue_ids if ue_ids else 'No UEs Connected'}")
            last_ue_ids = ue_ids
        
        except Exception as e:
            print(f"[ERROR] Failed to update UE information: {e}")
            import traceback
            print(traceback.format_exc())
            
            # Create a basic file with error information when an exception occurs
            try:
                # Clean the file first
                open(ue_info_file, 'w').close()
                print(f"[DEBUG][update_ue_info] Cleaned ue_info_{clean_ip}.json file before writing error state")
                
                with open(ue_info_file, 'w') as f:
                    json.dump({
                        'available_ues': [],
                        'default_ue': None,
                        'ue_metrics': {},
                        'cell_id': None,
                        'no_ues_message': f"Error retrieving UE information: {str(e)}",
                        'timestamp': time.time(),
                        'error': str(e)
                    }, f)
                print(f"[INFO] Created error state UE info file")
            except Exception as write_error:
                print(f"[ERROR] Failed to create error state UE info file: {write_error}")
        
        # Check for UE updates every 5 seconds
        time.sleep(5)

# Add this new function to check the number of UEs every 5 seconds
def monitor_ue_count():
    """
    Periodically checks the number of UEs for each cell and stores the information
    """
    global ip_dir, clean_ip
    
    ue_count_file = os.path.join(ip_dir, f"ue_count_{clean_ip}.json")
    last_counts = {}
    
    while True:
        try:
            # Get current cell IDs
            cell_data = update_data()
            cell_ids = cell_data.get('cell_ids', [])
            
            if not cell_ids:
                cell_ids = [1]  # Default to cell 1 if no cells found
            
            # Check UE count for each cell
            current_counts = {}
            for cell_id in cell_ids:
                num_ue = get_num_ues_for_cell(cell_id)
                current_counts[str(cell_id)] = num_ue
            
            # Only update if counts have changed
            if current_counts != last_counts:
                with open(ue_count_file, 'w') as f:
                    json.dump({
                        'cell_ue_counts': current_counts,
                        'timestamp': time.time()
                    }, f)
                print(f"[INFO] Updated UE counts: {current_counts}")
                last_counts = current_counts
            
        except Exception as e:
            print(f"[ERROR] Failed to monitor UE count: {e}")
            import traceback
            print(traceback.format_exc())
        
        # Check every 5 seconds
        time.sleep(5)

# Start the real-time chart
if __name__ == "__main__":
    create_chart()


