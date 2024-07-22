import re
from collections import defaultdict
import time
import os
import json
import tkinter as tk
from tkinter import ttk, simpledialog, filedialog, messagebox
import threading
from datetime import datetime
import socket
from operator import itemgetter
import requests

class SettingsDialog(simpledialog.Dialog):
    def __init__(self, parent, title, config):
        self.config = config
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="RCON Message Character Limit:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.rcon_limit = ttk.Entry(master)
        self.rcon_limit.insert(0, str(self.config.get('rcon_message_limit', 300)))
        self.rcon_limit.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(master, text="Player List Update Interval (seconds):").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.update_interval = ttk.Entry(master)
        self.update_interval.insert(0, str(self.config.get('player_list_update_interval', 5)))
        self.update_interval.grid(row=1, column=1, padx=5, pady=5)

        return self.rcon_limit  # Initial focus

    def apply(self):
        self.result = {
            'rcon_message_limit': int(self.rcon_limit.get()),
            'player_list_update_interval': int(self.update_interval.get())
        }
        
class RCONClient:
    def __init__(self, ip, port, password):
        self.ip = ip
        self.port = port
        self.password = password

    def send_command(self, command):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.ip, self.port))
                auth_packet = self.create_packet(3, self.password)
                sock.send(auth_packet)
                auth_response = self.receive_packet(sock)
                
                if auth_response[0] == -1:
                    print("RCON authentication failed")
                    return None
                
                command_packet = self.create_packet(2, command)
                sock.send(command_packet)
                response = self.receive_packet(sock)
                return response[2].decode('utf-8')
        except Exception as e:
            print(f"RCON error: {e}")
            return None

    def create_packet(self, type, body):
        body = body.encode('utf-8')
        size = len(body) + 10
        return (size.to_bytes(4, 'little') +
                int.to_bytes(0, 4, 'little') +
                type.to_bytes(4, 'little') +
                body + b'\x00\x00')

    def receive_packet(self, sock):
        raw_size = sock.recv(4)
        size = int.from_bytes(raw_size, 'little')
        packet = sock.recv(size)
        id = int.from_bytes(packet[:4], 'little')
        type = int.from_bytes(packet[4:8], 'little')
        body = packet[8:-2]
        return (id, type, body)

class SteamAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/"

    def get_username(self, steam_id):
        params = {
            "key": self.api_key,
            "steamids": steam_id
        }
        try:
            response = requests.get(self.base_url, params=params)
            response.raise_for_status()
            data = response.json()
            players = data['response']['players']
            if players:
                return players[0]['personaname']
            else:
                return None
        except requests.RequestException as e:
            print(f"Error fetching Steam username: {e}")
            return None
            
class PlayerTracker:
    def __init__(self, log_file_path, data_file_path, steam_api_key):
        self.log_file_path = log_file_path
        self.data_file_path = data_file_path
        self.data = self.load_data()
        self.players = self.data.get('players', {})
        self.last_position = 0
        self.last_processed_timestamp = self.get_last_processed_timestamp()
        self.rcon_client = None
        self.setup_rcon()
        self.steam_api = SteamAPI(steam_api_key)
        self.commands = {
            '!help': self.command_help,
            '!kd': self.command_kd,
            '!rank': self.command_rank,
            '!stats': self.command_stats,
            '!weapons': self.command_weapons,
            '!weapondeaths': self.command_weapon_deaths
        }
        self.command_descriptions = {
            '!help': 'Show this help message',
            '!kd': 'Show your kill/death ratio',
            '!rank': 'Show your rank among all players',
            '!stats': 'Show your detailed statistics',
            '!weapons': 'Show your top 5 weapons and their rankings',
            '!weapondeaths': 'Show top 5 weapons that killed you and their rankings'
        }
        self.start_periodic_help()
        self.config = {
            'rcon_message_limit': 300,
            'player_list_update_interval': 5
        }

    def get_player_name(self, player_id):
        return self.steam_api.get_username(player_id) or player_id
        
    def load_data(self):
        if os.path.exists(self.data_file_path):
            with open(self.data_file_path, 'r') as file:
                return json.load(file)
        return {'players': {}, 'rcon': {}}

    def save_data(self):
        with open(self.data_file_path, 'w') as file:
            json.dump({'players': self.players, 'rcon': self.data.get('rcon', {})}, file, indent=2)

    def setup_rcon(self):
        rcon_data = self.data.get('rcon', {})
        if rcon_data:
            self.rcon_client = RCONClient(rcon_data['ip'], rcon_data['port'], rcon_data['password'])

    def update_rcon_settings(self, ip, port, password):
        self.data['rcon'] = {'ip': ip, 'port': port, 'password': password}
        self.setup_rcon()
        self.save_data()

    def get_last_processed_timestamp(self):
        last_timestamp = "1970.01.01-00.00.00"
        for player_data in self.players.values():
            for event in player_data.get("kills", []) + player_data.get("deaths", []) + player_data.get("chat_history", []) + player_data.get("objectives", []):
                if event["timestamp"] > last_timestamp:
                    last_timestamp = event["timestamp"]
        return last_timestamp

    def parse_log_line(self, line):
        kill_pattern = r'(\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}).*?(\w+)\[(\d+|INVALID), team \d+\] killed (\w+)\[(\d+|INVALID), team \d+\] with (BP_\w+)'
        chat_pattern = r'(\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}).*?LogChat: Display: (.+)\((\d+)\) .+Chat: (.+)'
        objective_pattern = r'(\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}).*?Objective \d+ was captured for team \d+ from team \d+ by (.+)'
        
        kill_match = re.search(kill_pattern, line)
        if kill_match:
            timestamp, killer, killer_id, victim, victim_id, weapon = kill_match.groups()
            if timestamp <= self.last_processed_timestamp:
                return
            weapon_base = weapon.split('_')[2]  # Extract base weapon name
            
            # Process killer data
            if killer_id != "INVALID":
                if killer_id not in self.players:
                    self.players[killer_id] = self.create_default_player_data()
                self.players[killer_id]["kills"].append({
                    "timestamp": timestamp,
                    "victim": victim,
                    "weapon": weapon_base
                })
                self.players[killer_id]["weapons_kills"][weapon_base] = self.players[killer_id]["weapons_kills"].get(weapon_base, 0) + 1

            # Process victim data
            if victim_id != "INVALID":
                if victim_id not in self.players:
                    self.players[victim_id] = self.create_default_player_data()
                self.players[victim_id]["deaths"].append({
                    "timestamp": timestamp,
                    "killer": killer,
                    "weapon": weapon_base
                })
                self.players[victim_id]["weapons_deaths"][weapon_base] = self.players[victim_id]["weapons_deaths"].get(weapon_base, 0) + 1
            return

        chat_match = re.search(chat_pattern, line)
        if chat_match:
            timestamp, player_name, player_id, message = chat_match.groups()
            if timestamp <= self.last_processed_timestamp:
                return
            if player_id not in self.players:
                self.players[player_id] = self.create_default_player_data()
            self.players[player_id]["chat_history"].append({
                "timestamp": timestamp,
                "message": message
            })
            self.process_chat_command(player_id, message)
            return

        # Update the objective parsing to include score calculation
        objective_match = re.search(objective_pattern, line)
        if objective_match:
            timestamp, players_str = objective_match.groups()
            if timestamp <= self.last_processed_timestamp:
                return
            players = players_str.split(", ")
            for player in players:
                player_name, player_id = player.split("[")
                player_id = player_id.strip("]")
                if player_id != "INVALID":
                    if player_id not in self.players:
                        self.players[player_id] = self.create_default_player_data()
                    self.players[player_id]["objectives"].append({
                        "timestamp": timestamp
                    })
                    self.players[player_id]["score"] += 100  # Add 100 points for objective capture

    def create_default_player_data(self):
        return {
            "kills": [],
            "deaths": [],
            "weapons_kills": {},
            "weapons_deaths": {},
            "chat_history": [],
            "objectives": [],
            "score": 0  # Initialize score
        }
    def calculate_scores(self):
        for player_id, player_data in self.players.items():
            if player_id != "INVALID].":  # Exclude the INVALID player
                kills_score = len(player_data['kills']) * 10
                objectives_score = len(player_data['objectives']) * 100
                player_data['score'] = kills_score + objectives_score

    def get_player_rank(self, player_id):
        self.calculate_scores()
        valid_players = {pid: data for pid, data in self.players.items() if pid != "INVALID]."}
        sorted_players = sorted(valid_players.items(), key=lambda x: x[1]['score'], reverse=True)
        for rank, (pid, _) in enumerate(sorted_players, 1):
            if pid == player_id:
                return rank, len(sorted_players)
        return None, len(sorted_players)

    def command_rank(self, player_id):
        player_name = self.get_player_name(player_id)
        rank, total_players = self.get_player_rank(player_id)
        if rank is not None:
            player_data = self.players[player_id]
            message = f"Player {player_name} (ID: {player_id}) rank: #{rank}/{total_players} (Score: {player_data['score']}, Kills: {len(player_data['kills'])}, Objectives: {len(player_data['objectives'])})"
        else:
            message = f"Player {player_name} (ID: {player_id}) not found in rankings."
        self.send_rcon_message(message)
        
    def process_chat_command(self, player_id, message):
        command = message.split()[0].lower()
        if command in self.commands:
            self.commands[command](player_id)
    def calculate_weapon_rankings(self, weapon_type='kills'):
        weapon_stats = defaultdict(lambda: defaultdict(int))
        for player_id, player_data in self.players.items():
            if player_id != "INVALID].":
                for weapon, count in player_data[f'weapons_{weapon_type}'].items():
                    weapon_stats[weapon][player_id] = count
        
        rankings = {}
        for weapon, players in weapon_stats.items():
            sorted_players = sorted(players.items(), key=itemgetter(1), reverse=True)
            rankings[weapon] = {player_id: rank for rank, (player_id, _) in enumerate(sorted_players, 1)}
        
        return rankings, weapon_stats

    def get_top_weapons(self, player_id, weapon_type='kills', top_n=5):
        player_data = self.players.get(player_id)
        if not player_data:
            return []
        
        weapon_counts = player_data[f'weapons_{weapon_type}']
        sorted_weapons = sorted(weapon_counts.items(), key=itemgetter(1), reverse=True)
        return sorted_weapons[:top_n]

    def command_weapons(self, player_id):
        player_name = self.get_player_name(player_id)
        top_weapons = self.get_top_weapons(player_id, 'kills')
        rankings, weapon_stats = self.calculate_weapon_rankings('kills')
        
        message_lines = [f"Top 5 weapons for player {player_name} (ID: {player_id}):"]
        for rank, (weapon, kills) in enumerate(top_weapons, 1):
            weapon_rank = rankings[weapon][player_id]
            total_users = len(weapon_stats[weapon])
            message_lines.append(f"{rank}. {weapon}: {kills} kills (rank #{weapon_rank}/{total_users})")
        
        message = "\n".join(message_lines)
        self.send_rcon_message(message)

    def command_weapon_deaths(self, player_id):
        player_name = self.get_player_name(player_id)
        top_death_weapons = self.get_top_weapons(player_id, 'deaths')
        rankings, weapon_stats = self.calculate_weapon_rankings('deaths')
        
        message_lines = [f"Top 5 weapons that killed player {player_name} (ID: {player_id}):"]
        for rank, (weapon, deaths) in enumerate(top_death_weapons, 1):
            weapon_rank = rankings[weapon][player_id]
            total_victims = len(weapon_stats[weapon])
            message_lines.append(f"{rank}. {weapon}: {deaths} deaths (rank #{weapon_rank}/{total_victims})")
        
        message = "\n".join(message_lines)
        self.send_rcon_message(message)

    def command_kd(self, player_id):
        player_name = self.get_player_name(player_id)
        player_data = self.players.get(player_id, self.create_default_player_data())
        kills = len(player_data['kills'])
        deaths = len(player_data['deaths'])
        kd_ratio = kills / deaths if deaths > 0 else kills
        message = f"Player {player_name} (ID: {player_id}): K/D Ratio: {kd_ratio:.2f} (Kills: {kills}, Deaths: {deaths})"
        self.send_rcon_message(message)
        
    def command_stats(self, player_id):
        player_name = self.get_player_name(player_id)
        player_data = self.players.get(player_id)
        if player_data:
            kills = len(player_data['kills'])
            deaths = len(player_data['deaths'])
            objectives = len(player_data['objectives'])
            kd_ratio = kills / deaths if deaths > 0 else kills
            score = player_data['score']
            message = f"Player {player_name} (ID: {player_id}) stats: Score: {score}, K/D: {kd_ratio:.2f}, Kills: {kills}, Deaths: {deaths}, Objectives: {objectives}"
        else:
            message = f"Player {player_name} (ID: {player_id}) not found."
        self.send_rcon_message(message)
        
    def command_help(self, player_id):
        help_message = "Available commands:\n" + "\n".join([f"{cmd}: {desc}" for cmd, desc in self.command_descriptions.items()])
        self.send_rcon_message(help_message)

    def send_periodic_help(self):
        help_message = "Available commands: " + ", ".join(self.commands.keys()) + ". Type !help for more information."
        self.send_rcon_message(help_message)

    def start_periodic_help(self):
        def periodic_help_thread():
            while True:
                time.sleep(300)  # Wait for 5 minutes
                self.send_periodic_help()

        thread = threading.Thread(target=periodic_help_thread, daemon=True)
        thread.start()

    def send_rcon_message(self, message):
        if self.rcon_client:
            max_length = self.config['rcon_message_limit']
            messages = [message[i:i+max_length] for i in range(0, len(message), max_length)]
            for msg in messages:
                self.rcon_client.send_command(f"say {msg}")


    def create_default_player_data(self):
        return {
            "kills": [],
            "deaths": [],
            "weapons_kills": {},
            "weapons_deaths": {},
            "chat_history": [],
            "objectives": []
        }

    def process_new_lines(self):
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='replace') as file:
                file.seek(self.last_position)
                for line in file:
                    self.parse_log_line(line)
                self.last_position = file.tell()
            self.last_processed_timestamp = self.get_last_processed_timestamp()
            self.save_data()
        except IOError as e:
            print(f"Error reading log file: {e}")

    def run(self):
        while True:
            self.process_new_lines()
            time.sleep(5)  # Wait for 5 seconds before processing again
    def update_log_file_path(self, new_path):
        self.log_file_path = new_path
        self.last_position = 0  # Reset the last position when changing the log file

    def update_data_file_path(self, new_path):
        self.data_file_path = new_path
        self.save_data()  # Save current data to the new location

    def update_steam_api_key(self, new_key):
        self.steam_api.api_key = new_key

    def update_rcon_settings(self, ip, port, password):
        self.rcon_client = RCONClient(ip, port, password)

class PlayerTrackerGUI:
    def __init__(self, master, player_tracker, config_file):
        self.master = master
        self.player_tracker = player_tracker
        self.config_file = config_file
        master.title("Insurgency: Sandstorm Player Tracker")

        # Create menu bar
        self.menu_bar = tk.Menu(master)
        master.config(menu=self.menu_bar)

        # Create File menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Setup RCON", command=self.setup_rcon)
        self.file_menu.add_command(label="Set Log File Path", command=self.set_log_file_path)
        self.file_menu.add_command(label="Set JSON Save Path", command=self.set_json_save_path)
        self.file_menu.add_command(label="Set Steam API Key", command=self.set_steam_api_key)
        self.file_menu.add_command(label="Settings", command=self.open_settings)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=master.quit)


        self.player_listbox = tk.Listbox(master, width=50)
        self.player_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.player_listbox.bind('<<ListboxSelect>>', self.on_player_select)

        self.details_frame = ttk.Frame(master, padding="10")
        self.details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.details_text = tk.Text(self.details_frame, wrap=tk.WORD, width=50, height=20)
        self.details_text.pack(fill=tk.BOTH, expand=True)

        self.update_player_list()
        
    def open_settings(self):
        settings = SettingsDialog(self.master, "Settings", self.player_tracker.config)
        if settings.result:
            self.player_tracker.config.update(settings.result)
            self.save_config()
            self.apply_settings()

    def apply_settings(self):
        # Apply new settings
        self.player_tracker.rcon_message_limit = self.player_tracker.config['rcon_message_limit']
        self.update_player_list_interval()

    def update_player_list_interval(self):
        # Cancel the existing scheduled update
        if hasattr(self, '_job'):
            self.master.after_cancel(self._job)
        
        # Schedule a new update with the new interval
        interval_ms = self.player_tracker.config['player_list_update_interval'] * 1000
        self._job = self.master.after(interval_ms, self.update_player_list)

    def update_player_list(self):
        self.player_listbox.delete(0, tk.END)
        for player_id in self.player_tracker.players:
            self.player_listbox.insert(tk.END, player_id)
        self.update_player_list_interval()  # Schedule the next update

    def on_player_select(self, event):
        selection = self.player_listbox.curselection()
        if selection:
            player_id = self.player_listbox.get(selection[0])
            player_data = self.player_tracker.players[player_id]
            self.display_player_details(player_id, player_data)

    def display_player_details(self, player_id, player_data):
        self.details_text.delete('1.0', tk.END)
        self.details_text.insert(tk.END, f"Player ID: {player_id}\n")
        kills = len(player_data['kills'])
        deaths = len(player_data['deaths'])
        kd_ratio = kills / deaths if deaths > 0 else kills
        self.details_text.insert(tk.END, f"Total Kills: {kills}\n")
        self.details_text.insert(tk.END, f"Total Deaths: {deaths}\n")
        self.details_text.insert(tk.END, f"K/D Ratio: {kd_ratio:.2f}\n")
        self.details_text.insert(tk.END, f"Objectives Captured: {len(player_data['objectives'])}\n\n")
        
        self.details_text.insert(tk.END, "Kills by Weapon:\n")
        for weapon, count in player_data['weapons_kills'].items():
            self.details_text.insert(tk.END, f"  {weapon}: {count}\n")
        
        self.details_text.insert(tk.END, "\nDeaths by Weapon:\n")
        for weapon, count in player_data['weapons_deaths'].items():
            self.details_text.insert(tk.END, f"  {weapon}: {count}\n")
        
        self.details_text.insert(tk.END, "\nRecent Kills:\n")
        for kill in player_data['kills'][-5:]:  # Show last 5 kills
            self.details_text.insert(tk.END, f"  {kill['timestamp']} - Killed {kill['victim']} with {kill['weapon']}\n")
        
        self.details_text.insert(tk.END, "\nRecent Deaths:\n")
        for death in player_data['deaths'][-5:]:  # Show last 5 deaths
            self.details_text.insert(tk.END, f"  {death['timestamp']} - Killed by {death['killer']} with {death['weapon']}\n")
        
        self.details_text.insert(tk.END, "\nRecent Objectives:\n")
        for objective in player_data['objectives'][-5:]:  # Show last 5 objectives
            self.details_text.insert(tk.END, f"  {objective['timestamp']} - Captured an objective\n")
        
        self.details_text.insert(tk.END, "\nRecent Chat History:\n")
        for chat in player_data['chat_history'][-5:]:  # Show last 5 chat messages
            self.details_text.insert(tk.END, f"  {chat['timestamp']} - {chat['message']}\n")

    def setup_rcon(self):
        ip = simpledialog.askstring("RCON Settings", "Enter RCON IP:")
        port = simpledialog.askinteger("RCON Settings", "Enter RCON Port:")
        password = simpledialog.askstring("RCON Settings", "Enter RCON Password:", show='*')
        if ip and port and password:
            self.player_tracker.update_rcon_settings(ip, port, password)
            self.save_config()
            messagebox.showinfo("RCON Settings", "RCON settings updated and saved successfully.")

    def set_log_file_path(self):
        default_path = r"D:\SteamLibrary\steamapps\common\sandstorm_server\Insurgency\Saved\Logs\Insurgency.log"
        file_path = filedialog.askopenfilename(
            title="Select Insurgency.log file",
            filetypes=[("Log files", "*.log")],
            initialdir=os.path.dirname(default_path)
        )
        if file_path:
            self.player_tracker.update_log_file_path(file_path)
            self.save_config()
            messagebox.showinfo("Log File Path", f"Log file path set to:\n{file_path}\nConfiguration saved.")

    def set_json_save_path(self):
        default_path = r"D:\SteamLibrary\steamapps\common\sandstorm_server\Insurgency\Saved\Logs\player_data.json"
        file_path = filedialog.asksaveasfilename(
            title="Select JSON save location",
            filetypes=[("JSON files", "*.json")],
            initialdir=os.path.dirname(default_path),
            defaultextension=".json"
        )
        if file_path:
            self.player_tracker.update_data_file_path(file_path)
            self.save_config()
            messagebox.showinfo("JSON Save Path", f"JSON save path set to:\n{file_path}\nConfiguration saved.")

    def set_steam_api_key(self):
        api_key = simpledialog.askstring("Steam API Key", "Enter Steam API Key:")
        if api_key:
            self.player_tracker.update_steam_api_key(api_key)
            self.save_config()
            messagebox.showinfo("Steam API Key", "Steam API key updated and saved successfully.")

    def save_config(self):
        config = {
            "log_file_path": self.player_tracker.log_file_path,
            "data_file_path": self.player_tracker.data_file_path,
            "steam_api_key": self.player_tracker.steam_api.api_key,
            "rcon": {
                "ip": self.player_tracker.rcon_client.ip if self.player_tracker.rcon_client else "",
                "port": self.player_tracker.rcon_client.port if self.player_tracker.rcon_client else 0,
                "password": self.player_tracker.rcon_client.password if self.player_tracker.rcon_client else ""
            }
        }
        config.update(self.player_tracker.config)  # Add new settings to the config
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
            
    def update_rcon_settings(self):
        ip = simpledialog.askstring("RCON Settings", "Enter RCON IP:")
        port = simpledialog.askinteger("RCON Settings", "Enter RCON Port:")
        password = simpledialog.askstring("RCON Settings", "Enter RCON Password:", show='*')
        if ip and port and password:
            self.player_tracker.update_rcon_settings(ip, port, password)

def main():
    config_file = "tracker_config.json"
    default_config = {
        "log_file_path": r"D:\SteamLibrary\steamapps\common\sandstorm_server\Insurgency\Saved\Logs\Insurgency.log",
        "data_file_path": r"D:\SteamLibrary\steamapps\common\sandstorm_server\Insurgency\Saved\Logs\player_data.json",
        "steam_api_key": "YOUR_DEFAULT_API_KEY",
        "rcon": {
            "ip": "",
            "port": 0,
            "password": ""
        }
    }

    # Load or create configuration
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = default_config
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

    # Check if log file exists
    if not os.path.exists(config['log_file_path']):
        messagebox.showwarning("Log File Not Found", 
                               f"Log file not found at {config['log_file_path']}. "
                               "Please set the correct path in the File menu after the application starts.")

    # Create PlayerTracker instance
    tracker = PlayerTracker(config['log_file_path'], config['data_file_path'], config['steam_api_key'])

    # Set up RCON if configured
    if config['rcon']['ip'] and config['rcon']['port'] and config['rcon']['password']:
        tracker.update_rcon_settings(config['rcon']['ip'], config['rcon']['port'], config['rcon']['password'])

    # Start the tracker in a separate thread
    tracker_thread = threading.Thread(target=tracker.run, daemon=True)
    tracker_thread.start()

    # Start the GUI
    root = tk.Tk()
    gui = PlayerTrackerGUI(root, tracker, config_file)

    # Define a function to save config on exit
    def on_closing():
        config['log_file_path'] = tracker.log_file_path
        config['data_file_path'] = tracker.data_file_path
        config['steam_api_key'] = tracker.steam_api.api_key
        if tracker.rcon_client:
            config['rcon']['ip'] = tracker.rcon_client.ip
            config['rcon']['port'] = tracker.rcon_client.port
            config['rcon']['password'] = tracker.rcon_client.password
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
