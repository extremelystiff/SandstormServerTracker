# SandstormServerTracker


# UE4 Player Tracker

## Description
UE4 Player Tracker is a powerful tool designed for server administrators and enthusiasts of Unreal Engine 4-based games, particularly focused on Insurgency: Sandstorm. This application provides real-time tracking and analysis of player statistics, in-game events, and server interactions through an intuitive graphical user interface.

## Features

- **Real-time Log Parsing**: Continuously reads and parses the game server's log file to extract relevant information.
- **Player Statistics**: Tracks kills, deaths, K/D ratio, weapon usage, and objective captures for each player.
- **RCON Integration**: Sends in-game commands and messages through RCON (Remote Console) protocol.
- **Steam API Integration**: Retrieves player usernames using the Steam API for a more user-friendly display.
- **Graphical User Interface**: Easy-to-use interface for viewing player lists and detailed statistics.
- **In-game Commands**: Supports various in-game commands for players to check their stats and rankings.
- **In-App Configuration**: All settings and directories can be configured directly within the application.
- **Persistent Data Storage**: Saves player data in JSON format for long-term stat tracking.

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/ue4-player-tracker.git
   ```
2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

## Configuration

All configuration can be done directly within the application:

1. Run the application:
   ```
   python main.py
   ```
2. Use the File menu to configure all necessary settings:
   - Set Log File Path: Choose the location of your game server's log file.
   - Set JSON Save Path: Select where you want to store the player data JSON file.
   - Set Steam API Key: Enter your Steam API key (get one from https://steamcommunity.com/dev/apikey).
   - Setup RCON: Configure RCON settings (IP, port, and password).
   - Settings: Adjust other application settings as needed.

The application will automatically save your configuration for future use.

## Usage

After setting up your configuration, you can use the application to:

- View real-time player statistics
- Monitor in-game events
- Send RCON commands
- Analyze player performance

The main window displays a list of players and their detailed statistics.

## In-game Commands

Players can use the following commands in the game chat:

- `!help`: Display available commands
- `!kd`: Show player's kill/death ratio
- `!rank`: Display player's rank among all players
- `!stats`: Show detailed player statistics
- `!weapons`: List top 5 weapons used by the player
- `!weapondeaths`: List top 5 weapons that killed the player

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the Insurgency: Sandstorm community for inspiration and testing.
- Unreal Engine 4 for providing the framework that makes this tool possible.
