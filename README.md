# ESP RainMaker MCP Server

This project provides a Model Context Protocol (MCP) server wrapper around the [`esp-rainmaker-cli`](https://github.com/espressif/esp-rainmaker-cli) Python library.  
It allows MCP-compatible clients (like LLMs or applications such as Claude Desktop) to interact with your [ESP RainMaker](https://rainmaker.espressif.com/) devices using the official CLI.

## Prerequisites

*   **Python:** Version 3.13 or higher
*   **uv:** The `uv` Python package manager. Install from [Astral's uv documentation](https://docs.astral.sh/uv/getting-started/installation/).
*   **ESP RainMaker CLI Login:** You *must* have successfully logged into ESP RainMaker using the standard `esp-rainmaker-cli login` command in your terminal at least once. This server relies on the credentials saved by that process.

## Installation & Setup

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/dhavalgujar/esp-rainmaker-mcp.git
    cd esp-rainmaker-mcp
    ```

2.  **Install Dependencies using uv:**
    This command installs `esp-rainmaker-cli`, `mcp[cli]`, and any other dependencies listed in `pyproject.toml` into a virtual environment managed by `uv`.
    
    ```bash
    uv sync
    ```
    *(This assumes `uv` is installed)*

3. **Login to ESP Rainmaker using `esp-rainmaker-cli`**
    ```bash
    uv run esp-rainmaker-cli login
    ```

## Available Tools

This MCP server exposes the following tools for interacting with ESP RainMaker:

*   `login_instructions()`:
    *   Provides instructions (formatted with Markdown) on how to log in using the standard `esp-rainmaker-cli login` command in your terminal.  
        This server relies on the external CLI's browser-based login flow to securely store credentials.  
        Rendering as Markdown depends on the MCP client's capabilities.
*   `check_login_status()`:
    *   Checks if a valid login session exists based on credentials stored locally by `esp-rainmaker-cli`.
        Confirms if the server can communicate with the ESP RainMaker backend.
*   `get_nodes()`:
    *   Lists all node IDs associated with the logged-in user.
*   `get_node_config(node_id: str)`:
    *   Get the configuration details (device types, parameters, capabilities) for a specific node ID. Returns a dictionary.
*   `get_node_status(node_id: str)`:
    *   Get the online/offline connectivity status for a specific node ID. Returns a dictionary.
*   `get_params(node_id: str)`:
    *   Get the current parameters (state, e.g., Power, Brightness) for a specific node ID. Returns a dictionary.
*   `set_params(node_id: str, params_json: str)`:
    *   Set parameters for a specific node. Requires `params_json` to be a **string** containing valid JSON representing the desired state changes (e.g., `'{"Thermostat": {"Power": false}}'`). Returns a success or error message string.
*   `logout()`:
    *   Logout the current user from ESP RainMaker via API (if possible) and **clears the locally stored credentials**.
    *   Use this if you explicitly want to end the session saved by `esp-rainmaker-cli login`.


> [!NOTE]
> Direct login via username/password within MCP is not supported for security reasons. Please use the standard CLI login flow first.


## Client Configuration

To add this server to an MCP client (like Claude Desktop or Cursor, add an entry similar to the following to your client's configuration file (e.g., `claude_desktop_config.json` for Claude Desktop):

```json
{
   "mcpServers": {
      "ESP-RainMaker-MCP": {
         "command": "uv",
         "args": [
            "run",
            "--with",
            "esp-rainmaker-cli",
            "--with",
            "mcp[cli]",
            "mcp",
            "run",
            "<absolute_path_to_repo>/server.py"
         ]
      }
   }
}
```

> [!IMPORTANT]
> Replace `<absolute_path_to_repo>/server.py` with the actual **absolute path** to the `server.py` file within the cloned `esp-rainmaker-mcp` directory on your system.

> The `--with` arguments ensure `uv` includes the necessary dependencies when running the `mcp run` command.

## How it Works

This server acts as a bridge. It uses the `mcp` library to handle the Model Context Protocol communication. When a tool is called:

1.  It uses functions from the installed `esp-rainmaker-cli` library.
2.  The library functions read locally stored authentication tokens.
3.  It makes the necessary API calls to the ESP RainMaker cloud.
4.  It returns the results (or errors) back through the MCP protocol.

## Typical Workflow

1.  Ensure you have logged in via `esp-rainmaker-cli login` in your terminal.
2.  Start your MCP client configured with this server.
3.  Use the `check_login_status` tool in the MCP client to verify the connection.
4.  Use tools like `get_nodes`, `get_params`, and `set_params` to interact with your devices.

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.
