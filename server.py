import asyncio
import json
import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

# MCP Imports
from mcp.server.fastmcp import FastMCP, Context

# ESP Rainmaker CLI Library Imports
from rmaker_lib import session as rainmaker_session
from rmaker_lib import node as rainmaker_node
from rmaker_lib import configmanager as rainmaker_config

# Exceptions
from rmaker_lib.exceptions import (
    HttpErrorResponse,
    NetworkError,
    InvalidConfigError,
    InvalidUserError,
    ExpiredSessionError,
    AuthenticationError,
    InvalidJSONError,
    SSLError,
    RequestTimeoutError,
)

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger(__name__)


# --- Lifespan Management ---
@asynccontextmanager
async def rainmaker_lifespan(server: FastMCP) -> AsyncIterator[None]:
    log.info("Starting ESP RainMaker MCP Server...")
    try:
        config = rainmaker_config.Config()
        log.info(f"RainMaker config directory: {rainmaker_config.RM_USER_CONFIG_DIR_VALUE}")
        log.info(f"RainMaker config file: {rainmaker_config.CONFIG_FILE}")
        log.info(f"Using RainMaker region: {config.get_region()}")
    except Exception as e:
        log.warning(f"Initial config check failed: {e}")
    yield None
    log.info("ESP RainMaker MCP Server shutting down.")


# --- Initialize MCP Server ---
mcp = FastMCP("ESP-RainMaker-MCP", lifespan=rainmaker_lifespan, dependencies=["esp-rainmaker-cli"])


# --- Helper Function to Check Login State ---
async def ensure_login_session() -> rainmaker_session.Session:
    """
    Attempts to initialize a RainMaker session using stored credentials.
    Raises exceptions if not logged in or session cannot be refreshed.
    """
    try:
        # Creating a Session object implicitly uses configmanager to get/refresh tokens
        # Use asyncio.to_thread as Session init can involve network calls for token refresh
        s = await asyncio.to_thread(rainmaker_session.Session)
        log.info("RainMaker session initialized successfully.")
        return s
    except (InvalidUserError, ExpiredSessionError, InvalidConfigError) as e:
        log.warning(f"Login check failed: {type(e).__name__} - {e}")
        raise ValueError(
            "Login required. Please run the 'login_instructions' tool for steps on how to log in using the standard RainMaker CLI, then use 'check_login_status'."
        ) from e
    except (NetworkError, SSLError, RequestTimeoutError) as e:
        log.error(f"Network/SSL error during session init: {e}")
        raise ConnectionError(f"Failed to connect to RainMaker API: {e}") from e
    except Exception as e:
        log.exception("Unexpected error during session initialization.")
        raise RuntimeError(f"An unexpected error occurred during login check: {e}") from e


# --- Tools Implementation ---


@mcp.tool()
async def login_instructions() -> str:
    """
    Provides instructions (formatted with Markdown) on how to log in
    using the standard ESP RainMaker CLI.
    This server relies on credentials saved locally by that process.
    Rendering as Markdown depends on the MCP client capabilities.
    """
    log.info("Providing login instructions (with Markdown).")
    try:
        # Run synchronous config calls in a thread
        # Using await asyncio.to_thread ensures we don't block the event loop
        config = await asyncio.to_thread(rainmaker_config.Config)
        login_url_base = await asyncio.to_thread(config.get_login_url)
        config_file_path = rainmaker_config.CONFIG_FILE
    except Exception as e:
        log.error(f"Error getting config for login instructions: {e}")
        # Provide placeholders if config loading fails
        login_url_base = "[Could not determine login URL]"
        config_file_path = "[Could not determine config path]"

    # Construct the message using Markdown syntax
    # Use f-string for cleaner variable insertion
    return f"""## ESP RainMaker Login Instructions

This MCP server uses the secure browser-based login flow provided by the official `esp-rainmaker-cli`.
Because this involves opening your browser and requires a temporary local webserver for the redirect, **it must be initiated from your own terminal**, not directly from this server.

**Steps:**

1.  Open a terminal or command prompt on your computer and navigate to `esp-rainmaker-mcp`.
2.  Run the command: `uv run esp-rainmaker-cli login`
3.  Your web browser should open automatically to the ESP RainMaker login page (URL starts with: `{login_url_base}`).
4.  Log in with your credentials (or sign up if needed).
5.  After successful login in the browser, you should see a "Login successful" message in your terminal.
6.  The CLI saves your session credentials locally (typically in `{config_file_path}`).
7.  Come back here and run the `check_login_status` tool to confirm the session is active for this server.
"""


@mcp.tool()
async def check_login_status(ctx: Context) -> str:
    """Checks if a valid login session exists based on stored credentials."""
    log.info("Checking login status.")
    try:
        # Attempt to create a session using stored credentials
        s = await ensure_login_session()
        # If session creation succeeded, try to get username for confirmation
        try:
            config = await asyncio.to_thread(rainmaker_config.Config)
            user_name = await asyncio.to_thread(config.get_user_name)
            log.info(f"Login status check successful for user: {user_name}")
            return f"Login session is active for user: {user_name}"
        except Exception as e_inner:
            # Handle cases where session is technically valid but getting username fails
            log.warning(f"Session check passed but error getting username: {e_inner}")
            return f"Login session seems active, but could not retrieve username. Try other commands. Error: {e_inner}"

    except ValueError as e:  # From ensure_login_session if not logged in
        return str(e)
    except ConnectionError as e:  # From ensure_login_session
        return f"Connection Error: {e}"
    except RuntimeError as e:  # From ensure_login_session
        return f"Runtime Error during login check: {e}"
    except Exception as e:  # Catch any other unexpected errors
        log.exception("Unexpected error during login status check.")
        return f"An unexpected error occurred during login check: {str(e)}"


@mcp.tool()
async def logout(ctx: Context) -> str:
    """
    Logout the current user from ESP RainMaker via API and clear local credentials.
    Use this if you explicitly want to end the session saved by 'esp-rainmaker-cli login'.
    """
    log.info("Attempting explicit logout.")
    api_logout_success = False
    api_logout_error_msg = ""

    try:
        # Check if we are logged in and get session for API call
        s = await ensure_login_session()
        # Perform API logout
        await asyncio.to_thread(s.logout)
        log.info("RainMaker API logout successful.")
        api_logout_success = True
    except ValueError:
        # Not logged in initially, no API call needed.
        log.info("Not logged in, skipping API logout call.")
        api_logout_success = True  # Consider it success as the goal is to be logged out
    except HttpErrorResponse as e:
        log.error(f"HTTP error during API logout: {e}")
        api_logout_error_msg = f"API logout failed: {e}. "
    except (NetworkError, SSLError, RequestTimeoutError) as e:
        log.error(f"Network/SSL error during API logout: {e}")
        api_logout_error_msg = f"API logout connection failed: {e}. "
    except Exception as e:
        log.exception("Unexpected error during API logout.")
        api_logout_error_msg = f"Unexpected API logout error: {e}. "

    # Attempt to clear local credentials
    try:
        config = await asyncio.to_thread(rainmaker_config.Config)
        creds_exist = await asyncio.to_thread(config.check_user_creds_exists)
        if creds_exist:
            removed = await asyncio.to_thread(config.remove_curr_login_creds)
            if removed:
                log.info("Local credentials cleared successfully.")
                final_message = api_logout_error_msg + "Local session credentials cleared."
                return final_message.strip()
            else:
                log.warning("Failed to clear local credentials file.")
                return (
                    api_logout_error_msg + "Logout completed, but encountered an issue clearing the local session file."
                ).strip()
        else:
            log.info("No local credentials file found to clear.")
            return (
                api_logout_error_msg + "Logout completed (or already logged out). No local credentials file found."
            ).strip()

    except Exception as e:
        log.exception("Error clearing local credentials during logout.")
        return (api_logout_error_msg + f"Logout partially failed: error clearing local session file - {str(e)}").strip()


@mcp.tool()
async def get_nodes(ctx: Context) -> list[str] | str:
    """List all node IDs associated with the logged-in user."""
    log.info("Fetching node list.")
    try:
        s = await ensure_login_session()
        nodes_dict = await asyncio.to_thread(s.get_nodes)
        node_ids = list(nodes_dict.keys())
        log.info(f"Found {len(node_ids)} nodes.")
        if not node_ids:
            return "No nodes found for this user."
        return node_ids
    except (ValueError, ConnectionError, RuntimeError) as e:  # From ensure_login_session
        return str(e)
    except HttpErrorResponse as e:
        log.error(f"HTTP error getting nodes: {e}")
        return f"Error getting nodes: API error - {e}"
    # Network/SSL errors should be caught by ensure_login_session primarily
    except Exception as e:
        log.exception("Unexpected error getting nodes.")
        return f"Error getting nodes: An unexpected error occurred - {str(e)}"


@mcp.tool()
async def get_node_config(ctx: Context, node_id: str) -> dict | str:
    """Get the configuration details for a specific node."""
    log.info(f"Fetching configuration for node: {node_id}")
    try:
        s = await ensure_login_session()
        n = await asyncio.to_thread(rainmaker_node.Node, node_id, s)
        config_data = await asyncio.to_thread(n.get_node_config)
        log.info(f"Successfully fetched config for node: {node_id}")
        return config_data
    except (ValueError, ConnectionError, RuntimeError) as e:  # From ensure_login_session
        return str(e)
    except HttpErrorResponse as e:
        log.error(f"HTTP error getting config for node {node_id}: {e}")
        return f"Error getting config for node {node_id}: API error - {e}"
    except Exception as e:
        log.exception(f"Unexpected error getting config for node {node_id}.")
        return f"Error getting config for node {node_id}: An unexpected error occurred - {str(e)}"


@mcp.tool()
async def get_node_status(ctx: Context, node_id: str) -> dict | str:
    """Get the online/offline status for a specific node."""
    log.info(f"Fetching status for node: {node_id}")
    try:
        s = await ensure_login_session()
        n = await asyncio.to_thread(rainmaker_node.Node, node_id, s)
        status_data = await asyncio.to_thread(n.get_node_status)
        log.info(f"Successfully fetched status for node: {node_id}")
        return status_data
    except (ValueError, ConnectionError, RuntimeError) as e:  # From ensure_login_session
        return str(e)
    except HttpErrorResponse as e:
        log.error(f"HTTP error getting status for node {node_id}: {e}")
        return f"Error getting status for node {node_id}: API error - {e}"
    except Exception as e:
        log.exception(f"Unexpected error getting status for node {node_id}.")
        return f"Error getting status for node {node_id}: An unexpected error occurred - {str(e)}"


@mcp.tool()
async def get_params(ctx: Context, node_id: str) -> dict | str:
    """Get the current parameters (state) for a specific node."""
    log.info(f"Fetching parameters for node: {node_id}")
    try:
        s = await ensure_login_session()
        n = await asyncio.to_thread(rainmaker_node.Node, node_id, s)
        params_data = await asyncio.to_thread(n.get_node_params)
        if params_data is None:
            log.warning(f"get_node_params returned None for node {node_id}")
            return f"Error: Failed to retrieve parameters for node {node_id}. Node might be offline or an API error occurred."
        log.info(f"Successfully fetched parameters for node: {node_id}")
        return params_data
    except (ValueError, ConnectionError, RuntimeError) as e:  # From ensure_login_session
        return str(e)
    except HttpErrorResponse as e:
        log.error(f"HTTP error getting params for node {node_id}: {e}")
        return f"Error getting parameters for node {node_id}: API error - {e}"
    except Exception as e:
        log.exception(f"Unexpected error getting params for node {node_id}.")
        return f"Error getting parameters for node {node_id}: An unexpected error occurred - {str(e)}"


@mcp.tool()
async def set_params(ctx: Context, node_id: str, params_dict: dict) -> str:
    """
    Set parameters for a specific node using a JSON object (dictionary).
    Example params_dict value:
    {'Thermostat': {'Power': False}}
    Provide this structure as JSON input in the MCP client.
    """
    log.info(f"Attempting to set parameters for node: {node_id}")
    log.debug(f"Received params dictionary: {params_dict}")

    if not isinstance(params_dict, dict) or not params_dict:
        log.warning(f"Invalid or empty params_dict provided: {params_dict}")
        return "Error: Parameter data must be a non-empty JSON object (dictionary)."

    try:
        s = await ensure_login_session()
        n = await asyncio.to_thread(rainmaker_node.Node, node_id, s)
        success = await asyncio.to_thread(n.set_node_params, params_dict)

        if success:
            log.info(f"Successfully set parameters for node: {node_id}")
            return f"Parameters successfully updated for node {node_id}."
        else:
            log.warning(f"set_node_params returned False for node {node_id}")
            return f"Error: Failed to set parameters for node {node_id}. The RainMaker API call did not succeed (check node status and parameters)."

    except (ValueError, ConnectionError, RuntimeError) as e:  # From ensure_login_session
        return str(e)
    except HttpErrorResponse as e:
        log.error(f"HTTP error setting params for node {node_id}: {e}")
        return f"Error setting parameters for node {node_id}: API error - {e}"
    except Exception as e:
        log.exception(f"Unexpected error setting params for node {node_id}.")
        return f"Error setting parameters for node {node_id}: An unexpected error occurred - {str(e)}"
