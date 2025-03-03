#!/usr/bin/env python3

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from .gmail_client import GmailClient

# Find and load .env file
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    load_dotenv(env_path)
else:
    print(f"Warning: No .env file found at {env_path}", file=sys.stderr)

# Constants
DEFAULT_CREDS_PATH = "credentials.json"
DEFAULT_TOKEN_PATH = "token.json"

# Initialize FastMCP server
mcp = FastMCP("gmail")

# Initialize global client
gmail_client = None


def get_default_paths() -> Dict[str, str]:
    """Get default paths for credentials and token files.

    Returns:
        Dictionary containing default paths for credentials and token files
    """
    current_dir = os.getcwd()
    return {
        "creds": os.path.join(current_dir, DEFAULT_CREDS_PATH),
        "token": os.path.join(current_dir, DEFAULT_TOKEN_PATH),
    }


def validate_path(file_path: str) -> Optional[Path]:
    """Validate and normalize a file path.

    Args:
        file_path: The path to validate

    Returns:
        Path object if valid, None if invalid
    """
    try:
        path = Path(file_path).resolve()
        return path
    except Exception:
        return None


@mcp.tool()
async def search_emails(
    search_type: str,
    search_value: str,
    max_results: int = 10,
    page: int = 1,
) -> str:
    """Search for emails based on different criteria.

    Args:
        search_type: Type of search (keyword, to, from)
        search_value: Value to search for
        max_results: Maximum number of results to return per page
        page: Page number (1-based)
    """
    global gmail_client
    if not gmail_client:
        return "Error: Gmail client not initialized"

    if not search_value:
        return "Error: Missing search value"

    try:
        # Calculate offset based on page number
        offset = (page - 1) * max_results

        # Get all messages that match the query
        all_messages = gmail_client.list_messages(query=search_value)
        total_results = len(all_messages)

        # Slice messages for current page
        page_messages = all_messages[offset : offset + max_results]

        # Get only metadata for the current page
        results = []
        for msg in page_messages:
            msg_details = gmail_client.get_message(msg_id=msg["id"])
            if msg_details:
                # Only include metadata, not the full body
                results.append(
                    {
                        "id": msg_details["id"],
                        "subject": msg_details["subject"],
                        "sender": msg_details["sender"],
                        "snippet": msg_details["snippet"],
                    }
                )

        has_next = total_results > offset + max_results
        has_previous = page > 1

        return json.dumps(
            {
                "message": f"Found {total_results} emails matching your search (showing page {page})",
                "results": results,
                "pagination": {
                    "current_page": page,
                    "total_pages": (total_results + max_results - 1) // max_results,
                    "has_next": has_next,
                    "has_previous": has_previous,
                    "total_results": total_results,
                },
            }
        )
    except Exception as e:
        return f"Error: Failed to search emails - {str(e)}"


@mcp.tool()
async def get_email_content(msg_id: str) -> str:
    """Get the full content of a specific email.

    Args:
        msg_id: Message ID to retrieve
    """
    global gmail_client
    if not gmail_client:
        return "Error: Gmail client not initialized"

    if not msg_id:
        return "Error: Missing message ID"

    try:
        message = gmail_client.get_message(msg_id=msg_id)
        if not message:
            return "Error: Could not retrieve message"

        return json.dumps({"message": "Retrieved email content", "email": message})
    except Exception as e:
        return f"Error: Failed to get email content - {str(e)}"


@mcp.tool()
async def list_messages(query: str = "", max_results: int = 10) -> str:
    """List messages from Gmail inbox.

    Args:
        query: Query string to filter messages
        max_results: Maximum number of results to return
    """
    global gmail_client
    if not gmail_client:
        return "Error: Gmail client not initialized"

    try:
        messages = gmail_client.list_messages(query=query, max_results=max_results)
        return json.dumps(
            {"message": f"Retrieved {len(messages)} messages", "messages": messages}
        )
    except Exception as e:
        return f"Error: Failed to list messages - {str(e)}"


def initialize_client(creds_path: str, token_path: str) -> None:
    """Initialize the Gmail client.

    Args:
        creds_path: Path to the credentials file
        token_path: Path to the token file
    """
    global gmail_client
    try:
        gmail_client = GmailClient.create(creds_path, token_path)
    except Exception as e:
        print(f"Error initializing Gmail client: {str(e)}", file=sys.stderr)
        sys.exit(1)


def auth_command(creds_path: str, token_path: str) -> None:
    """Run the authorization flow.

    Args:
        creds_path: Path to the credentials file
        token_path: Path to the token file
    """
    try:
        GmailClient.authorize(creds_path, token_path)
    except Exception as e:
        print(f"Error during authorization: {str(e)}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Gmail MCP CLI")
    parser.add_argument(
        "--creds-path",
        help="Path to the credentials.json file",
        default=os.environ.get("GMAIL_CREDS_PATH"),
    )
    parser.add_argument(
        "--token-path",
        help="Path to the token.json file",
        default=os.environ.get("GMAIL_TOKEN_PATH"),
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["auth", "serve"],
        default="serve",
        help="Command to run (auth or serve)",
    )

    args = parser.parse_args()

    # Get default paths if not provided
    default_paths = get_default_paths()
    creds_path = args.creds_path or default_paths["creds"]
    token_path = args.token_path or default_paths["token"]

    # Validate paths
    if not validate_path(creds_path):
        print(f"Error: Invalid credentials path: {creds_path}", file=sys.stderr)
        sys.exit(1)

    if not validate_path(token_path):
        print(f"Error: Invalid token path: {token_path}", file=sys.stderr)
        sys.exit(1)

    if args.command == "auth":
        auth_command(creds_path, token_path)
    else:  # serve
        initialize_client(creds_path, token_path)
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
