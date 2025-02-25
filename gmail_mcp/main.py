#!/usr/bin/env python3

import argparse
import base64
import email
import json
import os
import sys
import logging
import asyncio
from email.message import EmailMessage

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly",
          "https://www.googleapis.com/auth/gmail.modify"]

EMAIL_ASSISTANT_PROMPTS = """You are a Gmail assistant.
You can help with searching, reading, and managing emails.
You have the following tools available:
- Search emails (search-emails)
- List recent emails (list-messages)
- Get message details (get-message)
- Save emails to file (save-emails)

Always handle email data with care and respect user privacy.
"""

# Define available prompts
PROMPTS = {
    "gmail-assistant": types.Prompt(
        name="gmail-assistant",
        description="Act as a Gmail assistant to help search and manage emails",
        arguments=None,
    ),
    "search-emails": types.Prompt(
        name="search-emails",
        description="Search for emails based on criteria",
        arguments=[
            types.PromptArgument(
                name="query",
                description="Search query string",
                required=True
            ),
            types.PromptArgument(
                name="max_results",
                description="Maximum number of results to return",
                required=False
            ),
        ],
    ),
}

class GmailService:
    def __init__(self, token_path="token.json"):
        logger.info(f"Initializing GmailService with token path: {token_path}")
        self.token_path = token_path
        self.service = self._get_gmail_service()
        logger.info("Gmail service initialized")

    def _get_gmail_service(self):
        """Initialize Gmail API service"""
        creds = None

        # The file token.json stores the user's access and refresh tokens
        if os.path.exists(self.token_path):
            creds = Credentials.from_authorized_user_info(
                json.loads(open(self.token_path, "r").read())
            )

        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                try:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        "credentials.json", SCOPES
                    )
                    creds = flow.run_local_server(port=0)
                except FileNotFoundError:
                    logger.error("Error: credentials.json file not found!")
                    print(
                        "Please follow the setup instructions in the README to get your credentials.json file."
                    )
                    sys.exit(1)

            # Save the credentials for the next run
            with open(self.token_path, "w") as token:
                token.write(creds.to_json())

        return build("gmail", "v1", credentials=creds)

    async def list_messages(self, user_id="me", query="", max_results=None):
        """List all Messages of the user's mailbox matching the query."""
        try:
            response = await asyncio.to_thread(
                self.service.users().messages().list(userId=user_id, q=query).execute
            )
            messages = []
            if "messages" in response:
                messages.extend(response["messages"])

            # Continue fetching messages until there are no more page tokens
            # or we've reached the max_results limit
            while "nextPageToken" in response:
                # Print progress
                logger.info(f"Retrieved {len(messages)} messages so far...")

                # Check if we've reached the max results
                if max_results and len(messages) >= max_results:
                    break

                page_token = response["nextPageToken"]
                response = await asyncio.to_thread(
                    self.service.users().messages().list(
                        userId=user_id, q=query, pageToken=page_token
                    ).execute
                )

                if "messages" in response:
                    messages.extend(response["messages"])

            logger.info(f"Total messages retrieved: {len(messages)}")

            # Return all messages or limit to max_results if specified
            if max_results:
                return messages[:max_results]
            return messages
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return []

    async def get_message(self, user_id="me", msg_id=""):
        """Get a Message with given ID."""
        try:
            message = await asyncio.to_thread(
                self.service.users().messages().get(userId=user_id, id=msg_id).execute
            )

            # Get email parts
            payload = message["payload"]
            headers = payload["headers"]

            # Look for Subject and Sender
            subject = ""
            sender = ""
            for header in headers:
                if header["name"] == "Subject":
                    subject = header["value"]
                if header["name"] == "From":
                    sender = header["value"]

            # The Body of the message
            parts = payload.get("parts", [])
            body = self._get_message_body(parts)

            return {
                "id": msg_id,
                "subject": subject,
                "sender": sender,
                "body": body,
                "snippet": message["snippet"],
            }

        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return None

    def _get_message_body(self, parts):
        """Get the body of the email message."""
        body = ""

        if not parts:
            return body

        for part in parts:
            if part.get("parts"):
                # If this part has subparts, recursively get their content
                body += self._get_message_body(part.get("parts", []))

            if part.get("body") and part.get("body").get("data"):
                data = part["body"]["data"]
                # Decode the base64url encoded data
                decoded_bytes = base64.urlsafe_b64decode(data)
                # If it's text, decode to a string
                if part.get("mimeType", "").startswith("text/"):
                    body += decoded_bytes.decode("utf-8")

        return body

    async def search_email(self, search_type, search_value, max_results=None):
        """Search for emails based on different criteria."""
        query = ""

        if search_type == "keyword":
            # Search for emails containing the keyword in subject or body
            query = f"{search_value}"
        elif search_type == "to":
            # Search for emails sent to a specific recipient
            query = f"to:{search_value}"
        elif search_type == "from":
            # Search for emails from a specific sender
            query = f"from:{search_value}"

        # Get messages that match the query
        messages = await self.list_messages(query=query, max_results=max_results)

        # Get details for each message
        results = []
        total_messages = len(messages)

        logger.info(f"Retrieving details for {total_messages} emails...")
        for i, msg in enumerate(messages):
            # Show progress
            if i % 10 == 0:
                logger.info(f"Processing email {i+1}/{total_messages}...")

            msg_details = await self.get_message(msg_id=msg["id"])
            if msg_details:
                results.append(msg_details)

        logger.info(f"Retrieved details for {len(results)} emails.")

        return results

    def save_emails_to_file(self, emails, filename):
        """Save email search results to a file."""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Total emails: {len(emails)}\n\n")
            for i, email in enumerate(emails):
                f.write(f"Email #{i+1}\n")
                f.write(f"From: {email['sender']}\n")
                f.write(f"Subject: {email['subject']}\n")
                f.write(f"Snippet: {email['snippet']}\n")
                if "body" in email and email["body"]:
                    f.write(f"Body: {email['body'][:500]}...\n")  # Truncate long bodies
                f.write("-" * 50 + "\n\n")

        logger.info(f"Saved {len(emails)} emails to {filename}")
        return f"Saved {len(emails)} emails to {filename}"

async def main(token_path="token.json"):

    gmail_service = GmailService(token_path)
    server = Server("gmail")

    @server.list_prompts()
    async def list_prompts() -> list[types.Prompt]:
        return list(PROMPTS.values())

    @server.get_prompt()
    async def get_prompt(
        name: str, arguments: dict[str, str] | None = None
    ) -> types.GetPromptResult:
        if name not in PROMPTS:
            raise ValueError(f"Prompt not found: {name}")

        if name == "gmail-assistant":
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=EMAIL_ASSISTANT_PROMPTS,
                        )
                    )
                ]
            )

        if name == "search-emails":
            query = arguments.get("query", "")
            max_results = arguments.get("max_results", "10")

            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""Please search for emails with the query: {query}
                            Limit results to: {max_results} emails.

                            Use the search-emails tool to perform this search."""
                        )
                    )
                ]
            )

        raise ValueError("Prompt implementation not found")

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="search-emails",
                description="Search for emails based on different criteria",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "search_type": {
                            "type": "string",
                            "description": "Type of search (keyword, to, from)",
                        },
                        "search_value": {
                            "type": "string",
                            "description": "Value to search for",
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of results to return",
                        },
                    },
                    "required": ["search_type", "search_value"],
                },
            ),
            types.Tool(
                name="list-messages",
                description="List messages from Gmail inbox",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Query string to filter messages",
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of results to return",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="get-message",
                description="Get details of a specific message",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "msg_id": {
                            "type": "string",
                            "description": "Message ID to retrieve",
                        },
                    },
                    "required": ["msg_id"],
                },
            ),
            types.Tool(
                name="save-emails",
                description="Save search results to a file",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "emails": {
                            "type": "array",
                            "description": "List of email objects to save",
                        },
                        "filename": {
                            "type": "string",
                            "description": "Filename to save results to",
                        },
                    },
                    "required": ["emails", "filename"],
                },
            ),
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:

        if name == "search-emails":
            search_type = arguments.get("search_type", "keyword")
            search_value = arguments.get("search_value", "")
            max_results = arguments.get("max_results", None)

            if not search_value:
                raise ValueError("Missing search_value parameter")

            results = await gmail_service.search_email(search_type, search_value, max_results)

            return [types.TextContent(
                type="text",
                text=f"Found {len(results)} emails matching your search",
                artifact={"type": "json", "data": results}
            )]

        if name == "list-messages":
            query = arguments.get("query", "")
            max_results = arguments.get("max_results", None)

            messages = await gmail_service.list_messages(query=query, max_results=max_results)

            return [types.TextContent(
                type="text",
                text=f"Retrieved {len(messages)} messages",
                artifact={"type": "json", "data": messages}
            )]

        if name == "get-message":
            msg_id = arguments.get("msg_id")
            if not msg_id:
                raise ValueError("Missing msg_id parameter")

            message = await gmail_service.get_message(msg_id=msg_id)

            return [types.TextContent(
                type="text",
                text="Retrieved message details",
                artifact={"type": "json", "data": message}
            )]

        if name == "save-emails":
            emails = arguments.get("emails", [])
            filename = arguments.get("filename", "email_results.txt")

            if not emails:
                raise ValueError("Missing emails parameter")

            result = gmail_service.save_emails_to_file(emails, filename)

            return [types.TextContent(type="text", text=result)]

        else:
            logger.error(f"Unknown tool: {name}")
            raise ValueError(f"Unknown tool: {name}")

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="gmail",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Gmail MCP Server')
    parser.add_argument('--token-path',
                       default="token.json",
                       help='File location to store and retrieve access token')

    args = parser.parse_args()
    asyncio.run(main(args.token_path))
