#!/usr/bin/env python3

import asyncio
import base64
import json
import os
import sys
from email.header import decode_header
from typing import Any, Dict, List

import httpx
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("gmail")

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Add a global variable to hold the service instance
gmail_service = None


def decode_mime_header(header: str) -> str:
    """Helper function to decode encoded email headers"""
    decoded_parts = decode_header(header)
    decoded_string = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            # Decode bytes to string using the specified encoding
            decoded_string += part.decode(encoding or "utf-8")
        else:
            # Already a string
            decoded_string += part
    return decoded_string


class GmailService:
    def __init__(self, creds_file_path, token_path):
        self.creds_file_path = creds_file_path
        self.token_path = token_path
        self.token = self._get_token()
        self.service = self._get_service()
        self.user_email = self._get_user_email()

    def _get_token(self) -> Credentials:
        """Get or refresh Google API token"""
        token = None

        if os.path.exists(self.token_path):
            token = Credentials.from_authorized_user_file(self.token_path, SCOPES)

        if not token or not token.valid:
            if token and token.expired and token.refresh_token:
                token.refresh(Request())
            else:
                try:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.creds_file_path, SCOPES
                    )
                    token = flow.run_local_server(port=0)
                except FileNotFoundError:
                    error_msg = f"Credentials file not found at: {self.creds_file_path}"
                    raise FileNotFoundError(error_msg)

            with open(self.token_path, "w") as token_file:
                token_file.write(token.to_json())

        return token

    def _get_service(self) -> any:
        """Initialize Gmail API service"""
        try:
            service = build("gmail", "v1", credentials=self.token)
            return service
        except HttpError as error:
            raise ValueError(f"An error occurred: {error}")

    def _get_user_email(self) -> str:
        """Get user email address"""
        profile = self.service.users().getProfile(userId="me").execute()
        user_email = profile.get("emailAddress", "")
        return user_email

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
                # Check if we've reached the max results
                if max_results and len(messages) >= max_results:
                    break

                page_token = response["nextPageToken"]
                response = await asyncio.to_thread(
                    self.service.users()
                    .messages()
                    .list(userId=user_id, q=query, pageToken=page_token)
                    .execute
                )

                if "messages" in response:
                    messages.extend(response["messages"])

            # Return all messages or limit to max_results if specified
            if max_results:
                return messages[:max_results]
            return messages
        except Exception:
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

        except Exception:
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

        for i, msg in enumerate(messages):
            msg_details = await self.get_message(msg_id=msg["id"])
            if msg_details:
                results.append(msg_details)

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

        return f"Saved {len(emails)} emails to {filename}"


@mcp.tool()
async def search_emails(
    search_type: str, search_value: str, max_results: int = 10
) -> str:
    """Search for emails based on different criteria.

    Args:
        search_type: Type of search (keyword, to, from)
        search_value: Value to search for
        max_results: Maximum number of results to return
    """
    global gmail_service  # Add this to access the global instance
    if not gmail_service:
        return "Error: Gmail service not initialized"

    if not search_value:
        return "Error: Missing search value"

    results = await gmail_service.search_email(search_type, search_value, max_results)

    return json.dumps(
        {
            "message": f"Found {len(results)} emails matching your search",
            "results": results,
        }
    )


@mcp.tool()
async def list_messages(query: str = "", max_results: int = 10) -> str:
    """List messages from Gmail inbox.

    Args:
        query: Query string to filter messages
        max_results: Maximum number of results to return
    """
    global gmail_service  # Add this to access the global instance
    if not gmail_service:
        return "Error: Gmail service not initialized"

    messages = await gmail_service.list_messages(query=query, max_results=max_results)

    return json.dumps(
        {"message": f"Retrieved {len(messages)} messages", "messages": messages}
    )


@mcp.tool()
async def get_message(msg_id: str) -> str:
    """Get details of a specific message.

    Args:
        msg_id: Message ID to retrieve
    """
    global gmail_service  # Add this to access the global instance
    if not gmail_service:
        return "Error: Gmail service not initialized"

    if not msg_id:
        return "Error: Missing message ID"

    message = await gmail_service.get_message(msg_id=msg_id)

    if not message:
        return "Error: Could not retrieve message"

    return json.dumps({"message": "Retrieved message details", "details": message})


@mcp.tool()
async def save_emails(
    emails: List[Dict[str, Any]], filename: str = "email_results.txt"
) -> str:
    """Save search results to a file.

    Args:
        emails: List of email objects to save
        filename: Filename to save results to
    """
    global gmail_service  # Add this to access the global instance
    if not gmail_service:
        return "Error: Gmail service not initialized"

    if not emails:
        return "Error: No emails provided to save"

    result = gmail_service.save_emails_to_file(emails, filename)

    return result


def main():
    # Get credentials paths from environment variables
    if "GMAIL_CREDS_PATH" not in os.environ:
        print(
            "Error: GMAIL_CREDS_PATH environment variable is not set", file=sys.stderr
        )
        sys.exit(1)

    if "GMAIL_TOKEN_PATH" not in os.environ:
        print(
            "Error: GMAIL_TOKEN_PATH environment variable is not set", file=sys.stderr
        )
        sys.exit(1)

    creds_path = os.environ["GMAIL_CREDS_PATH"]
    token_path = os.environ["GMAIL_TOKEN_PATH"]

    # Ensure paths are absolute
    creds_path = os.path.abspath(creds_path)
    token_path = os.path.abspath(token_path)

    # Initialize Gmail service with proper credentials
    global gmail_service
    gmail_service = GmailService(creds_path, token_path)

    # Run the server
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
