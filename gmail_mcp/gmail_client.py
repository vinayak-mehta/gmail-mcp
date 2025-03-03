import base64
import os
from email.header import decode_header
from typing import Any, Dict, List, Optional

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


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


class GmailClient:
    def __init__(self, creds_file_path: str, token_path: str):
        self.creds_file_path = creds_file_path
        self.token_path = token_path
        self.token = None
        self.service = None
        self.user_email = None

    @classmethod
    def create(cls, creds_file_path: str, token_path: str) -> "GmailClient":
        """Factory method to create and initialize a GmailClient instance"""
        client = cls(creds_file_path, token_path)
        client.initialize()
        return client

    @classmethod
    def authorize(cls, creds_file_path: str, token_path: str) -> None:
        """Run the authorization flow and save the token"""
        if not os.path.exists(creds_file_path):
            raise FileNotFoundError(f"Credentials file not found at: {creds_file_path}")

        try:
            flow = InstalledAppFlow.from_client_secrets_file(creds_file_path, SCOPES)
            token = flow.run_local_server(port=0)

            # Save the token
            with open(token_path, "w") as token_file:
                token_file.write(token.to_json())

            print(f"Successfully saved token to {token_path}")
        except Exception as e:
            raise Exception(f"Failed to authorize: {str(e)}")

    def initialize(self) -> None:
        """Initialize the Gmail client with credentials"""
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
                raise Exception(
                    "No valid token found. Please run 'gmail-mcp auth' first to authorize."
                )

        return token

    def _get_service(self) -> Any:
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

    def _get_message_body(self, parts: List[Dict[str, Any]]) -> str:
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

    def list_messages(
        self, user_id: str = "me", query: str = "", max_results: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """List all Messages of the user's mailbox matching the query."""
        try:
            response = (
                self.service.users().messages().list(userId=user_id, q=query).execute()
            )
            messages = []
            if "messages" in response:
                messages.extend(response["messages"])

            while "nextPageToken" in response:
                if max_results and len(messages) >= max_results:
                    break

                page_token = response["nextPageToken"]
                response = (
                    self.service.users()
                    .messages()
                    .list(userId=user_id, q=query, pageToken=page_token)
                    .execute()
                )

                if "messages" in response:
                    messages.extend(response["messages"])

            if max_results:
                return messages[:max_results]
            return messages
        except Exception:
            return []

    def get_message(
        self, user_id: str = "me", msg_id: str = ""
    ) -> Optional[Dict[str, Any]]:
        """Get a Message with given ID."""
        try:
            message = (
                self.service.users().messages().get(userId=user_id, id=msg_id).execute()
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
