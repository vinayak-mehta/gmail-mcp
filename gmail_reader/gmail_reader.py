#!/usr/bin/env python3

import argparse
import base64
import email
import json
import os
import sys

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def get_gmail_service():
    """Shows basic usage of the Gmail API.
    Returns a Gmail API service object.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_info(
            json.loads(open("token.json", "r").read())
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
                print("Error: credentials.json file not found!")
                print(
                    "Please follow the setup instructions in the README to get your credentials.json file."
                )
                sys.exit(1)

        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def list_messages(service, user_id="me", query="", max_results=None):
    """List all Messages of the user's mailbox matching the query.

    Args:
        service: Authorized Gmail API service instance.
        user_id: User's email address. The special value "me"
        can be used to indicate the authenticated user.
        query: String used to filter messages returned.
        max_results: Maximum number of results to return.
                    If None, returns all messages.

    Returns:
        List of Messages that match the criteria of the query. Note that the
        returned list contains Message IDs, you must use get with the
        appropriate ID to get the details of a Message.
    """
    try:
        response = service.users().messages().list(userId=user_id, q=query).execute()
        messages = []
        if "messages" in response:
            messages.extend(response["messages"])

        # Continue fetching messages until there are no more page tokens
        # or we've reached the max_results limit
        while "nextPageToken" in response:
            # Print progress
            print(f"Retrieved {len(messages)} messages so far...", end="\r")

            # Check if we've reached the max results
            if max_results and len(messages) >= max_results:
                break

            page_token = response["nextPageToken"]
            response = (
                service.users()
                .messages()
                .list(userId=user_id, q=query, pageToken=page_token)
                .execute()
            )
            if "messages" in response:
                messages.extend(response["messages"])

        print(f"Total messages retrieved: {len(messages)}          ")

        # Return all messages or limit to max_results if specified
        if max_results:
            return messages[:max_results]
        return messages
    except Exception as e:
        print(f"An error occurred: {e}")
        return []


def get_message(service, user_id="me", msg_id=""):
    """Get a Message with given ID.

    Args:
        service: Authorized Gmail API service instance.
        user_id: User's email address. The special value "me"
        can be used to indicate the authenticated user.
        msg_id: The ID of the Message required.

    Returns:
        A Message.
    """
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id).execute()

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
        body = get_message_body(parts)

        return {
            "id": msg_id,
            "subject": subject,
            "sender": sender,
            "body": body,
            "snippet": message["snippet"],
        }

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def get_message_body(parts):
    """Get the body of the email message."""
    body = ""

    if not parts:
        return body

    for part in parts:
        if part.get("parts"):
            # If this part has subparts, recursively get their content
            body += get_message_body(part.get("parts", []))

        if part.get("body") and part.get("body").get("data"):
            data = part["body"]["data"]
            # Decode the base64url encoded data
            decoded_bytes = base64.urlsafe_b64decode(data)
            # If it's text, decode to a string
            if part.get("mimeType", "").startswith("text/"):
                body += decoded_bytes.decode("utf-8")

    return body


def search_email(service, search_type, search_value, max_results=None):
    """
    Search for emails based on different criteria.

    Args:
        service: Authorized Gmail API service instance.
        search_type: Type of search ('keyword', 'to', 'from').
        search_value: The value to search for.
        max_results: Maximum number of results to return.
                    If None, returns all matching emails.

    Returns:
        List of matching email details.
    """
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
    messages = list_messages(service, query=query, max_results=max_results)

    # Get details for each message
    results = []
    total_messages = len(messages)

    print(f"Retrieving details for {total_messages} emails...")
    for i, msg in enumerate(messages):
        # Show progress
        if i % 10 == 0:
            print(f"Processing email {i+1}/{total_messages}...", end="\r")

        msg_details = get_message(service, msg_id=msg["id"])
        if msg_details:
            results.append(msg_details)

    print(f"Retrieved details for {len(results)} emails.          ")

    return results


def save_emails_to_file(emails, filename):
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

    print(f"Saved {len(emails)} emails to {filename}")


def run_search(service, args):
    """Run the search based on command-line arguments."""
    results = []

    if args.search_type == "all":
        print("Retrieving all emails...")
        messages = list_messages(service, max_results=args.max_results)

        # Show sample of results
        sample_size = min(5, len(messages))
        print(f"Found {len(messages)} emails. Showing first {sample_size} as preview:")

        for i, msg in enumerate(messages[:sample_size]):
            msg_details = get_message(service, msg_id=msg["id"])
            if msg_details:
                results.append(msg_details)
                print(f"From: {msg_details['sender']}")
                print(f"Subject: {msg_details['subject']}")
                print("-" * 50)

        # Ask if user wants to retrieve all message details
        if len(messages) > sample_size:
            answer = input(
                "Retrieve details for all emails? This may take a while. (y/n): "
            )
            if answer.lower() == "y":
                for i, msg in enumerate(messages[sample_size:]):
                    if i % 10 == 0:
                        print(
                            f"Processing email {i+sample_size+1}/{len(messages)}...",
                            end="\r",
                        )
                    msg_details = get_message(service, msg_id=msg["id"])
                    if msg_details:
                        results.append(msg_details)
    else:
        # For keyword, to, from searches
        print(f"Searching for {args.search_type}: '{args.search_value}'...")
        results = search_email(
            service, args.search_type, args.search_value, max_results=args.max_results
        )

        print(f"Found {len(results)} matching emails")
        for i, result in enumerate(results[:5]):  # Show first 5
            print(f"From: {result['sender']}")
            print(f"Subject: {result['subject']}")
            print("-" * 50)

    return results


def cli_main():
    """Command-line interface entry point."""
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Gmail Email Reader")
    parser.add_argument(
        "search_type",
        choices=["keyword", "to", "from", "all"],
        help="Type of search to perform",
    )
    parser.add_argument(
        "search_value",
        nargs="?",
        help="Value to search for (required for keyword, to, from)",
    )
    parser.add_argument(
        "--max",
        type=int,
        dest="max_results",
        help="Maximum number of results to return",
    )
    parser.add_argument(
        "--save", dest="save_file", help="Save results to specified file"
    )

    args = parser.parse_args()

    # Check if search_value is provided when needed
    if args.search_type != "all" and not args.search_value:
        parser.error(f"search_value is required for search_type '{args.search_type}'")

    try:
        # Get the Gmail service
        service = get_gmail_service()

        # Perform the search
        results = run_search(service, args)

        # Save results to file if requested
        if args.save_file and results:
            save_emails_to_file(results, args.save_file)

    except KeyboardInterrupt:
        print("\nOperation canceled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli_main()
