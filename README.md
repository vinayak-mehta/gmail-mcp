# Gmail MCP

Allow Claude to search and retrieve emails from your Gmail account.

## Setup

### 1. Get Google API Credentials

1. Visit the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Gmail API for your project
   - Navigate to "APIs & Services" > "Library"
   - Search for "Gmail API" and enable it
4. Create OAuth credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Select "Desktop application" as the application type
   - Name your client and click "Create"
5. Download the credentials JSON file
6. Save it as `credentials.json` in your project directory

### 2. Authorize the Application

Run the authorization command to generate your token:

```bash
uv run gmail-mcp auth --creds-path credentials.json --token-path token.json
```

This will open a browser window where you'll need to log in to your Google account and grant the necessary permissions. After authorization, a `token.json` file will be created in your project directory.

## Configuring with Claude

Add the Gmail MCP server to your Claude configuration file:

```
{
  "mcpServers": {
    "gmail": {
      "args": [
        "--from",
        "git+https://github.com/vinayak-mehta/gmail-mcp",
        "gmail-mcp"
      ],
      "command": "/Users/username/.local/bin/uvx",
      "env": {
        "GMAIL_CREDS_PATH": "/Users/username/path/to/gmail-mcp/credentials.json",
        "GMAIL_TOKEN_PATH": "/Users/username/path/to/gmail-mcp/token.json"
      }
    }
  }
}
```

Make sure to:

- Replace `/Users/username/path/to/gmail-mcp` with your actual project path
- Adjust the `command` path to your installed `uvx` executable
- Provide correct paths to your `credentials.json` and `token.json` files

Claude will now have access to the following tools:

### 1. Search Emails

Search for emails in your Gmail account.

**Example prompt:**
"Search for all emails from example@gmail.com"

### 2. Get Email Content

Retrieve the full content of a specific email.

**Example prompt:**
"Show me the full content of the email with the subject 'Meeting Tomorrow'"

### 3. List Messages

List recent messages from your Gmail inbox.

**Example prompt:**
"List my 5 most recent emails"

## Environment Variables

You can configure the paths to your credentials and token files using environment variables:

- `GMAIL_CREDS_PATH`: Path to your credentials.json file
- `GMAIL_TOKEN_PATH`: Path to your token.json file

Create a `.env` file in the project root with these variables for easy configuration.
