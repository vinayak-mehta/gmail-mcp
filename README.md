# Gmail Reader MCP

A command-line program to read and search emails from your Gmail account.

## Features

- Retrieve all emails from your Gmail account
- Search emails by keyword
- Search emails sent to a specific recipient
- Search emails from a specific sender
- Save search results to file
- Progress tracking for large email collections

## Setup Instructions

### 1. Create a Google Cloud Project and Enable Gmail API

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Click "Create Project" or select an existing project
3. In the search bar at the top, type "Gmail API" and select it from the results
4. Click "Enable" to activate the Gmail API for your project

### 2. Create OAuth 2.0 Credentials

1. In your Google Cloud project, navigate to "APIs & Services" > "Credentials" in the left sidebar
2. Click "Create Credentials" button and select "OAuth client ID"
3. If prompted, configure the OAuth consent screen:
   - Choose "External" as the User Type if you don't have a Google Workspace account
   - Fill in the required fields (App name, User support email, Developer email)
   - Add the Gmail API with ../auth/gmail.readonly scope
   - Add your email as a test user
   - Save and continue
4. Go back to "Create OAuth client ID":
   - Select "Desktop application" as the Application type
   - Give your client a name
   - Click "Create"
5. Download the JSON file with your credentials
6. Rename the downloaded file to `credentials.json`

### 3. Install the Package with uv in Claude Desktop App

#### Prerequisites
- [uv](https://github.com/astral-sh/uv) - Fast Python package installer and resolver
- Python 3.7 or higher

#### Installation Steps

1. Clone the repository:
```bash
git clone https://github.com/yourusername/gmail-reader-mcp.git
cd gmail-reader-mcp
```

2. Install the package using uv:
```bash
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e .
```

3. Place your `credentials.json` file in the project's root directory.

## Usage

```bash
# Get ALL emails
gmail-reader all

# Search for emails with keyword
gmail-reader keyword "important meeting"

# Search for emails from a specific sender
gmail-reader from "boss@company.com"

# Search for emails you've sent to someone
gmail-reader to "colleague@example.com"

# Limit results and save to file
gmail-reader keyword "meeting" --max 100 --save meeting_emails.txt
```

## First-Time Authentication

The first time you run the program, it will:

1. Open a browser window
2. Ask you to log in to your Google account
3. Request permission to access your Gmail account
4. After granting permission, you'll see an "Authentication successful" message
5. The program will save a token file for future use

## Troubleshooting

### Token Issues
If you encounter authentication issues, delete the `token.json` file and restart the program to reauthenticate.

### Rate Limits
The Gmail API has usage limits. If you hit a rate limit, wait a while before trying again.

### Large Email Collections
For accounts with many emails, retrieving all emails might take a significant amount of time. Use the `--max` option to limit results during testing.

## License

MIT
