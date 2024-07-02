# M365 Admin Center PowerShell Module Installer and Connector

## Overview

This PowerShell script automates the process of installing, updating, and connecting to various Microsoft 365 (M365) Admin Center modules. It's designed to simplify the setup process for M365 administrators and ensure that all necessary modules are up-to-date and properly connected.

## Features

- Checks for PowerShell version compatibility (requires PowerShell 5.1 or later)
- Verifies administrator privileges
- Installs and updates the following M365 admin modules:
  - ExchangeOnlineManagement
  - MSOnline
  - AzureADPreview
  - MSGRAPH
  - Microsoft.Graph.Intune
  - Microsoft.Graph.DeviceManagement
  - Microsoft.Graph.Compliance
  - Microsoft.Graph.Users
  - Microsoft.Graph.Groups
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Authentication
  - AIPService
- Removes conflicting AzureAD (non-preview) module if present
- Connects to various M365 services:
  - Exchange Online
  - Microsoft Online
  - Azure AD Preview
  - MG Graph
  - Azure Information Protection
  - Information Protection Service
  - MS Graph (Old School)
- Provides detailed error handling and reporting
- Generates summary reports for module installation/update and connection status

## Usage

1. Run PowerShell as an administrator
2. Execute the script
3. Follow the prompts to install/update modules and connect to services
4. Review the summary reports at the end of the execution

## Requirements

- PowerShell 5.1 or later
- Administrator privileges
- Internet connection
- Valid M365 Global Admin credentials

## Notes

- The script will prompt for confirmation before running the pre-requisite check and before connecting to modules
- You may be asked to sign in multiple times as each module loads and connects
- If you encounter any errors, you can re-run the script to attempt auto-fixing

## Troubleshooting

- If you see errors related to AzureAD, ensure you have 'AzureADPreview' installed instead of 'AzureAD'
- Check the summaries at the end of the script execution for any modules that failed to install, update, or connect
- For persistent issues, try manually uninstalling and reinstalling the problematic module

## Disclaimer

This script is provided as-is, without any warranties. Always test in a non-production environment before using in a production setting.
