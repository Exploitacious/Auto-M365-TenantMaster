# M365 Module Connector

## Overview

The M365 Module Connector is a PowerShell script designed to streamline the process of connecting to various Microsoft 365 services. It automates the import and connection of essential modules required for managing and administering Microsoft 365 environments.

## Features

- Automatically imports necessary Microsoft 365 modules
- Connects to multiple services including Exchange Online, Security & Compliance Center, Microsoft Graph, Azure AD, and more
- Handles authentication and Multi-Factor Authentication (MFA) processes
- Provides a summary of connection statuses for each service
- Logs activities and errors for troubleshooting

## Prerequisites

- Windows PowerShell 5.1 or later
- Administrator rights on the local machine
- Global Administrator credentials for the Microsoft 365 tenant
- Relevant Microsoft 365 modules installed (use the separate module installation script)

## Usage

1. Run PowerShell as an Administrator
2. Navigate to the directory containing the script
3. Execute the script: `.\M365ModuleConnector.ps1`
4. Enter your Global Administrator credentials when prompted
5. Follow on-screen instructions to complete MFA if required
6. Review the connection summary to ensure all services are connected

## Troubleshooting

- If you encounter errors, check the log file generated in the script directory
