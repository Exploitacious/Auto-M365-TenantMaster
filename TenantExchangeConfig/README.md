# M365 Tenant and Exchange Configuration Script

## Overview

This PowerShell script automates the configuration of Microsoft 365 tenant settings, focusing on Exchange Online and Entra ID. It's designed to implement best practices and security measures for M365 environments.

## Prerequisites

- PowerShell 5.1 or later
- Exchange Online PowerShell V2 module
- Azure AD PowerShell module
- MSOnline PowerShell module
- Microsoft.Graph.Identity.SignIns module (Removed because Graph is Broken)
- Global Administrator permissions in your M365 tenant

## Installation

1. Clone this repository or download the script files.
2. Ensure all required PowerShell modules are installed.
3. Create a `config.json` file in the same directory as the script (see Configuration section). (optional)

## Usage

1. Run the Module Updater script first to ensure all necessary modules are installed and you're connected to the required services. Use the Launcher for best results.
2. Open PowerShell as an administrator.
3. Navigate to the script directory.
4. Run the script:
   ```
   .\TenantExchangeConfig.ps1
   ```
5. Follow any interactive prompts during execution.
6. Review the summary output and log file after completion.

## Configuration

The script uses a `config.json` file for customizable settings. Here's an example structure with explanations:

```json
{
  "BreakGlassAccountPass": "StrongPassword",
  "GlobalAdminUPN": "Admin@example.com",
  "MSPName": "Umbrella",
  "AdminAccessToMailboxes": true,
  "DisableFocusedInbox": true,
  "DisableSecurityDefaults": true,
  "DeleteStaleDevices": true,
  "StaleDeviceThresholdDays": 90,
  "AuditLogAgeLimit": 730,
  "DevicePilotGroupName": "Pilot - Device Compliance",
  "GroupCreatorsGroupName": "Group Creators",
  "ExcludeFromCAGroupName": "Exclude From CA",
  "AllowedAutoForwardingGroup": "AutoForwarding-Allowed",
  "Language": "en-US",
  "Timezone": "Eastern Standard Time",

  "TeamsConfig": {
    "AllowOrgWideTeamCreation": false,
    "AllowPrivateTeamDiscovery": false,
    "AllowFederatedUsers": true,
    "AllowTeamsConsumer": false,
    "AllowGuestAccess": true,
    "DisableAnonymousJoin": true
  },

  "SharePointOneDriveConfig": {
    "OneDriveStorageQuota": 1048576,
    "OneDriveNewUserQuota": 1048576,
    "SharingCapability": "ExternalUserSharingOnly",
    "DefaultSharingLinkType": "Internal",
    "RootSharePointURL": "https://umbrellaitgroup.sharepoint.com"
  },

  "CompliancePolicies": {
    "EmailRetentionYears": 7,
    "SharePointOneDriveRetentionYears": 5
  }
}
```

## Modifications

The script makes the following key modifications:

1. Exchange Online:

   - Enables organization customization
   - Configures Send-From-Alias
   - Disables Focused Inbox
   - Sets up naming policy for distribution groups (DL\_""")
   - Enables/disables various Exchange features (e.g., Plus Addressing, Read Tracking)
   - Configure Mail-Tips
   - Enable External Sender Tags in Outlook
   - Enable Read Email Tracking
   - Enable Public Computer Detection (For OWA)
   - Disable Outlook Pay
   - Enable Lean Pop-Outs for OWA in Edge
   - Enable Outlook Events Recognition
   - Disable Feedback in Outlook Online
   - Enable Modern Authentication
   - Block Consumer Storage in OWA
   - Block Attachment Download on Unmanaged Assets OWA (Requires Additional CA Policy)
   - Set Max Retention Limit on deleted items (30)
   - Enable Unified Audit Log Search
   - Configures log retention policies and audit logging for every mailbox

2. Azure AD:

   - Sets up a break-glass admin account (MSPName+BG)
   - (Optional) Deletes all Stale devices from Intune
   - Creates and configures security groups (3 Groups defined in Config file)
   - Adds admin accounts to these newly created groups
   - Created a "Super Admin" Role to give more power to Global Admins not available by default (See line 429 for more details)
   - Configures "group creators" group creation restrictions
   - Grant ADmin access to all mailboxes in Tenant (Optional)

3. MSOL:

   - Disables shared mailbox sign-in
   - Configures regional settings for all mailboxes

4. Teams Configuration:

   - Set default team and channel settings
   - Configure external access
   - Configure guest access

5. SharePoint and OneDrive configurations:

   - Set default storage limits (7 years)
   - Configure external sharing settings

6. Configure basic compliance policies

   - Set up retention policy for email (7 years)
   - Set up retention policy for SharePoint and OneDrive (7 years)

7. Enhanced Security Alert Notifications

   - Admin Activities Alerts
   - Malware Alerts
   - Threat Policies Alerts
   - High Sensitivity Alerts
   - Basic Informational Alerts

8. Additional:
   - Optionally sets up archiving mailbox and litigation hold (interactive prompt)

## Troubleshooting

- Check the log file (TenantExchangeConfig\_[timestamp].log) for detailed execution information.
- Ensure all required PowerShell modules are installed and up to date.
- Verify that you have the necessary permissions in your M365 tenant.
- If a specific operation fails, you can often rerun just that part of the script after addressing the issue.

## Rollback

The script currently doesn't have an automated rollback feature. In case of issues:

1. Review the log file to identify which changes were made.
2. Manually revert critical changes using the M365 admin center or PowerShell commands.
3. For major issues, consider restoring from a tenant backup if available.

## Contributing

Contributions to improve the script are welcome. Please submit pull requests with clear descriptions of changes and their purpose.

## Disclaimer

This script makes significant changes to your M365 environment. Always test in a non-production environment first and ensure you understand each modification it makes.

## License

[Specify your license here, e.g., MIT License]
