# Auto-M365-TenantMaster

Quickly and easily get a client environment ready for your MSP's M365 management.

## Features

- Automates initial setup for Microsoft 365 tenants
- Configures essential security settings
- Deploys best practice configurations
- Non-disruptive to existing operations

## Requirements

- PowerShell 5.1 or higher
- Microsoft 365 Admin credentials

## Configuration

The script uses a `config.json` file for customizable settings. There are two ways to use this config file.

1. (Most Recommended) Run the Launcher.ps1 and it will generate a brand new config file. You can then open this file and modify settings as needed.

2. Copy the following text and customize it for the organization you are setting up. Place the file in the same directory as the Launcher.ps1 file.

```json
{
  "BreakGlassAccountPass": "StrongPassword",
  "GlobalAdminUPN": "Admin@example.com",
  "MSPName": "MSPname (no Spaces or characters)",
  "AdminAccessToMailboxes": true,
  "DisableFocusedInbox": true,
  "DisableSecurityDefaults": true,
  "DeleteStaleDevices": true,
  "StaleDeviceThresholdDays": 90,
  "AuditLogAgeLimit": 730,
  "DevicePilotGroupName": "Pilot - Device Compliance",
  "GroupCreatorsGroupName": "Group Creators",
  "ExcludeFromCAGroupName": "Exclude From CA",
  "GuestCreatorAdminsGroupName": "Guest Creators",
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
    "RootSharePointURL": "https://<customerDomain>.sharepoint.com"
  },

  "CompliancePolicies": {
    "EmailRetentionYears": 7,
    "SharePointOneDriveRetentionYears": 5
  }
}
```
