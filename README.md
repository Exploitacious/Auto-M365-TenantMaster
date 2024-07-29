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

2. Copy the following text and customize it for the organization you are setting up. Name the file `config.json` and place the file in the same directory as the Launcher.ps1 file.

```json
{
  "MSPName": "MSP Name (no Spaces or characters) e.g.: Umbrella",
  "MSPAlertsAddress": "alerting@umbrellaitgroup.com",
  "MSPSupportMail": "Support@Umbrellaitgroup.com",
  "MSPSupportInfo": "Umbrella IT Group (904) 930-4261",
  "BreakGlassAccountPass": "Strong-Password",
  "LogoURL": "Direct URL to a Logo for use with a white background. PNG or JPEG only.",
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
    "DisableAnonymousJoin": true,
    "AllowDropBox": false,
    "AllowGoogleDrive": false,
    "AllowOrgWideTeamCreation": false,
    "AllowGuestAccess": true,
    "AllowBox": false,
    "AllowTeamsConsumerInbound": false,
    "AllowFederatedUsers": true,
    "AllowTeamsConsumer": false,
    "AllowEmailIntoChannel": true,
    "AllowEgnyte": false
  },

  "SharePointOneDriveConfig": {
    "OneDriveStorageQuota": 1048576,
    "SharingCapability": "ExternalUserSharingOnly",
    "DefaultSharingLinkType": "Internal",
    "BccExternalSharingInvitations": true,
    "PreventExternalUsersFromResharing": true
  },

  "CompliancePolicies": {
    "SharePointOneDriveRetentionYears": 10,
    "EmailRetentionYears": 10
  },

  "ScriptPaths": {
    "ModuleUpdater": "M365ModuleUpdater\\M365ModuleUpdater.ps1",
    "TenantExchangeConfig": "TenantExchangeConfig\\TenantExchangeConfig.ps1",
    "ModuleConnector": "M365ModuleConnector\\M365ModuleConnector.ps1",
    "DLPConfig": "DataLossPrevention\\DLPConfig.ps1",
    "ATPConfig": "AdvancedThreatProtection\\ATPConfig.ps1"
  }
}
```
