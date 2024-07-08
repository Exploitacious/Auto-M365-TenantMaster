# Define the scopes required for your script
$Scopes = @(
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Organization.ReadWrite.All",
    "Device.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "SecurityEvents.ReadWrite.All",
    "MailboxSettings.ReadWrite",
    "Reports.Read.All",
    "AuditLog.Read.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "TeamSettings.ReadWrite.All",
    "Sites.FullControl.All",
    "IdentityRiskyUser.ReadWrite.All",
    "ThreatAssessment.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All"
)

# Function to connect to Microsoft Graph using interactive login
function Connect-MgGraphWithInteractive {
    try {
        Write-Host "Attempting to connect to Microsoft Graph using interactive login..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes $Scopes -ErrorAction Stop
        Write-Host "Microsoft Graph Connected!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "Failed to connect to Microsoft Graph: $_"
        return $false
    }
}

# Function to check the connection by listing users
function Check-MgGraphConnection {
    try {
        Write-Host "Checking Microsoft Graph connection by listing users..." -ForegroundColor Yellow
        $users = Get-MgUser -ErrorAction Stop
        if ($users) {
            Write-Host "Total users found: $($users.Count)" -ForegroundColor Green
            return $true
        }
        else {
            Write-Error "No users found. Please check your directory and permissions."
            return $false
        }
    }
    catch {
        Write-Warning "Failed to list users: $_"
        return $false
    }
}

# Function to list user emails
function List-MgUsers {
    try {
        Write-Host "Listing all user emails..." -ForegroundColor Yellow
        $users = Get-MgUser -ErrorAction Stop
        $users | ForEach-Object { Write-Host $_.UserPrincipalName }
    }
    catch {
        Write-Warning "Failed to list user emails: $_"
    }
}

# Main script execution
if (Connect-MgGraphWithInteractive) {
    if (Check-MgGraphConnection) {
        List-MgUsers
        Write-Host "Successfully listed users. Proceeding with further operations..." -ForegroundColor Green
        # Continue with the rest of your script here
    }
    else {
        Write-Host "Exiting script due to connection verification failure." -ForegroundColor Red
    }
}
else {
    Write-Host "Exiting script due to connection failure." -ForegroundColor Red
}