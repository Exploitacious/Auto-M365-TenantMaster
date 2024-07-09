# Check/Enter Admin Creds
If ($null -eq $Global:Credential.UserName) {
    try {
        $Global:Credential = Get-Credential -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "Credentials not entered. Exiting..."
        exit
    }
    Write-Host
}
else {
    Write-Host " $($Global:Credential.UserName) being used"
}

# Connect to Azure AD
Write-Host "Logging into AzureAD..."
Connect-AzureAD

# Obtain the access token
Write-Host "Gathering Token..."
$token = (Get-AzureADSignedInUserAccessToken).AccessToken

# Set the Authorization header
Write-Host "Setting Headers..."
$headers = @{
    Authorization = "Bearer $token"
}

# Connect to SharePoint Online using the token
Write-Host "Logging into SPO..."
$spoUrl = "https://$Global:TenantDomain-admin.sharepoint.com"
$response = Invoke-RestMethod -Uri $spoUrl -Headers $headers -Method Get

if ($response.StatusCode -eq 200) {
    Write-Output "Successfully connected to SharePoint Online."
}
else {
    Write-Output "Failed to connect to SharePoint Online. Status code: $($response.StatusCode)"
}
