# Ensure you have the AzureAD module installed
Install-Module AzureAD

# Connect to Azure AD
Connect-AzureAD -Credential $Global:Credential

# Obtain the access token
$token = (Get-AzureADSignedInUserAccessToken).AccessToken

# Set the Authorization header
$headers = @{
    Authorization = "Bearer $token"
}

# Connect to SharePoint Online using the token
$spoUrl = "https://$Global:TenantDomain-admin.sharepoint.com"
$response = Invoke-RestMethod -Uri $spoUrl -Headers $headers -Method Get

if ($response.StatusCode -eq 200) {
    Write-Output "Successfully connected to SharePoint Online."
}
else {
    Write-Output "Failed to connect to SharePoint Online. Status code: $($response.StatusCode)"
}
