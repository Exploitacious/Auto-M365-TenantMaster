# Function to Check Connection Status
function Test-ServiceConnection {
    param (
        [string]$ServiceName
    )
    
    switch ($ServiceName) {
        "Exchange Online" { 
            return $null -ne (Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened" })
        }
        "Security & Compliance Center" {
            return $null -ne (Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened" -and $_.ComputerName -like "*.ps.compliance.protection.outlook.com" })
        }
        "Microsoft Graph" {
            return [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthContext.HasValidAccessToken()
        }
        "Microsoft Online" {
            return $null -ne (Get-MsolCompanyInformation -ErrorAction SilentlyContinue)
        }
        "Azure AD Preview" {
            return $null -ne (Get-AzureADTenantDetail -ErrorAction SilentlyContinue)
        }
        "Azure Information Protection" {
            return $null -ne (Get-AipService -ErrorAction SilentlyContinue)
        }
        "Microsoft Teams" {
            return $null -ne (Get-Team -ErrorAction SilentlyContinue)
        }
        default {
            return $false
        }
    }
}

Test-ServiceConnection