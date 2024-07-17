# Import required modules
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Identity.DirectoryManagement
Import-Module Microsoft.Graph.Groups
Import-Module PartnerCenter

# Function to ensure authentication
function Ensure-GraphAuthentication {
    try {
        $context = Get-MgContext
        if (-not $context) {
            Write-Host "Not authenticated to Microsoft Graph. Attempting to connect..." -ForegroundColor Yellow
            Connect-MgGraph -Scopes "Directory.ReadWrite.All", "Group.ReadWrite.All"
        }
        else {
            Write-Host "Already authenticated to Microsoft Graph." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Failed to authenticate to Microsoft Graph: $_" -ForegroundColor Red
        exit
    }
}

function Ensure-PartnerCenterAuthentication {
    try {
        $partner = Get-PartnerContext
        if (-not $partner) {
            Write-Host "Not authenticated to Partner Center. Attempting to connect..." -ForegroundColor Yellow
            Connect-PartnerCenter
        }
        else {
            Write-Host "Already authenticated to Partner Center." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Failed to authenticate to Partner Center: $_" -ForegroundColor Red
        exit
    }
}

# Ensure authentication before proceeding
Ensure-GraphAuthentication
Ensure-PartnerCenterAuthentication

# Function to categorize roles
function Get-RoleCategories($roles) {
    $categories = @{
        "Identity and Access"     = @(
            "Global Administrator", "Authentication Administrator", "Conditional Access Administrator",
            "Password Administrator", "Privileged Authentication Administrator", "User Administrator"
        )
        "Security and Compliance" = @(
            "Security Administrator", "Compliance Administrator", "Compliance Data Administrator",
            "Cloud App Security Administrator", "Attack Simulation Administrator"
        )
        "Microsoft 365 Services"  = @(
            "Exchange Administrator", "SharePoint Administrator", "Teams Administrator",
            "Power Platform Administrator", "Dynamics 365 Administrator", "Intune Administrator"
        )
        "Azure and DevOps"        = @(
            "Azure DevOps Administrator", "Azure Information Protection Administrator",
            "Cloud Device Administrator", "Hybrid Identity Administrator"
        )
        "Specialized Roles"       = @()
    }

    $roles | ForEach-Object {
        $role = $_
        $categorized = $false
        foreach ($category in $categories.Keys) {
            if ($categories[$category] -contains $role) {
                $categorized = $true
                break
            }
        }
        if (-not $categorized) {
            $categories["Specialized Roles"] += $role
        }
    }

    return $categories
}

# Function to get or create assignable groups
function New-OrGetAssignableGroup($groupName, $description) {
    $existingGroup = Get-MgGroup -Filter "displayName eq '$groupName'"
    if ($existingGroup) {
        Write-Host "Group '$groupName' already exists with ID: $($existingGroup.Id)" -ForegroundColor Yellow
        return $existingGroup.Id
    }

    $params = @{
        DisplayName        = $groupName
        Description        = $description
        MailEnabled        = $false
        MailNickname       = ($groupName -replace '[^a-zA-Z0-9]', '').ToLower()
        SecurityEnabled    = $true
        IsAssignableToRole = $true
    }

    try {
        $newGroup = New-MgGroup -BodyParameter $params
        Write-Host "New assignable group '$groupName' created with ID: $($newGroup.Id)" -ForegroundColor Green
        return $newGroup.Id
    }
    catch {
        Write-Host "Failed to create new assignable group '$groupName': $_" -ForegroundColor Red
        return $null
    }
}

# Function to assign GDAP role to group
function New-GDAPRoleAssignment($groupId, $roleId, $customerId) {
    try {
        Add-PartnerCustomerUserRoleMember -CustomerId $customerId -RoleId $roleId -GroupId $groupId
        Write-Host "GDAP role assignment created for group $groupId and role $roleId" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to create GDAP role assignment: $_" -ForegroundColor Red
        return $false
    }
}

# Function to check prerequisites
function Check-Prerequisites($customerId) {
    $prerequisites = @{
        "Connected to Partner Center" = $false
        "GDAP relationship exists"    = $false
    }
    
    # Check Partner Center connection
    try {
        Get-PartnerCustomer -CustomerId $customerId -ErrorAction Stop
        $prerequisites["Connected to Partner Center"] = $true
    }
    catch {
        Write-Host "Not connected to Partner Center or issue with customer access. Error: $_" -ForegroundColor Red
    }
    
    # Check GDAP relationship
    try {
        $customer = Get-PartnerCustomer -CustomerId $customerId
        if ($customer.RelationshipToPartner -eq "Reseller") {
            $prerequisites["GDAP relationship exists"] = $true
        }
        else {
            Write-Host "No reseller relationship found for customer $customerId. GDAP might not be established." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Failed to check customer relationship: $_" -ForegroundColor Red
    }
    
    return $prerequisites
}

# Main script execution
$categories = Get-RoleCategories $gdapRoles
$groupIds = @{}

foreach ($category in $categories.Keys) {
    $groupName = "GDAP - $category Administrators"
    $description = "GDAP group for $category roles: $($categories[$category] -join ', ')"
    $groupId = New-OrGetAssignableGroup $groupName $description
    if ($groupId) {
        $groupIds[$category] = $groupId
    }
}

# Get list of customers based on whether a single customer tenant ID is specified
$singleCustomerTenantId = ""  # Replace with customer tenant ID to test with a single customer, leave empty for all customers
if ($singleCustomerTenantId -ne "") {
    $customers = Get-PartnerCustomer | Where-Object { $_.CustomerId -eq $singleCustomerTenantId }
    if (-not $customers) {
        Write-Host "No customer found with the specified Tenant ID: $singleCustomerTenantId" -ForegroundColor Red
        exit
    }
}
else {
    $customers = Get-PartnerCustomer
}

$summary = @()

foreach ($customer in $customers) {
    $customerName = $customer.Name
    $customerId = $customer.CustomerId
    Write-Host "Processing customer: $customerName ($customerId)" -ForegroundColor Cyan
    
    # Check prerequisites
    $prereqCheck = Check-Prerequisites -CustomerId $customerId
    
    if ($prereqCheck.Values -contains $false) {
        Write-Host "Prerequisites not met for customer $customerName. Skipping..." -ForegroundColor Yellow
        foreach ($prereq in $prereqCheck.GetEnumerator()) {
            if (-not $prereq.Value) {
                $summary += [PSCustomObject]@{
                    CustomerName = $customerName
                    CustomerId   = $customerId
                    Action       = "Skipped"
                    Reason       = "Prerequisite not met: $($prereq.Key)"
                }
            }
        }
        continue
    }
    
    Write-Host "All prerequisites met. Proceeding with role assignments." -ForegroundColor Green

    # Get available roles for the customer
    $availableRoles = Get-PartnerCustomerUserRole -CustomerId $customerId

    Write-Host "Available roles for $customerName :" -ForegroundColor Green
    $availableRoles | ForEach-Object {
        Write-Host "- $($_.Name) (ID: $($_.Id))" -ForegroundColor Yellow
    }

    # Prompt user for role assignments
    Write-Host "Do you want to assign roles for this customer? (Y/N)" -ForegroundColor Cyan
    $response = Read-Host
    if ($response -eq "Y" -or $response -eq "y") {
        foreach ($category in $categories.Keys) {
            $groupId = $groupIds[$category]
            foreach ($role in $categories[$category]) {
                $availableRole = $availableRoles | Where-Object { $_.Name -eq $role }
                if ($availableRole) {
                    Write-Host "Do you want to assign the role '$role' to the GDAP group '$category'? (Y/N)" -ForegroundColor Cyan
                    $assignRole = Read-Host
                    if ($assignRole -eq "Y" -or $assignRole -eq "y") {
                        $result = New-GDAPRoleAssignment $groupId $availableRole.Id $customerId
                        if ($result) {
                            $summary += [PSCustomObject]@{
                                CustomerName = $customerName
                                CustomerId   = $customerId
                                Action       = "Assigned"
                                Role         = $role
                                Category     = $category
                            }
                        }
                        else {
                            $summary += [PSCustomObject]@{
                                CustomerName = $customerName
                                CustomerId   = $customerId
                                Action       = "Failed"
                                Role         = $role
                                Category     = $category
                                Reason       = "GDAP assignment failed"
                            }
                        }
                    }
                }
                else {
                    Write-Host "Role '$role' not available for this customer. Skipping..." -ForegroundColor Yellow
                }
            }
        }
    }

    Write-Host "Completed processing for customer: $customerName ($customerId)" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------------------------"
}

# Output summary
Write-Host "Summary of Actions:" -ForegroundColor Cyan
$summary | Format-Table -AutoSize

# Export summary to CSV
$csvPath = "GDAP_Roles_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$summary | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Summary exported to CSV file: $csvPath" -ForegroundColor Green