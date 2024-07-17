$singleCustomerTenantId = "cec05043-fa57-42a8-87b6-3d46378f2ed0"  # Replace with customer tenant ID to test with a single customer, leave empty for all customers

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

# Function to ensure required modules are installed and imported
function Ensure-ModuleAvailable {
    param (
        [string]$ModuleName
    )
    
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Module $ModuleName is not installed. Attempting to install..." -ForegroundColor Yellow
        try {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
            Write-Host "Module $ModuleName installed successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to install module $ModuleName. Error: $_" -ForegroundColor Red
            return $false
        }
    }
    
    try {
        Import-Module $ModuleName -ErrorAction Stop
        Write-Host "Module $ModuleName imported successfully." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to import module $ModuleName. Error: $_" -ForegroundColor Red
        return $false
    }
}

# Check and import required modules
$requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.DirectoryManagement", "Microsoft.Graph.Groups", "PartnerCenter")
$allModulesAvailable = $true
foreach ($module in $requiredModules) {
    if (-not (Ensure-ModuleAvailable -ModuleName $module)) {
        $allModulesAvailable = $false
    }
}

if (-not $allModulesAvailable) {
    Write-Host "Not all required modules are available. Please install the missing modules and try again." -ForegroundColor Red
    exit
}

# Define the GDAP roles
$gdapRoles = @(
    "Global Administrator",
    "Application Administrator",
    "Attack Payload Author",
    "Attack Simulation Administrator",
    "Attribute Assignment Administrator",
    "Attribute Definition Administrator",
    "Attribute Log Administrator",
    "Authentication Administrator",
    "Authentication Extensibility Administrator",
    "Authentication Policy Administrator",
    "Azure DevOps Administrator",
    "Azure Information Protection Administrator",
    "B2C IEF Keyset Administrator",
    "B2C IEF Policy Administrator",
    "Billing Administrator",
    "Cloud App Security Administrator",
    "Cloud Application Administrator",
    "Cloud Device Administrator",
    "Compliance Administrator",
    "Compliance Data Administrator",
    "Conditional Access Administrator",
    "Desktop Analytics Administrator",
    "Domain Name Administrator",
    "Dynamics 365 Administrator",
    "Dynamics 365 Business Central Administrator",
    "Edge Administrator",
    "Exchange Administrator",
    "Exchange Recipient Administrator",
    "Extended Directory User Administrator",
    "External ID User Flow Administrator",
    "External ID User Flow Attribute Administrator",
    "External Identity Provider Administrator",
    "Fabric Administrator",
    "Global Secure Access Administrator",
    "Groups Administrator",
    "Helpdesk Administrator",
    "Hybrid Identity Administrator",
    "Identity Governance Administrator",
    "Insights Administrator",
    "Intune Administrator",
    "Kaizala Administrator",
    "Knowledge Administrator",
    "License Administrator",
    "Lifecycle Workflows Administrator",
    "Microsoft 365 Migration Administrator",
    "Microsoft Entra Joined Device Local Administrator",
    "Microsoft Hardware Warranty Administrator",
    "Network Administrator",
    "Office Apps Administrator",
    "Organizational Branding Administrator",
    "Password Administrator",
    "Permissions Management Administrator",
    "Power Platform Administrator",
    "Printer Administrator",
    "Privileged Authentication Administrator",
    "Privileged Role Administrator",
    "Search Administrator",
    "Security Administrator",
    "Service Support Administrator",
    "SharePoint Administrator",
    "SharePoint Embedded Administrator",
    "Skype for Business Administrator",
    "Teams Administrator",
    "Teams Communications Administrator",
    "Teams Devices Administrator",
    "Teams Telephony Administrator",
    "User Administrator",
    "Virtual Visits Administrator",
    "Viva Goals Administrator",
    "Viva Pulse Administrator",
    "Windows 365 Administrator",
    "Windows Update Deployment Administrator",
    "Yammer Administrator",
    "Application Developer"
)

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

# Function to create or get an assignable group
function New-OrGetAssignableGroup($groupName, $description, $roles) {
    $existingGroup = Get-MgGroup -Filter "displayName eq '$groupName'"
    if ($existingGroup) {
        Write-Host "Group '$groupName' already exists with ID: $($existingGroup.Id)" -ForegroundColor Yellow
        return $existingGroup.Id
    }

    # Truncate description if it's too long
    if ($description.Length -gt 1024) {
        $description = $description.Substring(0, 1021) + "..."
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
        Write-Host "Failed to create new assignable group '$groupName' with detailed description: $_" -ForegroundColor Yellow
        Write-Host "Attempting to create group with generic description..." -ForegroundColor Yellow
        $params.Description = "GDAP group for administrative roles. Total roles: $($roles.Count)"
        try {
            $newGroup = New-MgGroup -BodyParameter $params
            Write-Host "New assignable group '$groupName' created with generic description. ID: $($newGroup.Id)" -ForegroundColor Green
            return $newGroup.Id
        }
        catch {
            Write-Host "Failed to create group with generic description: $_" -ForegroundColor Red
            Write-Host "Attempting to create group without description..." -ForegroundColor Yellow
            $params.Remove('Description')
            try {
                $newGroup = New-MgGroup -BodyParameter $params
                Write-Host "New assignable group '$groupName' created without description. ID: $($newGroup.Id)" -ForegroundColor Green
                return $newGroup.Id
            }
            catch {
                Write-Host "Failed to create group even without description: $_" -ForegroundColor Red
                return $null
            }
        }
    }
}

# Function to get role ID
function Get-RoleId($roleName) {
    $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'"
    if (-not $role) {
        Write-Host "Role '$roleName' not found. Attempting to get all roles..." -ForegroundColor Yellow
        $allRoles = Get-MgDirectoryRole
        $closestMatch = $allRoles | Where-Object { $_.DisplayName -like "*$roleName*" } | Select-Object -First 1
        if ($closestMatch) {
            Write-Host "Closest match found: $($closestMatch.DisplayName)" -ForegroundColor Yellow
            return $closestMatch.Id
        }
        Write-Host "No matching role found for '$roleName'" -ForegroundColor Red
        return $null
    }
    return $role.Id
}

# Function to assign GDAP role to group
function New-GDAPRoleAssignment($groupId, $roleName, $customerId) {
    try {
        # Get the existing roles for the customer
        $existingRoles = Get-PartnerCustomerUserRole -CustomerId $customerId

        # Check if the role already exists
        $role = $existingRoles | Where-Object { $_.Name -eq $roleName }
        if (-not $role) {
            Write-Host "Role '$roleName' not found for customer $customerId" -ForegroundColor Red
            return $false
        }

        # Check if the group is already assigned to the role
        $roleMembers = Get-PartnerCustomerUserRoleMember -CustomerId $customerId -RoleId $role.Id
        $groupAssigned = $roleMembers | Where-Object { $_.GroupId -eq $groupId }

        if ($groupAssigned) {
            Write-Host "Group $groupId is already assigned to role $roleName for customer $customerId" -ForegroundColor Yellow
            return $true
        }

        # Assign the group to the role
        Add-PartnerCustomerUserRoleMember -CustomerId $customerId -RoleId $role.Id -GroupId $groupId
        Write-Host "GDAP role assignment created for group $groupId and role $roleName" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to create GDAP role assignment: $_" -ForegroundColor Red
        return $false
    }
}

# Function to check prerequisites
function Check-Prerequisites {
    param (
        [string]$CustomerId
    )
    
    $prerequisites = @{
        "Connected to Microsoft Graph" = $false
        "Connected to Partner Center"  = $false
        "GDAP relationship exists"     = $false
        "Required permissions"         = $false
    }
    
    # Check Microsoft Graph connection
    try {
        Get-MgContext -ErrorAction Stop
        $prerequisites["Connected to Microsoft Graph"] = $true
    }
    catch {
        Write-Host "Not connected to Microsoft Graph. Please connect using Connect-MgGraph." -ForegroundColor Red
    }
    
    # Check Partner Center connection
    try {
        Get-PartnerCustomer -CustomerId $CustomerId -ErrorAction Stop
        $prerequisites["Connected to Partner Center"] = $true
    }
    catch {
        Write-Host "Not connected to Partner Center. Please connect using Connect-PartnerCenter." -ForegroundColor Red
    }
    
    # Check GDAP relationship
    try {
        $customer = Get-PartnerCustomer -CustomerId $CustomerId
        if ($customer.RelationshipToPartner -eq "Reseller") {
            $prerequisites["GDAP relationship exists"] = $true
        }
        else {
            Write-Host "No reseller relationship found for customer $CustomerId. GDAP might not be established." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Failed to check customer relationship: $_" -ForegroundColor Red
    }
    
    # Check required permissions (this is a simplified check, you may need to adjust based on your exact permission requirements)
    try {
        Get-MgDirectoryRole -ErrorAction Stop
        $prerequisites["Required permissions"] = $true
    }
    catch {
        Write-Host "Insufficient permissions to manage directory roles. Please ensure you have the necessary permissions." -ForegroundColor Red
    }
    
    return $prerequisites
}

#######################
# Main script execution
####################### 

$categories = Get-RoleCategories $gdapRoles
$groupIds = @{}

# Ensure authentication before proceeding
Ensure-GraphAuthentication
Ensure-PartnerCenterAuthentication

foreach ($category in $categories.Keys) {
    $groupName = "GDAP - $category Administrators"
    $description = "GDAP group for $category roles: $($categories[$category] -join ', ')"
    $groupId = New-OrGetAssignableGroup $groupName $description $categories[$category]
    if ($groupId) {
        $groupIds[$category] = $groupId
    }
    else {
        Write-Host "Failed to create or get group for category: $category. Skipping this category." -ForegroundColor Red
    }
}

# Get list of customers based on whether a single customer tenant ID is specified
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
    
    # Check prerequisites (you may need to adjust this function to use Partner Center cmdlets)
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

    foreach ($category in $categories.Keys) {
        $groupId = $groupIds[$category]
        foreach ($role in $categories[$category]) {
            $result = New-GDAPRoleAssignment $groupId $role $customerId
            if ($result) {
                Write-Host "Assigned $role to $category group for customer $customerName" -ForegroundColor Green
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

    Write-Host "Completed processing for customer: $customerName ($customerId)" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------------------------"
}

Write-Host "GDAP role assignment process completed." -ForegroundColor Magenta

# Output summary
Write-Host "Summary of Changes:" -ForegroundColor Cyan
$summary | Format-Table -AutoSize

# Export summary to CSV
$csvPath = "GDAP_Assignment_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$summary | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Summary exported to CSV file: $csvPath" -ForegroundColor Green