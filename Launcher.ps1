# M365 Configuration Launcher

Clear-Host
Write-Host "                            .___  ___.  ____      __    _____                                               "
Write-Host "                            |   \/   | |___ \    / /   | ____|                                              "
Write-Host "                            |  \  /  |   __) |  / /_   | |__                                                "
Write-Host "                            |  |\/|  |  |__ <  | '_ \  |___ \                                               "
Write-Host "                            |  |  |  |  ___) | | (_) |  ___) |                                              "
Write-Host "                            |__|  |__| |____/   \___/  |____/                                               "
Write-Host "                                                                                                            "
Write-Host "   ______   ______   .__   __.  _______  __    _______  __    __  .______          ___   .___________.  ______   .______       "
Write-Host "  /      | /  __  \  |  \ |  | |   ____||  |  /  _____||  |  |  | |   _  \        /   \  |           | /  __  \  |   _  \      "
Write-Host " |  ,----'|  |  |  | |   \|  | |  |__   |  | |  |  __  |  |  |  | |  |_)  |      /  ^  \ '---|  |----'|  |  |  | |  |_)  |     "
Write-Host " |  |     |  |  |  | |  . '  | |   __|  |  | |  | |_ | |  |  |  | |      /      /  /_\  \    |  |     |  |  |  | |      /      "
Write-Host " |  '----.|  '--'  | |  |\   | |  |     |  | |  |__| | |  '--'  | |  |\  \----./  _____  \   |  |     |  '--'  | |  |\  \----. "
Write-Host "  \______| \______/  |__| \__| |__|     |__|  \______|  \______/  | _| '._____/__/     \__\  |__|      \______/  | _| '._____| "
Write-Host                                                                                                                                                         
Write-Host
Write-Host " Created by Alex Ivantsov @Exploitacious "
Write-Host
Write-Host


# Function to display menu and get user choice
function Show-Menu {
    param (
        [string]$Title = 'M365 Configuration Menu'
    )

    Write-Host "================ $Title ================"
    Write-Host
    Write-Host "1: Update/Install Required Modules"
    Write-Host "2: Configure M365 Tenant and Exchange Online"
    Write-Host "3: Configure ATP (Advanced Threat Protection)"
    Write-Host "4: Configure DLP (Data Loss Prevention)"
    Write-Host "5: Run All Configurations"
    Write-Host "Q: Quit"
    Write-Host
    Write-Host
}

# Function to run module updater
function Update-Modules {
    # Insert your module updater code here
}

# Function to run M365 Tenant and Exchange Online configuration
function Configure-M365TenantAndExchange {
    # Insert your existing script here, broken down into functions
}

# Function to run ATP configuration
function Configure-ATP {
    # Insert your ATP configuration script here
}

# Function to run DLP configuration
function Configure-DLP {
    # Insert your DLP configuration script here
}

# Main script logic
do {
    Show-Menu
    $input = Read-Host "Please make a selection"
    switch ($input) {
        '1' {
            Update-Modules
        } '2' {
            Configure-M365TenantAndExchange
        } '3' {
            Configure-ATP
        } '4' {
            Configure-DLP
        } '5' {
            Update-Modules
            Configure-M365TenantAndExchange
            Configure-ATP
            Configure-DLP
        } 'q' {
            return
        }
    }
    pause
}
until ($input -eq 'q')