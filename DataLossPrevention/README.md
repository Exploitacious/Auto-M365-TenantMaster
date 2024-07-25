# Microsoft 365 DLP Configuration Script

MSP Focused DLP deployment template for M365 Business Premium clients.

The point of this is to deploy an intelligent implementation of DLP on a customer's environment with a simple powershell script, rather than spending hours clicking through the protection.office.com GUI. There are a few things to consider in this script, but it was designed to be relevant and uninstrusive to a very wide range of USA based customers, especially within the small-medium size sector. If you have clients that are require HIPAA or PCI compliance, this script is still a great place to start.

## Policies and Rules Deployed

This scripts deploys three policies for the different locations covered by DLP. With each policy, there are specific rule sets which will be associated to the parent policy/location.

- Exchange

  - Auto-Detect and automatically Encrypt Sensitive Data going outside of organization.
  - Skip encryption if document is protected or PW protected zip file
  - Provide user with a notification that their email was encrypted, and provide instructions on how to assist the receiving party

- SharePoint + OneDrive
  - BLOCK Sharing Sensitive data using the 'anyone with link' option
- Teams + (SharePoint & OneDrive)

  - Detect any volume sensitive data being sent to outside of the organization
  - Require User to provide justification for sharing sensitive info
  - Detect HIGH VOLUMES of sensitive data being shared ourside of org.
  - Provide a report for admin

- Sensitive Information Covered by default
  - U.S. Social Security Number (SSN)
  - Credit Card Number
  - U.S. / U.K. Passport Number
  - U.S. Bank Account Number
  - U.S. Driver's License Number
  - U.S. Individual Taxpayer Identification Number (ITIN)
  - International Banking Account Number (IBAN)
  - Medicare Beneficiary Identifier (MBI) card
  - Other Technical Azure AD Related Information Types

## Recent Updates:

- Removed some Sensitive Info Types
  - Added Connect-CMDlet Option
  - Changed Confidence Level to "High" on High Volume Policy
  - Changed Confidence Level to "High" on Low Volume Policy
- Removed Email policytip/notification for "LastModifier" due to excessive notifications during 'OneDrive Known Folder Migrations'.
- Removed "AzureAD Storage Account Key (Generic)" Information Type which was causing excesive false positives
- Some light script cleanup

I discovered that in practice the "AzureAD Storage Account Key GENERIC" was causing a lot of false positive triggers, and there were false positives triggered due to '75' confidence on all other info types. I have found a lot better of results with using '85' or 'High' confidence for all. I have also discovered that the email template received by users is not very inteligent or informative, so I removed "Last Modifier" from the notification, so the user will only see the policy tips when attempting to share.

## Overview for 2.0

This PowerShell script automates the configuration of Data Loss Prevention (DLP) policies and rules in Microsoft 365. It sets up comprehensive DLP policies for Exchange Online, SharePoint, OneDrive, and Teams, as well as configuring sensitivity labels and their associated policies.

## Features

1. **Exchange Online DLP Policy**

   - Creates or updates a DLP policy for Exchange Online
   - Sets up rules to encrypt emails containing sensitive information

2. **Non-Exchange DLP Policies**

   - Creates or updates DLP policies for SharePoint, OneDrive, and Teams
   - Configures rules for different volumes of sensitive information (Any, High, Low)

3. **Sensitivity Labels**

   - Creates or updates sensitivity labels (Public, Internal, Confidential, Highly Confidential)
   - Sets up a default sensitivity label policy

4. **SharePoint and OneDrive Integration**
   - Enables Azure Information Protection (AIP) integration for SharePoint and OneDrive

## Prerequisites

- PowerShell 5.1 or later
- Exchange Online PowerShell module
- Azure AD PowerShell module
- Microsoft Graph PowerShell module
- Global Administrator credentials for the Microsoft 365 tenant

## Usage

1. Ensure you have the required PowerShell modules installed.
2. Run the script in an elevated PowerShell session.
3. When prompted, enter your Global Administrator credentials.
4. The script will perform the following actions:
   - Connect to necessary services (Exchange Online, Security & Compliance Center, Azure AD)
   - Configure DLP policies and rules
   - Set up sensitivity labels and policies
   - Enable SharePoint and OneDrive integration

## Script Sections

1. **Initialization and Connection**

   - Sets up logging
   - Connects to required services

2. **Sensitive Information Types**

   - Defines sensitive information types used in DLP policies

3. **Exchange Online DLP Policy**

   - Configures DLP policy and rules for Exchange Online

4. **Non-Exchange DLP Policies**

   - Sets up DLP policies and rules for SharePoint, OneDrive, and Teams

5. **Sensitivity Labels**

   - Creates or updates sensitivity labels

6. **Sensitivity Label Policy**

   - Configures the default sensitivity label policy

7. **SharePoint and OneDrive Integration**
   - Enables AIP integration for SharePoint and OneDrive

## Customization

You can customize the script by modifying:

- Sensitive information types in the `Get-SensitiveInfoTypes` function
- Policy and rule names, priorities, and actions in the respective functions
- Sensitivity label names and settings

## Logging

The script creates a log file in the same directory, named `DLPConfig_[Timestamp].log`. This log contains information about each action performed and any errors encountered.

## Caution

This script makes significant changes to your Microsoft 365 environment. It's recommended to:

1. Review the script thoroughly before running
2. Test in a non-production environment first
3. Backup your current DLP and sensitivity label configurations before running
