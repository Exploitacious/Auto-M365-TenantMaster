# Auto-M365-DLP
MSP Focused DLP deployment template for M365 Business Premium clients.

The point of this is to deploy an intelligent implementation of DLP on a customer's environment with a simple powershell script, rather than spending hours clicking through the protection.office.com GUI. There are a few things to consider in this script, but it was designed to be relevant and uninstrusive to a very wide range of USA based customers, especially within the small-medium size sector. If you have clients that are require HIPAA or PCI compliance, this script is still a great place to start.


### Policies and Rules Deployed

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


### Recent Updates:
- Removed some Sensitive Info Types
    - Added Connect-CMDlet Option
    - Changed Confidence Level to "High" on High Volume Policy
    - Changed Confidence Level to "High" on Low Volume Policy
- Removed Email policytip/notification for "LastModifier" due to excessive notifications during 'OneDrive Known Folder Migrations'.
- Removed "AzureAD Storage Account Key (Generic)" Information Type which was causing excesive false positives
- Some light script cleanup

I discovered that in practice the "AzureAD Storage Account Key GENERIC" was causing a lot of false positive triggers, and there were false positives triggered due to '75' confidence on all other info types. I have found a lot better of results with using '85' or 'High' confidence for all. I have also discovered that the email template received by users is not very inteligent or informative, so I removed "Last Modifier" from the notification, so the user will only see the policy tips when attempting to share.
