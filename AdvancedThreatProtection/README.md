# M365 Defender for Office 365 Configuration Script

This script automates the setup process for Microsoft 365 Defender for Office 365 (Plan 2) and Exchange Online. It's designed to be a safe starting point for deploying M365 Defender across various environments, based on customer feedback and iterative improvements.

## Version

2.0

## Description

This script configures Microsoft 365 Defender for Office 365 (Plan 2) settings, including anti-malware, anti-phishing, anti-spam, safe attachments, and safe links policies. It's designed to be safe to deploy after communicating the purpose and expectations of ATP to the client.

## Prerequisites

- Ensure all required PowerShell modules are installed and updated.
- Have an alerting mailbox ready for receiving alerts from your customer's tenant.
- Modify the script variables at the beginning to include your MSP's domain and any email addresses that should be whitelisted by default.
- Ensure your Customer's Global Admin account is licensed for a mailbox (recommended for receiving alerts).

## Features

The script automatically configures:

1. Mail Forwarding and Junk Email Settings
2. Anti-Malware Policy
3. Anti-Phishing Policy
4. Anti-Spam Policy (Inbound and Outbound)
5. Safe Attachments Policy
6. Safe Links Policy
7. Tenant Allow/Block List
8. User Reported Message Submissions

## Usage

1. Run the script with appropriate permissions.
2. Choose options from the menu to configure specific policies or select 'A' to configure all policies.

## Configuration Details

### 1. Mail Forwarding and Junk Email Settings

- Configures automatic forwarding from the customer's admin mailbox to the MSP's alerting address.
- Disables the junk email folder for the admin mailbox to ensure all messages are forwarded.
- Creates an 'Allowed Outbound Forwarding' policy specifically for the admin mailbox.

### 2. Anti-Malware Policy

- Blocks a comprehensive list of potentially malicious file types in email attachments.
- Enables Zero-hour Auto Purge (ZAP) to retroactively remove malicious messages.
- Configures policy tips to notify both internal users and external senders when malware is detected.
- Creates a separate, less restrictive policy for the admin mailbox to prevent false positives on important communications.

### 3. Anti-Phishing Policy

- Implements protection against impersonation attempts and domain spoofing.
- Blocks external senders with display names matching internal users.
- Extends protection to all customer domains automatically.
- Quarantines suspected phishing emails for review.
- Sets the anti-phish aggressiveness to level 2 out of 4, balancing security and usability.

### 4. Anti-Spam Policy

- Configures separate inbound and outbound policies for regular users and admins.
- Sets bulk mail threshold to 6, blocking most unwanted bulk mail while allowing legitimate services like SendGrid.
- Implements quarantine actions for high-confidence spam and phishing attempts.
- Enables alerts for potential outbound spam without blocking legitimate bulk emails.
- Creates a bypass policy for the admin mailbox to ensure important communications are not affected.

### 5. Safe Attachments Policy

- Enables Dynamic Delivery, which allows recipients to read emails while attachments are being scanned.
- Quarantines messages with malicious attachments and sends a notification to the admin.
- Configures a separate policy for the admin mailbox to reduce potential delays on critical communications.

### 6. Safe Links Policy

- Enables URL rewriting for emails, Microsoft Teams, and Office applications.
- Tracks user clicks on links to generate reports on potentially malicious websites.
- Applies time-of-click verification for all URLs in messages and documents.
- Configures custom warning pages for potentially malicious links.

### 7. Tenant Allow/Block List

- Migrates existing allow and block lists from anti-phishing and anti-spam policies to the global tenant list.
- Adds additional whitelisted domains and email addresses specified in the script.
- Ensures that important communications from trusted sources are not blocked by other security measures.

### 8. User Reported Message Submissions

- Configures handling of messages reported by users as potential phishing attempts.
- Sets up automatic forwarding of user-reported messages to the MSP for analysis.
- Enables user notifications to confirm receipt of their reported messages.

Customers should expect:

- Improved protection against various email-based threats including malware, phishing, and spam.
- Potential initial increase in quarantined messages as the system adjusts to the new policies.
- Minimal disruption to normal email flow, with special considerations for the admin mailbox.
- The ability to easily adjust policies if they find certain measures too restrictive or not strict enough.
- Improved visibility into potential threats through admin notifications and user-reported message handling.

Note: While these configurations aim to significantly enhance security, they should be monitored and fine-tuned based on the specific needs and feedback of each customer environment.

## Important Notes

- Review and adjust the default whitelisted domains and senders before deployment.
- The script preserves existing whitelist/blacklist entries and appends new values.
- Policies can be easily adjusted in the GUI after deployment if needed.

## Disclaimer

This script is provided as-is, without any warranty. Always test in a non-production environment before deploying to production.

## Contributions

Contributions and feedback are welcome. If you find this script helpful, consider supporting the author.

## Author

Created by [Your Name/Organization]

For updates and more information, visit [Your Repository URL]
