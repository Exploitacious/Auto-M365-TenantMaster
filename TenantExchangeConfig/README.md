# Auto-M365-TenantMaster

This script is a collection of things that I've found make life easier for MSPs and their clients in M365 environments. Running this scrript should have no disruptive consequenses and is meant to automate the tenant setup process. This script is safe to run and has been tested in brand new tenants, as well as existing ones. There is no notable user disruption.

Set a few Variables at the top of the script before running it.

# The following items will be configured automatically:

- Enable Organization Customization
- Enable AIP (Azure Information Protection) https://docs.microsoft.com/en-us/azure/information-protection/activate-service
- Disable Microsoft Security Defaults (Optional) https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults

- Create a secondary Admin account called the "Break Glass"
- Create & Configure Groups: "Exclude from CA", "Group Creators", "AutoForwarding-Allowed", "Pilot-IntuneDeviceCompliance"
- Add the two Admin Users to the newly created groups / verify presence
- Create a new Azure AD/EOP Role Group Called "Super Admin" with Permissions such as: Compliance Administrator, Security Administrator, Audit Logs, and more. (These are not assigned to Global Admin by default)


- Turn Off Focused Inbox Mode Organization-Wide (Optional)
- Enable Send-from-Alias Preview Feature
- Enable Naming Scheme for Distribution Lists (DL_<GroupName>)
- Enable Plus Addressing https://docs.microsoft.com/en-us/exchange/recipients-in-exchange-online/plus-addressing-in-exchange-online
- Enable (Not Annoying) Available Mail-Tips for Office 365
- Enable Read Email Tracking
- Enable Public Computer Detection (For OWA)
- Disable Outlook Pay (Microsoft Pay)
- Enable Lean Pop-Outs for OWA in Edge
- Enable Outlook Events Recognition
- Disable Feedback/UserVoice in Outlook Online

- Verify/Set Intune as MDM Authority
- Enable Modern Authentication (non-destructive and will leave legacy Auth on if it's still enabled)
- Delete all intune devices that haven't contacted the tenant in x days (90 is default) (Optional)
- Allow Admin to Access all Mailboxes in Tenant (Allows quick and easy access to mailboxes for administrative purposes without having to wait for permissions) (Optional)
- Set Time and language on all mailboxes (to Variable: Eastern Standard, English USA by Default)
- Disable Group Creation unless User is member of 'Group Creators' Group (Prevents users from creating a bunch of M365 groups willy-nilly)
- Block Consumer Storage in OWA
- Disable Shared Mailbox Interractive Logon
- Block Attachment Download on Unmanaged Assets OWA (May be semi-disruptive if users log in to OWA from personal machines, but only works after correstponding CA POLICY IS ENABLED)
- Set Retention Limit on deleted items (Default 30 Days)
- Enable Unified Audit Logging and search
- Configure the audit log retention limit on all mailboxes (2 Years)
- Set up Archive Mailbox and Litigation mailbox for all available users (if licensing allows. Requires Exo Plan2, M365 Business Premium or Auto-Archiving Add-On) (Optional)
- Enable Auto-Expanding Archive
- Enable the Auto-Archive Mailbox for All Users
- Enable Litigation Hold Shadow Archive for all users