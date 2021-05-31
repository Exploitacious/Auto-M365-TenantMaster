# Auto-M365-TenantMaster

This script is a collection of things that I've found make life easier for MSPs and clients in M365 environments. Running this scrript should have no disruptive consequenses and is meant to automate the tenant setup process. This script is safe to run and has been tested in brand new tenants, as well as existing ones. There is not notable user disruption.

# The following items will be configured automatically:

- Set Intune as MDM Authority
- Enable Modern Authentication (non-destructive and will leave legacy Auth on if it's still enabled)
- Delete all intune devices that haven't contacted the tenant in x days (90 is default)
- Turn Off Focused Inbox Mode Organization-Wide (This is a preference for our clients)
- Set Time and language on all mailboxes to Eastern Standard, English USA
- Allow Admin to Access all Mailboxes in Tenant (Allows quick and easy access to mailboxes for administrative purposes without having to wait for permissions)
- Disable Group Creation unless User is member of 'Group Creators' Group (Prevents users from creating a bunch of M365 groups willy-nilly)
  - Creates new group called "Group Creators" and adds specified Global Admin as member
- Block Consumer Storage in OWA
- Disable Shared Mailbox Interractive Logon
- Block Attachment Download on Unmanaged Assets OWA (May be semi-disruptive if users log in to OWA from personal machines, but only works after correstponding CA POLICY IS ENABLED)
- Set Retention Limit on deleted items (Default 30 Days)
- Enable Unified Audit Logging and search
- Configure the audit log retention limit on all mailboxes (2 Years)
- Set up Archive Mailbox and Litigation mailbox for all available users (if licensing allows. Requires Exo Plan2, M365 Business Premium or Auto-Archiving Add-On)

* Disabled the last part about forwarding mail to MSP mailbox because it makes more sense to have that one in the ATP Configuration Script.
