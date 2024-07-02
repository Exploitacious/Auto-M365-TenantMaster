# Auto-M365-ATP

This script automates a lot of the set up process of M365 ATP and Exchange Online. This is not the first itteration of this script, and I have been making steady adjustments to it for a few months now based on customer feedback. I beleive it is safe to deploy just about anywhere and is a great place to start with M365 ATP.
This script is safe to run after communicating what ATP is to the client and setting expectations. It's not majorly disruptive, but it'd a good idea to let the customer know.

# Prerequisites
- Make sure you have all powershell modules installed and updated.
- Make sure you have an alerting mailbox you would like to use for receiving alerts from your customer's tenant.
- Make sure you modify the script variables (in the begining of script) to include your MSP's Domain and add any email addresses which should be whitelisted by default.
- Make sure your Customer's Global Admin account is licensed for a mailbox. (Not required, but highly recomended to receive alerts) We like to use M365 F3 that way we can join computers to AAD with all the sweet Intune features, AAD P1, and the account gets a small mailbox for forwarding. (Cost for CSP MSP's.. something like $6.80 a month? Worth it!)

# The following items will be configured automatically:

- Mail Forwarding to MSP from the Customers Admin Mailbox
  - Disable Junk folder on mailbox
  - Create 'Allowed Outbound Forwarding' policy for only this mailbox
  - Automatically forward all received mail

- Anti-Mailware
  - Block certain file types in attachments (Adds Unique file-types instead of overwriting the existing.)
  - Enable ZAP
  - Send policyTips to users and external senders when their mail is found to contain malware

- Anti-Phishing
  - Ingest the current default whitelist / blacklist and apend it to the script. (No need to recreate your whitelisted senders list)
  - Block all external senders with names matching internal users
  - Protect all customer domains
  - Move Suspected phishing to quarantine
  - Set Anti-Phish agressiveness to level 2 (out of 4)

- Anti-Spam (Inbound and Outbound + Admin vs Everyone Else)
  - It's easier to review the actual script if you interested in the configuration for this policy. It has been tuned to what I find is most impactful and least disruptive to clients so it is NOT agressive.
  - WILL NOT DELETE your current whitelists or blocklists under the default Anti-Spam. Will only add values to it.
  - This policy is super easy to adjust in the GUI after the deployment in case customer finds it too aggressive or too lax.
  - Inbound mail policy includes default values I found work well to protect users across the organization, Including the following:
    - Bulk-Mail threshold set to 6. Ths is the sweet spot for us becuase it blocks the badly behaving bulk mail, but anything above 6 will also block SendGrid.
    - No limits set on outbound for end usrs, but alerting is enabled when thresholds are reached.
    - Admin have absolutely no limits. Both incoming and outgoing mail is unmolested. (Except link-requiting. This is set by org level)
    - Very trigger happy with the quarantine. I prefer to not deliver mail to a customer by default, and let them decide if it needs to be delivered.
  - Outbound policy will not stop users from sending outbound mail, but will trigger an alert when over 100 recepients are emailed in a short period of time. This can be great for identifying suspicious behavior but not getting in the way of users who occasionally send bulk mail.

  - Disable all filtering and rules for Global Admin Mailbox - Inbound and Outbound.

- Safe Attachments
  - Scan and Dynamically Deliver attachments in E-Mail messages. ( This policy will deliver the email, but hold the attachment until the scan is complete. It doesn't take long, but some customers may find this annoying. If that's the case, just change the setting [ 'Action' =  "DynamicDelivery"; ] to "Block". I quite enjoy the dynamic delivery, and it lets you preview the attachment in web view in a sandbox.

- Safe Links
  - Scan and re-write links with M365 ATP platform
  - Track user clicks and generate reports of sus websites

!! Be sure to adjust the Default whitelisted domains and senders, as well as your MSP's Alerts Address before deploying this script. !!

I do this in my free time and do not benifit from this, other than knowing customers around the world will miss a few phishing emails and therefore be safer becuase of my work. If I ended up saving your MSP some time and energy, or even brought you the solution you've been looking for, buy me a beer! I like hazy IPA's ;D

paypal.me/aivantsov
