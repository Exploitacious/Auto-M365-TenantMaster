# Disable Junk Folder for All Users

$Users = get-EXOMailbox -Filter * | select UserPrincipalName

Foreach ($mailbox in $Users) {

    Write-Host $mailbox

    # Set-MailboxJunkEmailConfiguration -Enabled $false -ErrorAction SilentlyContinue

}  -Identity $mailbox 


