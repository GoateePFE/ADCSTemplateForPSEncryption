# Create Certificate Template in ADCS for PowerShell CMS Encryption

by Ashley McGlone, Microsoft PFE

http://aka.ms/GoateePFE

@GoateePFE

Functionality
- Take parameters
- Generate a unique OID for the template
- Create the template
- Permission the template with Enroll for a specified group(s)
- Optionally add AutoEnroll permission as well
- Optionally publish the template to CA(s)
- Target all operations to the designated DC

Requirements:
- Enterprise AD CS PKI
- Tested on 2012 R2 & 2016
- Enterprise Administrator rights
- ActiveDirectory PowerShell Module

Template generated will have these properties:
- 2 year lifetime
- 2003 lowest compatibility level
- Private key not exportable
- Not stored in AD
- Document Encryption
- No digital signature

Satisfies the document encryption template requires of these PowerShell 5.x features:
- DSC credential encryption
https://docs.microsoft.com/en-us/powershell/dsc/securemof#certificate-requirements
- CMS message cmdlets
https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Security/Protect-CmsMessage
