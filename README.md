# Create Certificate Template in ADCS for PowerShell CMS Encryption

- by Ashley McGlone, Microsoft PFE
- http://aka.ms/GoateePFE
- @GoateePFE

# Problem

Active Directory Certificate Services does not include a template for Document Encryption.
This is required for DSC credential encryption and the CMS encryption cmdlets.
Current processes require manual effort to create the template.
Or you must figure out how to use the less-than-friendly AD CS API from .NET.

PowerShell 5.x features:
- DSC credential encryption
https://docs.microsoft.com/en-us/powershell/dsc/securemof#certificate-requirements
- CMS encryption cmdlets
https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Security/Protect-CmsMessage

# Solution

I reverse-engineered the resulting OID and certificate objects in Active Directory and wrote a function to create this template from code.
This provides a fully-automated solution for creating the template in a lab or production environment.

Functionality
- Take parameters
- Generate a unique OID for the template
- Create the template
- Optionally permission the template with Enroll for specified group(s)
- Optionally add AutoEnroll permission as well
- Optionally publish the template to CA(s)
- Optionally target all operations to a designated DC

Requirements:
- Enterprise AD CS PKI
- Tested on Windows Server 2012 R2 & 2016
- Enterprise Administrator rights
- ActiveDirectory PowerShell Module

Template generated will have these properties:
- 2 year lifetime
- 2003 lowest compatibility level
- Private key not exportable
- Not stored in AD
- Document Encryption
- No digital signature

# Sample Usage
```PowerShell
# Create only the template
# Least valuable approach
New-ADCSTemplateForPSEncryption -DisplayName PowerShellCMS
```

```PowerShell
# Full template creation, permissioning, and deployment
New-ADCSTemplateForPSEncryption -DisplayName PSEncryption -Server dc1.contoso.com -GroupName G_DSCNodes -AutoEnroll -Publish

# From a client configured via GPO for AD CS autoenrollment:
$Req = @{
    Template          = 'PSEncryption'
    Url               = 'ldap:'
    CertStoreLocation = 'Cert:\LocalMachine\My'
}
Get-Certificate @Req
# Note: If you have the Carbon module installed, it conflicts with Get-Certificate native cmdlet.

$DocEncrCert = (dir Cert:\LocalMachine\My -DocumentEncryptionCert | Sort-Object NotBefore)[-1]

Protect-CmsMessage -To $DocEncrCert -Content "Encrypted with my new cert from the new template!"
```

# Future

I would like to see someone take this and turn it into a DSC resource in the xAdcsDeployment module.
https://www.powershellgallery.com/packages/xAdcsDeployment
