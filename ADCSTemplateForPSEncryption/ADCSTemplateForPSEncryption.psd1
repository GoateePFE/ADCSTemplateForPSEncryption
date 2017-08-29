@{
RootModule = '.\ADCSTemplateForPSEncryption.psm1'
ModuleVersion = '1.0.0'
GUID = 'cd27da6a-5eb5-4d24-8b00-a813724be61a'
Author = 'Ashley McGlone (GoateePFE)'
CompanyName = 'Microsoft'
Copyright = '(c) 2017 Microsoft. All rights reserved.'
Description = 'Creates a new Active Directory Certificate Services template for PowerShell encryption. The template can be used for CMS cmdlet encryption and/or DSC credential encryption.'
PowerShellVersion = '5.0'
PowerShellHostVersion = '5.0'
RequiredModules = @('ActiveDirectory')
FunctionsToExport = 'New-ADCSTemplateForPSEncryption'
PrivateData = @{
    PSData = @{
        Tags = @('certificate','template','ADCS','ActiveDirectoryCertificateServices','ActiveDirectory','encryption','DSC','CMS')
        LicenseUri = 'https://github.com/GoateePFE/ADCSTemplateForPSEncryption/blob/master/LICENSE'
        ProjectUri = 'https://github.com/GoateePFE/ADCSTemplateForPSEncryption'
        ReleaseNotes = 'Aug 29, 2017 - Initial release'
    }
}
HelpInfoURI = 'https://github.com/GoateePFE/ADCSTemplateForPSEncryption'
}
