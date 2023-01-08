function Get-DomainEnum {
    <#
    .SYNOPSIS
    Enumerates information about a domain, including users, computers, trusts, domain controllers, and domain details.
    
    .PARAMETER AccountCredential
    The credentials to use for accessing the domain. This parameter is required.
    
    .PARAMETER DC
    The domain controller to use for the enumeration. If not specified, the default domain controller will be used.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$AccountCredential,
        [Parameter()]
        [string]$DC
    )
    Import-Module ActiveDirectory

    $results = @{
        EnumType = "Domain"
        ADUsers = @{}
        ADComputers = @{}
        ADTrusts = @{}
        DomainController = @{}
        Domain = @{}
        Count = @{
            DomainAdmins = 0
        }
    }
    $results.ADUsers = Get-ADUser -Filter * -Server $DC -Credential $AccountCredential | Select-Object DistinguishedName,Name,ObjectClass,SamAccountName,UserPrincipalName
    $results.ADComputers = Get-ADComputer -Filter * -Server $DC -Credential $AccountCredential | Select-Object DistinguishedName,DNSHostName,Name,ObjectClass,SamAccountName
    $results.ADTrusts = Get-ADTrust -Filter * -Server $DC -Credential $AccountCredential
    $results.DomainController = Get-ADDomainController -Filter * -Server $DC -Credential $AccountCredential
    $results.Domain = Get-ADDomain -Server $DC -Credential $AccountCredential | Select-Object Name,NetBIOSName,PDCEmulator,RIDMaster,DistinguishedName,DNSRoot,DomainControllersContainer,DomainMode,Forest,InfrastructureMaster 
    
    $domadmins = Get-ADGroupMember "domain admins" -Server $DC -Credential $AccountCredential  | Select-Object Name,SamAccountName
    $results.DomainAdmins = $domadmins
    $results.Count.DomainAdmins = $domadmins.Count

    $results.add("timestamp",(Get-Date -Format "o") )
    
    return $results

}
Export-ModuleMember Get-DomainEnum
