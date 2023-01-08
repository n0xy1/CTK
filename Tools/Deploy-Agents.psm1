function Deploy-Sysmon {
    <#
    .SYNOPSIS
    Deploys Sysmon to a target PC and configures it with a specified configuration file.
    
    .PARAMETER SysmonFile
    The path to the Sysmon executable file. This parameter is required.
    
    .PARAMETER SysmonConfig
    The path to the Sysmon configuration file. This parameter is required.
    
    .PARAMETER TargetPC
    The name or IP address of the target PC to deploy Sysmon to. This parameter is required.
    
    .PARAMETER TargetDirectory
    The directory on the target PC where Sysmon should be installed. This parameter is required.
    
    .PARAMETER Credentials
    The credentials to use for accessing the target PC. This parameter is required.
    
    .PARAMETER OverrideConfig
    A switch to indicate that the configuration file should be used to override any existing Sysmon configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SysmonFile,
        [Parameter(Mandatory=$true)]
        [string]$SysmonConfig,
        [Parameter(Mandatory=$true)]
        [string]$TargetPC,

        [Parameter(Mandatory=$true)]
        [string]$TargetDirectory,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credentials,
    
        [switch]$OverrideConfig
    )
    $ErrorActionPreference = 'Stop'
    
    #fixup trailing \
    If($TargetDirectory.EndsWith("\")){
        $TargetDirectory = $TargetDirectory.TrimEnd("\")
    }

    #parse file formats
    if ($SysmonFile -match "([^\\]+\.exe)$"){
        $SysmonFileStripped = $Matches[1]
    }else{
        Write-Error "Error parsing -SysmonFile (Should be of format: '.\path\to\Sysmon.exe')"
        return
    }
    
    if ($SysmonConfig -match "([^\\]+\.xml)$"){
        $SysmonConfigStripped = $Matches[1]
    }else{
        Write-Error "Error parsing -SysmonConfig`t(Should be of format: '.\path\to\Sysmonconfig.xml')"
        return
    }
    

    $session = New-PSSession -ComputerName $TargetPC -Credential $Credentials
    Write-Verbose "Copying $SysmonFile to $TargetPC $TargetDirectory\$SysmonFileStripped"
    Copy-Item -Path $SysmonFile -Destination "$TargetDirectory\$SysmonFileStripped" -ToSession $session -Force
    Copy-Item -Path $SysmonConfig -Destination "$TargetDirectory\$SysmonConfigStripped" -ToSession $session -Force
    Write-Verbose "Copying $SysmonConfig to $TargetPC $TargetDirectory\$SysmonConfigStripped"
    Remove-PSSession $session 


   
    # Install Sysmon
    Invoke-Command -ComputerName $TargetPC -Credential $Credentials -ScriptBlock {
        # Check if its running
        If((Get-Service *sysmon*) -and (-not $Using:OverrideConfig)){
            return "Sysmon already deployed on $Using:TargetPC`t(Re-run with -OverrideConfig to force the new configuration.)"
        }
        # Check hash
        Get-FileHash -Algorithm SHA256 -Path "$Using:TargetDirectory\$Using:SysmonFileStripped"
        # configure sysmon here..
        Start-Process -FilePath "$Using:TargetDirectory\$Using:SysmonFileStripped" -ArgumentList '-i',"$Using:TargetDirectory\$Using:SysmonConfigStripped",'-accepteula'
        # start the service
        Get-Service *sysmon*
        # wait for success
    } -ErrorAction Stop

}
Export-ModuleMember Deploy-Sysmon