
function Convert-IPtoSnort {
    <#
    .SYNOPSIS
    Generates a list of Snort rules that block the specified IP addresses

    .PARAMETER ipAddresses
    An array of IP addresses to generate rules for

    .OUTPUTS 
    An array of Snort rules that block the specified IP addresses

    .EXAMPLE
    GenerateSnortRules -ipAddresses "10.0.0.1", "10.0.0.2"

    Output:
    alert ip 10.0.0.1 any -> any any (msg: "IP address 10.0.0.1 marked by CTK rule"; sid:69493265;)
    alert ip 10.0.0.2 any -> any any (msg: "IP address 10.0.0.2 marked by CTK rule"; sid:69493266;)
    #>
    param(
        $IPAddresses
    )
    # Loop through each IP address in the array
    $res = @()
    $sid = Get-Random -Minimum 69000000 -Maximum 71000000;
    foreach ($ip in $IPAddresses) {
        # Generate a Snort rule for the current IP address
        $rule = [string]::format("alert ip {0} any -> any any (msg: `"IP address {0} marked by CTK rule`"; sid:{1};)",$ip, $sid)
        $sid +=1;
        # Write the rule to the console
       $res += $rule
    }
    return $res
}


function Send-RulestoSecOnion{
    #You can add NIDS rules in /opt/so/saltstack/local/salt/idstools/local.rules on your manager. Within 15 minutes, Salt should then copy those rules into /opt/so/rules/nids/local.rules. The next run of idstools should then merge /opt/so/rules/nids/local.rules into /opt/so/rules/nids/all.rules which is what Suricata reads from.You can add NIDS rules in /opt/so/saltstack/local/salt/idstools/local.rules on your manager. Within 15 minutes, Salt should then copy those rules into /opt/so/rules/nids/local.rules. The next run of idstools should then merge /opt/so/rules/nids/local.rules into /opt/so/rules/nids/all.rules which is what Suricata reads from.
    <#
    .SYNOPSIS
    Pushes the generated ruleset to the security onion node.

    .PARAMETER SOIP
    The security onion IP address.

    .PARAMETER SOCredential
    The credentials for security onion ssh (so-admin is the default username)
    .PARAMETER Rules
    The array of rules to push
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SOIP,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$SOCredential,
        [Parameter(Mandatory=$true)]
        $Rules
    )
    #example rule: alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root 2"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:7000000; rev:1;)
    
    #load the rules into a string format
    $rulefile = ""
    foreach($rule in $Rules){
        Write-Verbose "Wrapping: $rule"
        $rulefile += $rule
        $rulefile += "`n"
    }

    #use plink to write local.rules as root. (soadmin doesnt have access)
    Write-Warning "Starting SSH Session to $SOIP with provided credentials..."
    $procInfo = New-Object System.Diagnostics.ProcessStartInfo
    $procInfo.RedirectStandardInput = $true
    $procInfo.FileName=".\ThirdParty\plink.exe"
    $procInfo.Arguments = "-t $SOIP"
    $procInfo.UseShellExecute = $false

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $procInfo
    [void]$process.Start()

    Start-Sleep -m 1000
    $process.StandardInput.WriteLine($SOCredential.GetNetworkCredential().UserName)
    Start-Sleep -m 1000
    $process.StandardInput.WriteLine($SOCredential.GetNetworkCredential().Password)
    Start-Sleep -m 1000
    $process.StandardInput.Write("sudo su -`n")
    Start-Sleep -m 3000
    $process.StandardInput.Write(($SOCredential.GetNetworkCredential().Password + "`n"))
    Start-Sleep -m 1000
    $process.StandardInput.Write("echo '{0}' >> /opt/so/saltstack/local/salt/idstools/local.rules `n" -f $rulefile)
    Start-Sleep -m 1000
    Write-Output ""
    Write-Warning "Remote SSH connection closing..."
    Stop-Process $process
}

function Clear-CustomSORules(){
    param(
        [Parameter(Mandatory=$true)]
        [string]$SOIP,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$SOCredential,
        [switch]$Confirm
    )
    if(-not $Confirm){
        Write-Warning "This will irrevocably delete all rules from the local.rules file.."
        Write-Warning "You need to confirm with the -Confirm switch"
        return
    }
    Write-Warning "This will irrevocably delete all rules from the local.rules file. Are you really sure?"
    $conf = Read-Host -Prompt "Type YES to confirm"
    if($conf -like "YES"){
            #timestamp
            $DTG = Get-Date
            #use plink to erase local.rules as root. (soadmin doesnt have access)
            Write-Warning "Starting SSH Session to $SOIP with provided credentials..."
            $procInfo = New-Object System.Diagnostics.ProcessStartInfo
            $procInfo.RedirectStandardInput = $true
            $procInfo.FileName=".\ThirdParty\plink.exe"
            $procInfo.Arguments = "-t $SOIP"
            $procInfo.UseShellExecute = $false

            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $procInfo
            [void]$process.Start()

            Start-Sleep -m 1000
            $process.StandardInput.WriteLine($SOCredential.GetNetworkCredential().UserName)
            Start-Sleep -m 1000
            $process.StandardInput.WriteLine($SOCredential.GetNetworkCredential().Password)
            Start-Sleep -m 1000
            $process.StandardInput.Write("sudo su -`n")
            Start-Sleep -m 3000
            $process.StandardInput.Write(($SOCredential.GetNetworkCredential().Password + "`n"))
            Start-Sleep -m 1000
            $process.StandardInput.Write(("echo '# Cleared by CTK @ {0}' > /opt/so/saltstack/local/salt/idstools/local.rules `n" -f $DTG))
            Start-Sleep -m 1000
            Write-Output ""
            Write-Warning "Remote SSH connection closing..."
            Stop-Process $process
            return
    }else{
        Write-Warning "You didn't supply the correct parameter."
    }
}
Export-ModuleMember Clear-CustomSORules
Export-ModuleMember Send-RulestoSecOnion
Export-ModuleMember Convert-IPtoSnort