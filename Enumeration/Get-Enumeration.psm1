function Get-Enumeration(){
    # I've had to nest the specific functions inside this single-giant function.
    # This is so that when you call invoke-command you can just pass through a single function, instead of 100 little ones.
    # it makes it heaps easier to enumerate.
    param(
    [Parameter(Mandatory=$true)]
    [System.Management.Automation.PSCredential]$Credential
    )
    function Get-OSInfo(){
        # OS - Uses WMI.
        # Returns a PSObject/hashtable.
        $hostdata = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object * -ExcludeProperty CimSystemProperties,CimClass,CimInstanceProperties,PSComputerName, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container
        $qfe = Get-CimInstance -ClassName Win32_quickfixengineering | Select-Object * -ExcludeProperty CimSystemProperties,CimClass,CimInstanceProperties,PSComputerName, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container
        $systime = Get-Date
    
        #create an empty hashtable (dict in python)
        $return_data = @{}
        #add the data collected to the hashtable.. so now you can use $hostdata["ComputerSystem"] to find the data.
        $return_data.add("ComputerSystem", $hostdata)
        $return_data.add("Patches", $qfe)
        $return_data.add("System Time", $systime)
    
        #return the hashtable.
        return $return_data
    }
    # Network
    
    function Get-NetInfo(){
        #define the schema i wanna return    
        $output = @{
            Netstat = New-Object System.Collections.Generic.List[System.Object]
            IpAddress = ""
            Raw = @{
                Netstat = ""
                UDPStat = ""
                Ipconfig = ""
                Arp = ""
                Route = ""
                FirewallRules = ""
                FirewallSetting = ""
                DNSHistory = ""
            }
            Count = @{
                TCP = 0
                UDP = 0
                Routes = 0
                Arp = 0
                FirewallRules = 0
                FirewallSetting = 0
                DNSHistory = 0
            }
        }
    
        #get the tcp netstat. Loop through results of the command, and only add relevant fields to the return results.
        # State is being cast to a string, which forces powershell to lookup the enum. (It turns integers into their values - 0 -> listening etc..)
        $tcpdata = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        ForEach($conn in $tcpdata){
            $output.Netstat.Add(@{
                "LocalAddress"=$conn.LocalAddress;
                "RemoteAddress"=$conn.RemoteAddress;
                "LocalPort"=$conn.LocalPort;
                "RemotePort"=$conn.RemotePort;
                "State"=($conn.State -as [string]);
                "OwningProcess"=$conn.OwningProcess
            })
        }
    
        #add the raw fields and their counts.
        $output.Raw.Netstat = $tcpdata | Format-Table | Out-String
        $output.Count.TCP = $tcpdata.Count

        $tempUDP = Get-NetUDPEndpoint
        $output.Raw.UDPStat = $tempUDP | Format-Table | Out-String
        $output.Count.UDP = $tempUDP.Count

        $tempIPconfig = Get-NetIPConfiguration
        $output.Raw.Ipconfig = $tempIPconfig | Format-List | Out-String

        $tempARP = Get-NetNeighbor
        $output.Raw.Arp = $tempARP | Format-Table | Out-String
        $output.Count.Arp = $tempARP.Count

        $tempRoute = Get-NetRoute
        $output.Raw.Route = $tempRoute | Format-Table | Out-String
        $output.Count.Route = $tempRoute.Count

        #i dont want 127.0.0.1 in the results
        $output.IpAddress = (Get-NetIPAddress -AddressState Preferred -AddressFamily IPv4).IPAddress | Where-Object {$_ -ne "127.0.0.1"}

        $tempFWRule =  Get-NetFirewallRule -All
        $output.Raw.FirewallRules = $tempFWRule | Format-List | Out-String
        $output.Count.FirewallRules = $tempFWRule.Count

        $tempFWSetting =  Get-NetFirewallSetting -All
        $output.Raw.FirewallSetting = $tempFWSetting | Format-List | Out-String
        $output.Count.FirewallSetting = $tempFWSetting.Count

        $tempDNSHist =  Get-DnsClientCache
        $output.Raw.DNSHistory = $tempDNSHist  | Format-List | Out-String
        $output.Count.DNSHistory = $tempDNSHist.Count
    
        #return the giant hashtable.
        return $output
    }
    
    
    function Get-FileInfo(){
    
        $output = @{
            Linkfiles_Windows = New-Object System.Collections.Generic.List[System.Object]
            Linkfiles_Office = New-Object System.Collections.Generic.List[System.Object]
            Raw = @{
                WindowsRecent = ""
                OfficeRecent = ""
                Prefetch = ""
                NamedPipes = ""
                CMDLineHistory = ""
                TMPDirs = ""
            }
            Count = @{
                WindowsRecent = 0
                OfficeRecent = 0
                NamedPipes = 0
                CMDLineHistory = 0
                TMPDirs = 0
            }
        }
        # Recently accessed windows files.
        # The times for a link file differ to the actual file times. The creation time of a .lnk file is for when it is first used. If the modification time is different to the creation time then the file has been used more than once.
        $output.Raw.WindowsRecent = Get-ChildItem -path $env:APPDATA\Microsoft\Windows\Recent |Select-Object -Property CreationTime,LastAccessTime,LastWriteTime,Length,Name |Sort-Object -Property LastAccessTime -Descending |Format-Table -Wrap | Out-String
        # Associated file location, this uses the above .lnk fullname information ($linkfiles) and puts it into new object ($WScript) to find the .lnk files targetpath. 
        $linkfiles_windows = Get-ChildItem -path $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent |Sort-Object -Property LastAccessTime -Descending
        $WScript_windows = New-Object -ComObject WScript.Shell
        ForEach($link in $linkfiles_windows){
            try{$output.LinkFiles_Windows.add(@{"FilePath"=$WScript_windows.CreateShortcut($link.FullName).TargetPath;"Item"=$link.Name})}
            catch{$output.LinkFiles_Windows.add(@{"FilePath"="Unknown";"Item"=$link.Name})}
            #count
            $output.Count.WindowsRecent++
        }
        
        # Recently accessed office files.
        # The times for a link file differ to the actual file times. The creation time of a .lnk file is for when it is first used. If the modification time is different to the creation time then the file has been used more than once.
        $output.Raw.OfficeRecent = Get-ChildItem -path $env:APPDATA\Microsoft\Office\Recent |Select-Object -Property CreationTime,LastAccessTime,LastWriteTime,Length,Name |Sort-Object -Property LastWriteTime -Descending |Format-Table -Wrap | Out-String
        # Associated file location, this uses the above .lnk fullname information ($linkfiles) and puts it into new object ($WScript) to find the .lnk files targetpath.
        $linkfiles_office = Get-ChildItem -path $env:USERPROFILE\AppData\Roaming\Microsoft\Office\Recent |Sort-Object -Property LastAccessTime -Descending
        ForEach($link in $linkfiles_office){
            try{$output.LinkFiles_Office.add(@{"FilePath"=$WScript_windows.CreateShortcut($link.FullName).TargetPath;"Item"=$link.Name})}
            catch{$output.LinkFiles_Office.add(@{"FilePath"="Unknown";"Item"=$link.Name})}
            #count
            $output.Count.OfficeRecent++
        }
        
        #Prefetch files (Creation Time), admin privileges required to access C:\Windows\Prefetch.
        $tempPrefetch = Get-ChildItem -Path C:\Windows\Prefetch 
        $output.Raw.Prefetch = $tempPrefetch | Select-Object -Property LastWriteTime,CreationTime,Length,Name | Out-String
        $output.Count.Prefetch = $tempPrefetch.Count

        #Named pipes, using .net framework but using get-childitem will provide more property objects.
        $tempPipes =  Get-ChildItem -Path \\.\pipe\
        $output.Raw.NamedPipes = $tempPipes |Select-Object -Property FullName | Out-String
        $output.Count.NamedPipes = $tempPipes.Count

        #Commandline History
        $tempCMDHist =  Get-History
        $output.Raw.CMDHistory = $tempCMDHist | Out-String
        $output.Count.CMDLineHistory = $tempCMDHist.Count

        return $output
    }
    
    function Get-UserInfo(){
        #define the schema i wanna return    
        $output = @{
            Accounts = New-Object System.Collections.Generic.List[System.Object]
            Groups = New-Object System.Collections.Generic.List[System.Object]
            Raw = @{
                LocalUsers = ""
                LocalAdmins = ""
            }
            Count = @{
                LocalUsers = 0
                LocalAdmins = 0
            }
        }
        
        Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount = True" | 
        ForEach-Object {
            $group = $_.Name
            (Get-CimInstance -ClassName Win32_GroupUser -Filter "GroupComponent = `"Win32_Group.Domain='$($_.Domain)',Name='$($_.Name)'`"").PartComponent | 
                ForEach-Object {
                    if($_ -ne $null){
                        $output.Groups.Add(@{"Group" = $group;"MemberDomain" = $_.Domain;"Member" = $_.Name})
                        #add the localadmins count below //// this will miss administrators that arent in the "Administrators" default group. (custom groups etc.)
                        if($group -eq "Administrators"){
                            $output.Count.LocalAdmins++
                        }
                    }
                }
        }
    
        $useraccounts = Get-CimInstance -ClassName Win32_UserAccount | Select-Object * -ExcludeProperty CimSystemProperties,CimClass,CimInstanceProperties,PSComputerName, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container
        ForEach($account in $useraccounts){
            $output.Accounts.Add($account)
            $output.Count.LocalUsers++
        }

        $output.Raw.LocalUsers = net.exe user | Out-String
        $output.Raw.LocalAdmins = net.exe localgroup Administrators | Out-String
        # the below command needs admin login creds.
        $output.Raw.LoggedIn = C:\Windows\system32\quser.exe | Out-String
    
        ## TODO: ACTIVE DIRECTORY ENUM.
        # definately worth a discussion here. The get-aduser commands will query LDAP/Domain for user information. This should be the same results 
        # regardless of what host it is ran on.. its all querying the same resource.
        # I propose that instead of including active directory info in this script, craft a separate one to enum the domaininfo.
    
        #need to error check this line. try/catch/ install the module etc.. #for this to work, we need to have the RSAT tools on the host. 
        #import-module ActiveDirectory
        #$ADusers = Get-ADUser -filter * 
        # $Admins = Get-ADGroupMember -Identity Administrators
        # $ServicedAccounts = Get-ADServiceAccount -filter *     
        # $userInfo = ("$NetUser, $ADUsers, $Admins, $ServicedAccounts") 
        
        return $output 
        
    }
    
    # software
    function Get-SoftwareAndVersion(){
        $output = @{
            Software = New-Object System.Collections.Generic.List[System.Object]
            Count = 0
        }
        #Outputs two fields. The Name of the software and the version.
        $res = Get-WmiObject -Class Win32_Product | Select-Object Name, Version 
        ForEach($item in $res){
            $output.Software.Add($item)
            $output.Count++
        }
    }

    function Get-Processes(){
        $output = @{
            Processes = New-Object System.Collections.Generic.List[System.Object]
            Raw = ""
            Count = 0
        }
        #Outputs two fields. The Name of the software and the version.
        $res = Get-CimInstance -Class Win32_Process | Select-Object Name,ProcessId,ParentProcessId,CommandLine
        ForEach($item in $res){
            $output.Processes.Add($item)
            $output.Count++
        }
        $output.Raw = $res | Out-String
        return $output
    }
    
    function Get-Autoruns(){
        $output = @{
            StartupCommand = New-Object System.Collections.Generic.List[System.Object]
            Registry = New-Object System.Collections.Generic.List[System.Object]
            SchedTasks = New-Object System.Collections.Generic.List[System.Object]
            Raw = @{
                StartupCommand = ""
            }
            Count = @{
                StartupCommand = 0
                RegistryValue = 0
                SchedTasks = 0
            }
        }
    
        #get the runkeys (you can add more if you want)
        $regkeys = @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SYSTEM\CurrentControlSet\Services','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices')
        ForEach ($key in $regkeys){
            $values = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSDrive,PSProvider,PSChildName | Out-string
            $output.Registry.Add(@{"Key"=$key;"Value"=$values})
            $output.Count.RegistryValue++
        }
    
        #Output the programs that execute on boot, their locations on system and who owns them.
        $sucmd = Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User
        ForEach($item in $sucmd){
            $output.StartupCommand.Add($item)
            $output.Count.StartupCommand++
        }
    
        $output.Raw.StartupCommand = ($sucmd | Out-String)
    
        #TODO: add startup folders and at jobs,  etc.
        $tempSched = Get-ScheduledTask 
        $output.SchedTasks = $tempSched | Select-Object TaskPath,TaskName,@{Name="Path"; Expression={$_.Actions.Execute + " " + $_.Actions.Arguments}}
        $output.Count.SchedTasks = $tempSched.Count

        return $output
    
    }
    
    # hardware 
    function Get-HWInfo(){
        $output = @{
            PCI = New-Object System.Collections.Generic.List[System.Object]
            NetworkCards = New-Object System.Collections.Generic.List[System.Object]
            Disks = New-Object System.Collections.Generic.List[System.Object]
            USB = New-Object System.Collections.Generic.List[System.Object]
            CPU = ""
            Memory = New-Object System.Collections.Generic.List[System.Object]
            Raw = @{
                Drivers = ""
                Firmware = ""
            }
        }
        ##PCI device information
        $pciinfo = Get-CimInstance -ClassName win32_pnpentity -Filter "deviceid like '%PCI%'" | Select-Object Name,DeviceID 
        $output.PCI.add($pciinfo)
        
        ##Network cards
        #Get all visible and hidden network adapters
        $networkcards = Get-NetAdapter -Name * -IncludeHidden | Select-Object MacAddress,MediaType,LinkSpeed,Status,InterfaceAlias
        $output.NetworkCards.add($networkcards)
        ##Hard drives
        $hardDrives = Get-CimInstance -ClassName Win32_LogicalDisk | Select-Object DeviceID,DriveType,Size,FreeSpace 
        $output.Disks.add($hardDrives)
        
        ##drivers
        $output.Raw.Drivers = driverquery | Out-String
    
        #firmware
        $output.Raw.Firmware = Get-Ciminstance -Classname Win32_Bios | Select-Object SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber,Version | Out-String
    
        #usb devices
        $output.USB = Get-CimInstance -Classname CIM_USBDevice | Select-Object DeviceID,Name 
        
        #CPU type
        $output.CPU = get-wmiobject win32_processor | Select-Object Name | Out-String
    
        #memory information
        $colRAM = Get-WmiObject -Class "win32_PhysicalMemory" -namespace "root\CIMV2"
        Foreach ($objRAM In $colRAM) {
            $output.Memory.Add( @{Slot=$objRAM.DeviceLocator; Size=($objRAM.Capacity / 1GB)} )
        }
    
        return $output
    }

    #the actual enumeration occurs here
    $results = @{}
    $osinfo = Get-OSInfo
    $results.add("OS", $osinfo)
    
    $netinfo = Get-NetInfo
    $results.add("NET", $netinfo)
    
    $fileinfo = Get-FileInfo
    $results.add("FILE", $fileinfo)
    
    $userinfo = Get-UserInfo
    $results.add("USER", $userinfo)
    
    $hwinfo = Get-HWInfo
    $results.add("HW", $hwinfo)
    
    $swinfo = Get-SoftwareAndVersion
    $results.add("Software", $swinfo)

    $autoinfo = Get-Autoruns
    $results.add("Autoruns", $autoinfo)

    $processinfo = Get-Processes
    $results.add("PS", $processinfo)

    $results.add("EnumType", "Host")
    $results.add("timestamp",(Get-Date -Format "o") )
    
    return $results
    
}
Export-ModuleMember Get-Enumeration