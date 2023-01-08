class IPDetail {
    # This class represents details about an IP address, including the network address, broadcast address, subnet mask, IP address, and CIDR.
    #
    # The Network property represents the network address of the IP address.
    # The Broadcast property represents the broadcast address of the IP address.
    # The Mask property represents the subnet mask of the IP address.
    # The IP property represents the IP address.
    # The CIDR property represents the CIDR of the IP address.
    #
    # The ToString method returns the string representation of the IP address.
    [System.Net.IPAddress] $Network
    [System.Net.IPAddress] $Broadcast
    [System.Net.IPAddress] $Mask
    [System.Net.IPAddress] $IP
    [int]$CIDR
    [string] ToString(){
        return $this.IP.ToString()
    }
}
 
function IPConstruct() {
    <#
    .SYNOPSIS
    Converts an IP address and CIDR into a custom object that includes the IP address, network address, broadcast address, subnet mask, and CIDR.
    
    .PARAMETER IPAddress
    The IP address to convert. This parameter can be in the form of an IP address or an IP address with a CIDR, for example "192.168.0.1/24". This parameter is required.
    
    .PARAMETER cidr
    The CIDR to use for the conversion. If the IPAddress parameter is in the form of an IP address with a CIDR, this parameter is optional and will be ignored.
#>
    param(
        [string]$IPAddress,
        [int]$cidr
    )
    # A little helper function to conver and ipaddress and cidr into a IPDetail, which includes IP Address, Network address, Broadcast addres, Subnet Mask and Cidr
    if ($IPAddress.Contains("/")){
        $splitty = $IPAddress.Split("/")
        $parsedIpAddress = [System.Net.IPAddress]::Parse($splitty[0])
        $cidr = $splitty[1]
    }else{
        $parsedIpAddress = [System.Net.IPAddress]::Parse($IPAddress)
    }
    $shift = 64 - $cidr
    [System.Net.IPAddress]$subnet = 0
    if ($cidr -ne 0) {
        $subnet = [System.Net.IPAddress]::HostToNetworkOrder([int64]::MaxValue -shl $shift)
    }
    [System.Net.IPAddress]$network = $parsedIpAddress.Address -band $subnet.Address

    $a = [uint32[]](($subnet).ToString()).split('.')
    $ipValue = [uint32]($a[3] -shl 24) + ($a[2] -shl 16) + ($a[1] -shl 8) + $a[0]
    $broadcastAddress = [System.Net.IPAddress]::New(([System.BitConverter]::GetBytes((([System.BitConverter]::ToInt32((([System.Net.IPAddress](-bnot $ipValue)).GetAddressBytes()), 0)) -bor ([System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($parsedIpAddress).GetAddressBytes()), 0))))))

    return [IPDetail]@{
        IP = $parsedIpAddress
        Network = $network
        Mask = $subnet
        Broadcast = $broadcastAddress
        CIDR = $cidr
    }
}

# A little helper function to conver and ipaddress and cidr into a IPDetail, which includes IP Address, Network address, Broadcast addres, Subnet Mask and Cidr
# you can call .ToString() on the IPDetail and itll just return the IP, without the extra fluff.
# IPConstruct -IPAddress "10.1.0.20" -Cidr 24
# IPConstruct -IPAddress "10.1.100.10/17"