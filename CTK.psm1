function Get-RemoteEnum(){
    <#
    .SYNOPSIS
    Conducts a brief enumeration of a remote computer via ps remoting.

    .DESCRIPTION
    The function iterates over each target computer in the `$Targets` list and runs the `Get-Enumeration` script block on the remote computer using the `Invoke-Command` cmdlet.
    Specify the IndexIt switch, and elastic creds / url if you want it to be indexed. Otherwise, it just saves to a JSON formatted file.

    .PARAMETER Targets
    This parameter is mandatory and represents a list of target computers that the function will enumerate..

    .PARAMETER Credential
    This parameter is also mandatory and represents the credentials that will be used to connect to the target computers

    .PARAMETER IndexIt
    This is a switch parameter that indicates whether or not the enumeration results should be indexed into elasticsearch

    .PARAMETER ElasticUrl
    This is an optional parameter of type `string` that specifies the URL of an Elasticsearch instance..

    .PARAMETER SkipCertCheck
    This is an optional that specifies the whether the TLS certficate of the elasticsearch database should be verified. If this is a private/self-signed cert, you probably want this.

    .EXAMPLE
    Send-HashtableToElasticsearch -Hashtable @{"field1"="value1";"field2"="value2";"field3"="value3"} -IndexName "myindex"

    Sends the fields and values in the hashtable to Elasticsearch, using the index named "myindex".

    .EXAMPLE
    $credential = Get-Credential
    $elkcreds = Get-Credential
    Get-RemoteEnum -Targets @('dc01.int.secn3t.com') -Credential $credential -ElasticCreds $elkcreds -IndexIt -ElasticUrl 'https://elasticsearch.secsh3ll.com' -SkipCertCheck

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $Targets,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential,

        [switch] $IndexIt,

        [string]$ElasticUrl,
        [string]$ElasticIndex = 'enumeration',
        [System.Management.Automation.PSCredential]$ElasticCreds
    )
    
    ForEach($pc in $Targets){
        Write-Output "Enumerating $pc"
        $enum = Invoke-Command -ComputerName $pc -Credential $Credential -ScriptBlock ${Function:Get-Enumeration} -ArgumentList $Credential
        $enum.Remove('PSComputerName')
        $enum.Remove('PSShowComputerName')
        $enum.Remove('RunspaceId')
        if($IndexIt){
            Write-Output "Indexing enum for $pc"
            try{
                Send-HashtableToElasticsearch -ElasticsearchUrl $ElasticUrl -IndexName $ElasticIndex -Credential $ElasticCreds -Hashtable $enum
            }
            catch {
                Write-Error "Unable to index the document.. "
                Write-Error $_
                #save the enum locally as a .json if this indexing fails.
                $enum | convertto-json -depth 40 | out-file ("{0} - {1} - Enumeration.json" -f $data.timestamp,$pc)
            }
        }else{
            Write-Output "Enum completed.. IndexIt not specified, saving to json locally."
            $enum | convertto-json -depth 40 | out-file ("{0} - {1} - Enumeration.json" -f $data.timestamp,$pc)
        }


    }
}

function Get-RemoteDomainEnum() {
    <#
    .SYNOPSIS
    Conducts a brief enumeration of a domain through ps remoting. The target must be a domain-joined computer, and the dns hostname of the domain controller is required for this to function correctly.

    .DESCRIPTION
    The function iterates over each target computer in the `$Targets` list and runs the `Get-ADEnumeration` script block on the remote computer using the `Invoke-Command` cmdlet.
    The target can be any domain-joined computer, as long as the domain controllers hostname is passed via the DC parameter.
    Invoking this one more than one computer/target is NOT necessary, they will all return the same information.
    Specify the IndexIt switch, and elastic creds / url if you want it to be indexed. Otherwise, it just saves to a JSON formatted file.

    .PARAMETER Targets
    This parameter is mandatory and represents a list of target computers that the function will enumerate..

    .PARAMETER DC
    This parameter is mandatory and is the dns hostname of the domain controller. 

    .PARAMETER Credential
    This parameter is also mandatory and represents the credentials that will be used to connect to the target computers

    .PARAMETER IndexIt
    This is a switch parameter that indicates whether or not the enumeration results should be indexed into elasticsearch

    .PARAMETER ElasticUrl
    This is an optional parameter of type `string` that specifies the URL of an Elasticsearch instance..

    .PARAMETER SkipCertCheck
    This is an optional that specifies the whether the TLS certficate of the elasticsearch database should be verified. If this is a private/self-signed cert, you probably want this.

    .EXAMPLE
    Send-HashtableToElasticsearch -Hashtable @{"field1"="value1";"field2"="value2";"field3"="value3"} -IndexName "myindex"

    Sends the fields and values in the hashtable to Elasticsearch, using the index named "myindex".

    .EXAMPLE
    $credential = Get-Credential
    $elkcreds = Get-Credential
    Get-RemoteADEnum -Targets @('dc01.int.secn3t.com') -DC 'dc01.int.secn3t.com' -Credential $credential -ElasticCreds $elkcreds -IndexIt -ElasticUrl 'https://elasticsearch.secsh3ll.com'

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $Targets,

        [Parameter(Mandatory=$true)]
        $DC,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential,

        [switch] $IndexIt,

        [string]$ElasticUrl,

        [string]$ElasticIndex = 'enumeration',

        [System.Management.Automation.PSCredential]$ElasticCreds
    )
    
    ForEach($pc in $Targets){
        Write-Output "Enumerating domain.."
        $enum = Invoke-Command -ComputerName $pc -Credential $Credential -ScriptBlock ${Function:Get-DomainEnum} -ArgumentList ($Credential, $DC)
        $enum.Remove('PSComputerName')
        $enum.Remove('PSShowComputerName')
        $enum.Remove('RunspaceId')
        if($IndexIt){
            Write-Output "Indexing enum for $pc"
            try{
                Send-HashtableToElasticsearch -ElasticsearchUrl $ElasticUrl -IndexName $ElasticIndex -Credential $ElasticCreds -Hashtable $enum
            }
            catch {
                Write-Error "Unable to index the document.. "
                Write-Error $_
                #save the enum locally as a .json if this indexing fails.
                $enum | convertto-json -depth 40 | out-file ("{0} - {1} - Enumeration.json" -f $data.timestamp,$pc)
            }
        }else{
            Write-Output "Enum completed.. IndexIt not specified, saving to json locally."
            $enum | convertto-json -depth 40 | out-file ("{0} - {1} - Enumeration.json" -f $data.timestamp,$pc)
        }
    }
}

function Write-NmapToElastic(){
    param(
        [Parameter(Mandatory=$true)]
        $Files,
        [string]$ElasticUrl,
        [string]$ElasticIndex = 'enumeration',
        [System.Management.Automation.PSCredential]$ElasticCreds
    )
        <#

    .SYNOPSIS
    Indexes the results of an nmap scan in Elasticsearch.

    .DESCRIPTION
    The Write-NmapToElastic function converts the results of an nmap scan from a file specified by the FileName 
    parameter to a PowerShell object using the Convert-NmapToObject function. It then iterates through the results 
    of the scan and creates an index document for each host that was scanned. The index document includes information 
    about the open ports on the host, the IP address of the host, the type of enumeration performed, the start time 
    and finish time of the scan, and (optionally) the hostname of the host if DNSLookup is specified. The index 
    document is then sent to Elasticsearch using the Send-HashtableToElasticsearch function.

    .PARAMETER Files
    The path and filename of the nmap scan file. This parameter is mandatory.

    .PARAMETER ElasticUrl
    The URL of the Elasticsearch instance where the index documents should be sent.

    .PARAMETER ElasticIndex
    The name of the Elasticsearch index where the index documents should be stored. If ElasticIndex is not 
    specified, the default index name 'enumeration' will be used.

    .PARAMETER ElasticCreds
    The credentials to use when connecting to the Elasticsearch instance.

    .EXAMPLE
    Write-NmapToElastic -Files 'C:\nmap_scans\scan1.xml' -ElasticUrl 'http://localhost:9200' -ElasticCreds (Get-Credential)
    
    Indexes the results of the nmap scan in the file 'C:\nmap_scans\scan1.xml' in Elasticsearch. The index documents are sent to the Elasticsearch instance at 'http://localhost:9200' using the 
    credentials specified by the user. The index documents are stored in the 'enumeration' index.
    
    Write-NmapToElastic -Files 'C:\nmap_scans\scan2.xml' -ElasticUrl 'http://elasticsearch.example.com:9200' -ElasticIndex 'network_enumeration' -ElasticCreds (Get-Credential 'elastic')
    
    Indexes the results of the nmap scan in the file 'C:\nmap_scans\scan2.xml' in Elasticsearch. The index documents are sent to the Elasticsearch 
    instance at 'http://elasticsearch.example.com:9200' using the credentials stored in the 'elastic' credential object. The index documents are stored in the 'network_enumeration' index.
    #>

    #parse all the files with sec505 parser.
    $res = Convert-NmapToObject -path $Files
    #index the results
    foreach($parsed in $res){
        try{
            $ht = @{
                nmap = $parsed
                timestamp = $parsed.StartedAt
                EnumType = "NMAP"
            }
            Send-HashtableToElasticsearch -ElasticsearchUrl $ElasticUrl -IndexName $ElasticIndex -Credential $ElasticCreds -Hashtable $ht
        }
        catch {
            Write-Error "Unable to index the document.. "
            Write-Error $_
        }
    }
}