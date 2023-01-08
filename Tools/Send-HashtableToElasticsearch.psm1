function Send-HashtableToElasticsearch {
        <#
    .SYNOPSIS
    Sends a hashtable to Elasticsearch as a JSON document.

    .DESCRIPTION
    This function converts the hashtable to a JSON document and sends it to Elasticsearch using the Elasticsearch PowerShell module. The function can also handle authentication with Elasticsearch, if a PSCredential is provided.

    .PARAMETER Hashtable
    The fields and values to send to Elasticsearch, as a hashtable.

    .PARAMETER IndexName
    The name of the Elasticsearch index to send the document to.

    .PARAMETER ElasticsearchUrl
    The URL of the Elasticsearch endpoint. Default: "http://localhost:9200"

    .PARAMETER Credential
    A PSCredential object containing the username and password to use for authentication with Elasticsearch.

    .PARAMETER SkipCertCheck
    If the elasticsearch is running an untrusted tls cert, specify this switch to skip the check.

    .EXAMPLE
    Send-HashtableToElasticsearch -Hashtable @{"field1"="value1";"field2"="value2";"field3"="value3"} -IndexName "myindex"

    Sends the fields and values in the hashtable to Elasticsearch, using the index named "myindex".

    .EXAMPLE
    $credential = Get-Credential
    Send-HashtableToElasticsearch -Hashtable @{"field1"="value1";"field2"="value2";"field3"="value3"} -IndexName "myindex" -Credential $credential

    Another Example, for sending arrays of objects :
    $ps = Get-Process | Select-Object Id,Name,CommandLin
    Send-HashtableToElasticsearch -Hashtable @{"Processes"=$ht} -ElasticsearchUrl 'https://elasticsearch.secsh3ll.com' -IndexName sampleindex -Credential $creds

    Prompts the user to enter a username and password, and then uses those credentials to authenticate with Elasticsearch when sending the fields and values in the hashtable to the index named "myindex".
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Hashtable,

        [Parameter(Mandatory=$true)]
        [string]$IndexName,

        [string]$ElasticsearchUrl = "http://localhost:9200",

        [System.Management.Automation.PSCredential]$Credential,

        [switch] $SkipCertCheck
    )

    # Import the required libraries
    # Convert the hashtable to a JSON document
    $json = $Hashtable | ConvertTo-Json -Depth 10 -Compress
    
    # Set the credentials, if provided
    if ($Credential) {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
    }

    if ($SkipCertCheck){
        # Adding certificate exception and TLS 1.2 
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    # Build the URI
    $Uri = [string]::Format("{0}/{1}/_doc",$ElasticsearchUrl, $IndexName)

    # Build the Auth Headers, if authentication is provided.
    if($username){
        $Header = @{
            "Authorization" = [string]::Format("Basic {0}", [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password)))
        }
    }else{
        $Header = @{}
    }
    

    # Index the doc.
    $result = Invoke-RestMethod -Method POST -Headers $Header -ContentType "application/json" -Uri $Uri -Body $json
    if ($result.result -eq 'created' ) {
        Write-Host "Successfully indexed document with ID $($result._id) in index $($result._index)"
    } else {
        Write-Host "Failed to index document: $($result)"
    }
}
Export-ModuleMember -Function Send-HashtableToElasticsearch