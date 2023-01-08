function Get-IrisCaseList{
    <#
    .SYNOPSIS
    Gets a list of cases in Iris using the Iris API.
    
    .PARAMETER APIToken
    The API token to use for authenticating the request. This parameter is required.
    
    .PARAMETER IrisURL
    The URL of the Iris instance.
    #>
    param(
    [Parameter(Mandatory=$true)]
    [string]$APIToken,
    [string]$IrisURL
    )
    $res = Invoke-RestMethod -Uri ("{0}/manage/cases/list" -f $IrisURL) -Method GET -ContentType 'application/json' -Headers @{Authorization="Bearer {0}"-f $APIToken}   
    if ($res.status -like 'success'){
        $results = @()
        ForEach($case in $res.data){
            $r = " " | Select-Object CaseID,CaseName,CaseDescription
            $r.CaseID = $case.case_id
            $r.CaseName = $case.case_name
            $r.CaseDescription = $case.case_description
            $results += $r
        }
        return $results
    }
}

function Get-IrisCaseAssets{
    <#
    .SYNOPSIS
    Creates a new asset in Iris using the Iris API.
    
    .PARAMETER APIToken
    The API token to use for authenticating the request. This parameter is required.
    
    .PARAMETER IrisURL
    The URL of the Iris instance.
    
    .PARAMETER CaseID
    The ID of the case to which the asset should be added. Defaults to "1".
    
    .PARAMETER NewAsset
    A hashtable containing the properties of the new asset. This parameter is required.
    An asset should be in this form: @{Name="NameofAsset"; Description="This is the asset description"; IP="Asset ip address"; Type="9"; Status="1"}
    Type 9 = Windows computer, Status 1 = No analysis started
#>
    param(
    [Parameter(Mandatory=$true)]
    [string]$APIToken,
    [string]$IrisURL,
    [string]$CaseID = "1"
    )
    $p = @{
        cid = $CaseID
    }
    $res = Invoke-RestMethod -Uri ("{0}/case/assets/list" -f $IrisURL) -Method GET -ContentType 'application/json' -Headers @{Authorization="Bearer {0}"-f $APIToken} -Body $p
    if ($res.status -like 'success'){
        if ($res.data.assets.count -gt 0){
            return $res.data.assets
        }else{
            return "Case has no assets"
        }
    }
}

function New-IrisAsset{
    param(
    [Parameter(Mandatory=$true)]
    [string]$APIToken,
    [string]$IrisURL,
    [string]$CaseID = "1",
    [Parameter(Mandatory=$true)]
    [hashtable]$NewAsset
    )

    $p = @{
        cid = $CaseID
        asset_name = $NewAsset.Name
        asset_type_id = $NewAsset.Type
        asset_description = $NewAsset.Description
        analysis_status_id = $NewAsset.Status
        asset_ip = $NewAsset.IP
        custom_attributes = @{}
    }
    $res = Invoke-RestMethod -Uri ("{0}/case/assets/add" -f $IrisURL) -Method POST -ContentType 'application/json' -Headers @{Authorization="Bearer {0}"-f $APIToken} -Body ($p|Convertto-Json -depth 2)
    if ($res.status -like 'success'){
        if ($res.data.asset_id){
            return "Added asset: # {0}"-f $res.data.asset_id
        }else{
            return "Error"
        }
    }
}

function Import-IrisAssetFromNmap{
    <#
    .SYNOPSIS
    Imports assets into Iris from a Nmap file using the Iris API.
    
    .PARAMETER APIToken
    The API token to use for authenticating the request. This parameter is required.
    
    .PARAMETER IrisURL
    The URL of the Iris instance.
    
    .PARAMETER CaseID
    The ID of the case to which the assets should be imported. Defaults to "1".
    
    .PARAMETER NmapFile
    The path to the Nmap file to import. This parameter is required.
    #>
    param(
    [Parameter(Mandatory=$true)]
    [string]$APIToken,
    [string]$IrisURL,
    [string]$CaseID = "1",
    [Parameter(Mandatory=$true)]
    $NmapFile
    )
    $res = Convert-NmapToObject -Path $NmapFile

    foreach($h in $res){
        $a =  @{
            Name = $h.Ipv4
            Type = "9"
            Status = "1"
            IP = $h.Ipv4
            Description = "Imported from nmap" -f $h.FinishedAt
        }
        New-IrisAsset -APIToken $APIToken -IrisURL $IrisURL -CaseID $CaseID -NewAsset $a
    }
    
}

function Import-IrisUser{
    <#
    .SYNOPSIS
    Imports a list of users into Iris using the Iris API.
    
    .PARAMETER APIToken
    The API token to use for authenticating the request. This parameter is required.
    
    .PARAMETER IrisURL
    The URL of the Iris instance.
    
    .PARAMETER UserList
    The list of users to import (as an array). This parameter is required.
    #>
    param(
    [Parameter(Mandatory=$true)]
    [string]$APIToken,
    [string]$IrisURL,
    [Parameter(Mandatory=$true)]
    $UserList
    )

    ForEach($user in $UserList){
        $u = @{
            user_name = $user
            user_login = $user
            user_email = "{0}@iris.dco"-f $user
            user_password = "12characterswithoneUPPERCASE"
        }
        $res = Invoke-RestMethod -Uri ("{0}/manage/users/add" -f $IrisURL) -Method POST -ContentType 'application/json' -Headers @{Authorization="Bearer {0}"-f $APIToken} -Body ($u|Convertto-Json)
        if ($res.status -like 'success'){
            if ($res.data.user_login){
                Write-Output ("Added user: {0}" -f $res.data.user_login)
            }else{
                Write-Error ("Error adding {0}" -f $res.data)
            }
        }
    }
}