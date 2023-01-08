function Invoke-Analysis{
    param(
        $File
    )

    $res = @{
        Hashes = @{
            md5 = ""
            sha256 = ""
        }
        Magic = @{
            Hex = ""
            ASCII = ""
        }
        LOLBAS = @{
            Match = $false
            Details = ""
            Comment = ""
        }
    }
    Write-Verbose "Getting file hashes"
    $res.Hashes.md5 = (Get-FileHash -Algorithm MD5 -Path $File).Hash
    $res.Hashes.sha256 = (Get-FileHash -Algorithm SHA256 -Path $File).Hash
    $res.Add("Certificate", (Get-AuthenticodeSignature -FilePath $File))

    # file magic bytes
    Write-Verbose "Getting file magic bytes"
    $tmp = (Get-Content -Encoding Byte -ReadCount 1 -TotalCount 2 -Path $File)
    foreach($c in $tmp){   
        $res.Magic.Hex += (("{0:X}" -f $c))
        $res.Magic.ASCII += (("{0}" -f [char]$c))
    }


    # auto search lolbas
    $lolbas = Get-ChildItem -Path .\ThirdParty\LOLBAS\ -Recurse
    $fn = $File.split(".")[0].split("\")[-1]
    ForEach($f in $lolbas){
        if($f.Name.split(".")[0] -like $fn){
            $res.LOLBAS.Match = $true
            $res.LOLBAS.Details = $f
            $res.LOLBAS.Comment = (Get-Content $f.FullName | Select-String -Pattern "Description")[0]
        }
    }

    # Summary
    Write-Output ("Summary of {0}" -f $File)
    Write-Output ("Hashes:`n`tMD5: {0}`n`tSHA256: {1}" -f $res.Hashes.md5, $res.Hashes.sha256)
    Write-Output ("Magic bytes:`n`tHex: {0}`n`tASCII: {1}" -f $res.Magic.Hex, $res.Magic.ASCII)
    Write-Output ("Authenticode:`n`tCertificate is {0}`n`tSigner: {1}`n`tOS Binary: {2}" -f $res.Certificate.Status, $res.Certificate.SignerCertificate.Subject, $res.Certificate.IsOSBinary)
    Write-Output ("Links:`n`tVirustotal:`thttps://virustotal.com/gui/search/{0}`n`tGoogle:`t`thttps://google.com/search?q={0}" -f $res.Hashes.sha256)
    Write-Output ("LOLBAS:`n`tMatch: {0}`n`tDetails: {1}`n`t{2}" -f $res.LOLBAS.Match, $res.LOLBAS.Details.FullName,$res.LOLBAS.Comment)
    if($res.LOLBAS.Match){Write-Output "`tThis file is known to be used maliciously, check the Details file for further information."}
    # return $res

}