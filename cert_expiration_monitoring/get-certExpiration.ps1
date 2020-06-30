param(
	[Parameter(Mandatory=$true)][int32] $maxDays,  # Number of days to check certificate expiration 
    [Parameter(Mandatory=$true)][string] $subscriptionID, # Subscription ID where App Service Plans will be enumerated
    [Parameter(Mandatory=$true)][string] $LogAnalyticsID, # L&A Workspace to dump information collected
    [Parameter(Mandatory=$true)][string] $LogAnalyticsSharedKey # L&A Shared Key for access the workspace
)


Set-PsDebug -Strict 
Set-StrictMode -Version Latest 


# ---------------------------------------i----------------------------------------------------------------------- 
Function Build-Signature ($customerId, $LogAnalyticsSharedKey, $date, $contentLength, $method, $contentType, $resource)
# -------------------------------------------------------------------------------------------------------------- 
{   
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($LogAnalyticsSharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# ---------------------------------------i----------------------------------------------------------------------- 
Function Post-OMSData($customerId, $sharedKey, $body, $logType)
# -------------------------------------------------------------------------------------------------------------- 
{   
	$method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = "DateValue";
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}



# -------------------------------------------------------------------------------------------------------------- 
Function getExpiringCerts ()
# -------------------------------------------------------------------------------------------------------------- 
{   
    $certCollection = @()
    $allCertificates  = @()
    $allWebApps  = @()
    
	$maxDate = (Get-Date).AddDays($MaxDays)
	
	$resourceGroups = Get-AzureRmResourceGroup 

	foreach ($resourceGroup in $resourceGroups)
	{
		$allCertificates += Get-AzureRmWebAppCertificate -ResourceGroupName $resourceGroup.ResourceGroupName
		$allWebApps 	 += Get-AzureRmWebApp -ResourceGroupName $resourceGroup.ResourceGroupName	
	}
		
		
	foreach ($webapp in $allWebApps)
	{
		foreach($webAppCert in $webapp.HostNameSslStates)
		{
			if ($webAppCert.thumbprint -ne $null)
			{
				foreach ($cert in $allcertificates)
				{
					if ($cert.thumbprint -eq $webappcert.thumbprint -and $cert.expirationdate -lt $maxdate)
                    {
                        $obj = New-Object -TypeName psobject
						$obj | Add-Member -MemberType NoteProperty -Name CertThumbprint -value  $cert.thumbprint -force
						$obj | Add-Member -MemberType NoteProperty -Name ExpirationDate -value  $cert.ExpirationDate -force
						$obj | Add-Member -MemberType NoteProperty -Name WebAppName -value  $webapp.Name -force
						$certCollection += $obj
					}
				}
			}
		}
	}
	
	return $certCollection | Select-Object 'CertSubject','CertThumbprint','ExpirationDate', 'WebAppName' -Unique	
}

### ENTRYPOINT

try
{
	$expiringCerts = @()
	
	select-azurermsubscription -subscriptionID $subscriptionID
    $expiringCerts = getExpiringCerts
    if ($expiringCerts)
    {
        write-warning "Some certificates are about to expire in the next $($MaxDays) days"
        $expiringCerts
        foreach ($cert in $ExpiringCerts)
        {
             $obj = New-Object -TypeName psobject
             $obj | Add-Member -Name "WebAppName" -Value $expiringCerts.WebAppName -MemberType NoteProperty
             $obj | Add-Member -Name "CertSubject" -Value $expiringCerts.CertSubject -MemberType NoteProperty
             $obj | Add-Member -Name "CertThumbprint" -Value $expiringCerts.CertThumbprint -MemberType NoteProperty
             $obj | Add-Member -Name "ExpirationDate" -Value $expiringCerts.ExpirationDate -MemberType NoteProperty
             $json = ConvertTo-JSON $obj
             Post-OMSData -customerId $LogAnalyticsID -sharedKey $LogAnalyticsSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType "Cert_Expiration_Monitoring"   
         }
    }
    else
    {
        write-warning "All SSL certificates expiration date for subscription $($subscriptionID) are over defined timeframe"    
    }
	
}
Catch
{
     $ErrorRecord = $_
     $Exception = $ErrorRecord.Exception
     $ErrorMessage = $Exception.Message
     write-error  $Exception $ErrorMessage
     break;
}