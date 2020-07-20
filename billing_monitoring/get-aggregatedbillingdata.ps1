[CmdletBinding()]

param(
	[Parameter(Mandatory=$true)][string] $SubscriptionId,				# Your subscription ID
	[Parameter(Mandatory=$true)][string] $LogAnalyticsID, 				# L&A Workspace to dump information collected
    [Parameter(Mandatory=$true)][string] $LogAnalyticsSharedKey 		# L&A Shared Key for access the workspace
)

Set-PsDebug -Strict 
Set-StrictMode -Version Latest 


# ---------------------------------------i----------------------------------------------------------------------- 
Function Build-Signature ($customerId, $sharedkey, $date, $contentLength, $method, $contentType, $resource)
# -------------------------------------------------------------------------------------------------------------- 
{   
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedkey)

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



### ENTRYPOINT

$Conn = Get-AutomationConnection -Name AzureRunAsConnection
Connect-AzureRmAccount -ServicePrincipal -Tenant $Conn.TenantID `
-ApplicationId $Conn.ApplicationID -CertificateThumbprint $Conn.CertificateThumbprint


$ToTime = Get-Date -format "yyyy-MM-dd hh:mm:ss"
$LastWeek =  (Get-Date).AddDays(-7)
$LastDay =  (Get-Date).AddDays(-1)
$totalLastWeek = 0
$totalLastDay = 0

$subscription = get-azurermsubscription | where-object {$_.SubscriptionId -eq $SubscriptionId}


write-output "`n-----------------------------------------------------------------------"
write-output "`nMonitoring billing for $($subscription.Name) in daily/weekly basis"
	
			
$LastWeekConsumption = Get-AzureRmConsumptionUsageDetail -StartDate $LastWeek -EndDate $ToTime
$LastDayConsumption = Get-AzureRmConsumptionUsageDetail -StartDate $LastDay -EndDate $ToTime

foreach ($cost in $LastWeekConsumption)
{
	$totalLastWeek = $totalLastWeek + $cost.PretaxCost
}

foreach ($cost in $LastDayConsumption)
{
	$totalLastDay = $totalLastDay + $cost.PretaxCost
}


write-warning $("`n$($subscription.Name) Last Day Consumption: $($totalLastDay) Eur")
write-warning $("`n$($subscription.Name) Last Week Consumption: $($totalLastWeek) Eur")


$obj = New-Object -TypeName psobject
$obj | Add-Member -Name "Subscription Name" -Value $subscription.Name -MemberType NoteProperty
$obj | Add-Member -Name "Subscription Id" -Value $subscription.SubscriptionId -MemberType NoteProperty
$obj | Add-Member -Name "Last Day Consumption" -Value $totalLastDay -MemberType NoteProperty
$obj | Add-Member -Name "Last Week Consumption" -Value $totalLastWeek -MemberType NoteProperty

$json = ConvertTo-JSON $obj

Post-OMSData -customerId $LogAnalyticsID -sharedKey $LogAnalyticsSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType "Billing_Monitoring" 

write-output "`n-----------------------------------------------------------------------"

