#################################################
#HelloID-Conn-Prov-Target-Generic-Scim-Import
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Get-ScimOAuthToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ClientID,

        [Parameter(Mandatory)]
        [string]
        $ClientSecret,

        [Parameter(Mandatory)]
        [string]
        $TokenUri
    )

    try {
        $headers = @{
            'content-type' = 'application/x-www-form-urlencoded'
        }

        $body = @{
            client_id     = $ClientID
            client_secret = $ClientSecret
            scope         = 'scim'
            grant_type    = 'client_credentials'
        }

        Invoke-RestMethod -Uri $TokenUri -Method 'POST' -Body $body -Headers $headers
    } catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            $httpErrorObj.FriendlyMessage = $errorDetailsObject.detail
        } catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}
function ConvertTo-HelloIDAccountObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $AccountObject
    )
    process {

        # Making sure only fieldMapping fields are imported
        $helloidAcountObject = [PSCustomObject]@{}
        foreach ($field in $actionContext.ImportFields) {
            switch($field){
                'Id'                    { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.id}
                'EmailAddress'          { $helloidAcountObject | Add-Member -NotePropertyName $field -NotePropertyValue $AccountObject.emails.value}
                'IsEmailPrimary'        { $helloidAcountObject | Add-Member -NotePropertyName $field -NotePropertyValue "$($AccountObject.emails.primary)"}
                'EmailAddressType'      { $helloidAcountObject | Add-Member -NotePropertyName $field -NotePropertyValue $AccountObject.emails.type}
                'Username'              { $helloidAcountObject | Add-Member -NotePropertyName $field -NotePropertyValue $AccountObject.userName}
                'ExternalId'            { $helloidAcountObject | Add-Member -NotePropertyName $field -NotePropertyValue $AccountObject.externalId}
                'GivenName'             { $helloidAcountObject | Add-Member -NotePropertyName $field -NotePropertyValue $AccountObject.name.givenName}
                'NameFormatted'         { $helloidAcountObject | Add-Member -NotePropertyName $field -NotePropertyValue $AccountObject.name.formatted}
                'FamilyName'            { $helloidAcountObject | Add-Member -NotePropertyName $field -NotePropertyValue $AccountObject.name.familyName}
                'FamilyNamePrefix'      { $helloidAcountObject | Add-Member -NotePropertyName $field -NotePropertyValue $AccountObject.name.familyNamePrefix}
                'IsEnabled'             { $helloidAcountObject | Add-Member -NotePropertyName $field -NotePropertyValue $AccountObject.active}
                default                 { $helloidAcountObject | Add-Member -NotePropertyName $field -NotePropertyValue $AccountObject.$field}
            }
        }
        Write-Output $helloidAcountObject
    }
}
#endregion

try {

    Write-Information 'Starting Generic-Scim account entitlement import'
    $accessToken = Get-ScimOAuthToken -ClientID $actionContext.configuration.ClientID -ClientSecret $actionContext.configuration.ClientSecret -TokenUri $ActionContext.Configuration.TokenUrl
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "$($accessToken.token_type) $($accessToken.access_token)")
    $headers.Add('Accept', 'application/json')

    $take = 20
    $startIndex = 0
    do {
        $splatImportAccountParams = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/users?startIndex=$($startIndex)&count=$($take)"
            Method  = 'GET'
            Headers = $headers
        }

        $response = Invoke-RestMethod @splatImportAccountParams

        $result = $response.Resources
        $totalResults = $response.totalResults

        if ($null -ne $result) {
            foreach ($importedAccount in $result) {
                $data = ConvertTo-HelloIDAccountObject -AccountObject $importedAccount

                # Set Enabled based on importedAccount status
                $isEnabled = $false
                if ($importedAccount.active -eq $true) {
                    $isEnabled = $true
                }

                # Make sure the displayName has a value
                $displayName = "$($importedAccount.name.formatted)"
                if ([string]::IsNullOrEmpty($displayName)) {
                    $displayName = $importedAccount.Id
                }

                # Make sure the userName has a value
                $UserName =  $importedAccount.UserName
                if ([string]::IsNullOrWhiteSpace($UserName)) {
                    $UserName = $importedAccount.Id
                }

                Write-Output @{
                    AccountReference = $importedAccount.Id
                    displayName      = $displayName
                    UserName         = $UserName
                    Enabled          = $isEnabled
                    Data             = $data
                }
                $startIndex++
            }
        }
    } while (($result.count -gt 0) -and ($startIndex -lt $totalResults))

    Write-Information 'Generic-Scim account entitlement import completed'
} catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        Write-Error "Could not import Generic-Scim account entitlements. Error: $($errorObj.FriendlyMessage)"
    } else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        Write-Error "Could not import Generic-Scim account entitlements. Error: $($ex.Exception.Message)"
    }
}