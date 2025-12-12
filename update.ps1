#################################################
# HelloID-Conn-Prov-Target-Generic-Scim-Update
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

function Resolve-Generic-ScimError {
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
        $helloidAccountObject = [PSCustomObject]@{}
        foreach ($property in $actionContext.Data.PSObject.Properties) {
            switch($property.Name){
                'Id'                    { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.id}
                'EmailAddress'          { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.emails.value}
                'IsEmailPrimary'        { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue "$($AccountObject.emails.primary)"}
                'EmailAddressType'      { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.emails.type}
                'Username'              { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.userName}
                'ExternalId'            { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.externalId}
                'GivenName'             { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.name.givenName}
                'NameFormatted'         { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.name.formatted}
                'FamilyName'            { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.name.familyName}
                'FamilyNamePrefix'      { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.name.familyNamePrefix}
                'IsEnabled'             { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.active}
                default                 { $helloidAccountObject | Add-Member -NotePropertyName $property.Name -NotePropertyValue $AccountObject.$($property.Name)}
            }
        }
        Write-Output $helloidAccountObject
    }
}
#endregion

try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    $accessToken = Get-ScimOAuthToken -ClientID $actionContext.configuration.ClientID -ClientSecret $actionContext.configuration.ClientSecret -TokenUri $ActionContext.Configuration.TokenUrl
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "$($accessToken.token_type) $($accessToken.access_token)")
    $headers.Add('Accept', 'application/json')

    Write-Information 'Verifying if a Scim account exists'
    $splatGetUser = @{
        Uri         = "$($actionContext.Configuration.BaseUrl)/Users/$($actionContext.References.Account)"
        Method      = 'GET'
        Headers     = $headers
        ContentType = 'application/json'
    }
    $correlatedAccount = Invoke-RestMethod @splatGetUser

    # Always compare the account against the current account in target system
    if ($null -ne $correlatedAccount) {

        $targetAccount = ConvertTo-HelloIDAccountObject($correlatedAccount)

        $outputContext.PreviousData = $targetAccount

        $splatCompareProperties = @{
            ReferenceObject  = @($targetAccount.PSObject.Properties)
            DifferenceObject = @($actionContext.Data.PSObject.Properties)
        }
        $propertiesChanged = Compare-Object @splatCompareProperties -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        if ($propertiesChanged) {
            $action = 'UpdateAccount'
        } else {
            $action = 'NoChanges'
        }
    } else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'UpdateAccount' {
            Write-Information "Account property(s) required to update: $($propertiesChanged.Name -join ', ')"

            [System.Collections.Generic.List[object]]$operations = @()
            foreach ($property in $propertiesChanged) {
                switch ($property.Name) {
                    'ExternalId' {
                        $operations.Add(
                            [PSCustomObject]@{
                                op    = 'Replace'
                                path  = 'externalId'
                                value = $property.Value
                            }
                        )
                    }
                    'Username' {
                        $operations.Add(
                            [PSCustomObject]@{
                                op    = 'Replace'
                                path  = 'userName'
                                value = $property.Value
                            }
                        )
                    }
                    'GivenName' {
                        $operations.Add(
                            [PSCustomObject]@{
                                op    = 'Replace'
                                path  = 'name.givenName'
                                value = $property.Value
                            }
                        )
                    }
                    'NameFormatted' {
                        $operations.Add(
                            [PSCustomObject]@{
                                op    = 'Replace'
                                path  = 'name.Formatted'
                                value = $property.Value
                            }
                        )
                    }
                    'FamilyName' {
                        $operations.Add(
                            [PSCustomObject]@{
                                op    = 'Replace'
                                path  = 'name.FamilyName'
                                value = $property.Value
                            }
                        )
                    }
                    'FamilyNamePrefix' {
                        $operations.Add(
                            [PSCustomObject]@{
                                op    = 'Replace'
                                path  = 'name.FamilyNamePrefix'
                                value = $property.Value
                            }
                        )
                    }
                    'EmailAddress' {
                        $operations.Add(
                            [PSCustomObject]@{
                                op    = 'Replace'
                                path  = 'emails.value'
                                value = $property.Value
                            }
                        )
                    }
                    'IsEmailPrimary' {
                        $operations.Add(
                            [PSCustomObject]@{
                                op    = 'Replace'
                                path  = 'emails.primary'
                                value = $property.Value
                            }
                        )
                    }
                    'EmailAddressType' {
                        $operations.Add(
                            [PSCustomObject]@{
                                op    = 'Replace'
                                path  = 'emails.type'
                                value = $property.Value
                            }
                        )
                    }
                }
            }

            $body = [ordered]@{
                schemas    = @(
                    'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                )
                Operations = $operations
            } | ConvertTo-Json

            $splatUpdateUser = @{
                Uri         = "$($actionContext.Configuration.BaseUrl)/Users/$($actionContext.References.Account)"
                Headers     = $headers
                Body        = $body
                Method      = 'Patch'
                ContentType = 'application/json'
            }

            # Make sure to test with special characters and if needed; add utf8 encoding.
            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Updating Scim account with accountReference: [$($actionContext.References.Account)]"
                $results = Invoke-RestMethod @splatUpdateUser
                if (-not($results.id)) {
                    throw
                }
            } else {
                Write-Information "[DryRun] Update Scim account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Update account was successful, Account property(s) updated: [$($propertiesChanged.name -join ',')]"
                    IsError = $false
                })
            break
        }

        'NoChanges' {
            Write-Information "No changes to Scim account with accountReference: [$($actionContext.References.Account)]"

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = 'No changes will be made to the account during enforcement'
                    IsError = $false
                })
            break
        }

        'NotFound' {
            Write-Information "Scim account: [$($actionContext.References.Account)] could not be found, possibly indicating that it could be deleted"
            $outputContext.Success = $false
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Scim account with accountReference: [$($actionContext.References.Account)] could not be found, possibly indicating that it could be deleted"
                    IsError = $true
                })
            break
        }
    }
} catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Generic-ScimError -Error $ex
        $auditMessage = "Could not update Scim account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not update Scim account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}