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
        $ClientSecret
    )

    try {
        $headers = @{
            'content-type' = 'application/x-www-form-urlencoded'
        }

        $body = @{
            client_id     = $ClientID
            client_secret = $ClientSecret
            grant_type    = 'client_credentials'
        }

        Invoke-RestMethod -Uri $Uri -Method 'POST' -Body $body -Headers $headers
    } catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
}

function Invoke-ScimRestMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [string]
        $ContentType = 'application/json',

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]
        $Headers,

        [string]
        $TotalResults
    )

    try {
        $splatParams = @{
            Uri         = "$($actionContext.configuration.BaseUrl)/$Uri"
            Headers     = $Headers
            Method      = $Method
            ContentType = $ContentType
        }

        if ($Body) {
            $splatParams['Body'] = $Body
        }

        if ($TotalResults) {
            # Fixed value since each page contains 20 items max
            $count = 20

            [System.Collections.Generic.List[object]]$dataList = @()
            do {
                $startIndex = $dataList.Count
                $splatParams['Uri'] = "$($baseUrl)/$($Uri)?startIndex=$startIndex&count=$count"
                $result = Invoke-RestMethod @splatParams
                foreach ($resource in $result.Resources) {
                    $dataList.Add($resource)
                }
            } until ($dataList.Count -eq $TotalResults)
            Write-Output $dataList
        } else {
            Invoke-RestMethod @splatParams
        }
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
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
#endregion

try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    $accessToken = Get-ScimOAuthToken -ClientID $($actionContext.configuration.ClientID) -ClientSecret $($actionContext.configuration.ClientSecret)
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "Bearer $accessToken")

    Write-Information 'Verifying if a Scim account exists'
    $splatGetUser = @{
        Uri     = "Users/$($actionContext.References.Account)"
        Method  = 'GET'
        Headers = $headers
    }
    $correlatedAccount = Invoke-ScimRestMethod @splatGetUser
    $outputContext.PreviousData = $correlatedAccount

    # Always compare the account against the current account in target system
    if ($null -ne $correlatedAccount) {
        $targetAccount = [PSCustomObject]@{
            EmailAddress        = $correlatedAccount.emails.value
            IsEmailPrimary      = "$($correlatedAccount.emails.primary)"
            EmailAddressType    = $correlatedAccount.emails.type
            Username            = $correlatedAccount.userName
            ExternalId          = $correlatedAccount.externalId
            GivenName           = $correlatedAccount.name.givenName
            NameFormatted       = $correlatedAccount.name.formatted
            FamilyName          = $correlatedAccount.name.familyName
            FamilyNameFormatted = $correlatedAccount.name.familyNamePrefix
        }

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
                                path  = 'name.NameFormatted'
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
                    'FamilyNameFormatted' {
                        $operations.Add(
                            [PSCustomObject]@{
                                op    = 'Replace'
                                path  = 'name.FamilyNameFormatted'
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

            $splatParams = @{
                Uri     = "Users/$($actionContext.References.Account)"
                Headers = $headers
                Body    = $body
                Method  = 'Patch'
            }

            # Make sure to test with special characters and if needed; add utf8 encoding.
            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Updating Scim account with accountReference: [$($actionContext.References.Account)]"
                $results = Invoke-ScimRestMethod @splatParams
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
        $errorObj = Resolve-HTTPError -Error $ex
        $auditMessage = "Could not update Scim account for: $($actionContext.Data.DisplayName). Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not update Scim account for: $($actionContext.Data.DisplayName). Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}