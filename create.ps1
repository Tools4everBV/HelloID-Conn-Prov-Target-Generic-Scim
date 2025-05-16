#################################################
# HelloID-Conn-Prov-Target-Generic-Scim-Create
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
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'

    $accessToken = Get-ScimOAuthToken -ClientID $($actionContext.configuration.ClientID) -ClientSecret $($actionContext.configuration.ClientSecret)
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "Bearer $accessToken")

    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.AccountField
        $correlationValue = $actionContext.CorrelationConfiguration.PersonFieldValue

        if ([string]::IsNullOrEmpty($($correlationField))) {
            throw 'Correlation is enabled but not configured correctly'
        }
        if ([string]::IsNullOrEmpty($($correlationValue))) {
            throw 'Correlation is enabled but [accountFieldValue] is empty. Please make sure it is correctly mapped'
        }

        Write-Information 'Getting total number of users'
        $splatGetTotal = @{
            Uri     = 'Users'
            Method  = 'Get'
            Headers = $headers
        }
        $response = Invoke-ScimRestMethod @splatGetTotal
        $totalResults = $response.totalResults

        Write-Information "Retrieving '$totalResults' users"
        $splatGetUsers = @{
            Uri          = 'Users'
            Method       = 'GET'
            Headers      = $headers
            TotalResults = $totalResults
        }
        $responseAllUsers = Invoke-ScimRestMethod @splatGetUsers

        Write-Information "Verifying if account for '$($actionContext.Data.DisplayName)' must be created or correlated"
        $lookup = $responseAllUsers | Group-Object -Property 'ExternalId' -AsHashTable
        $correlatedAccount = $lookup[$actionContext.Data.ExternalId]
    }

    if ($null -ne $correlatedAccount) {
        $action = 'CorrelateAccount'
    } else {
        $action = 'CreateAccount'
    }

    # Process
    switch ($action) {
        'CreateAccount' {
            [System.Collections.Generic.List[object]]$emailList = @()
            $emailList.Add(
                [PSCustomObject]@{
                    primary = $actionContext.Data.IsEmailPrimary
                    type    = $actionContext.Data.EmailAddressType
                    display = $actionContext.Data.EmailAddress
                    value   = $actionContext.Data.EmailAddress
                }
            )

            $body = [ordered]@{
                schemas    = @(
                    'urn:ietf:params:scim:schemas:core:2.0:User',
                    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'
                )
                externalId = $actionContext.Data.ExternalID
                userName   = $actionContext.Data.UserName
                active     = $false
                emails     = $emailList
                meta       = @{
                    resourceType = 'User'
                }
                name       = [ordered]@{
                    formatted        = $actionContext.Data.NameFormatted
                    familyName       = $actionContext.Data.FamilyName
                    familyNamePrefix = $actionContext.Data.FamilyNamePrefix
                    givenName        = $actionContext.Data.GivenName
                }
            } | ConvertTo-Json

            $splatCreateParams = @{
                Uri     = 'Users'
                Method  = 'POST'
                Body    = $body
                Headers = $headers
            }

            # Make sure to test with special characters and if needed; add utf8 encoding.
            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information 'Creating and correlating Scim account'
                $createdAccount = Invoke-ScimRestMethod @splatCreateParams
                $outputContext.Data = $createdAccount
                $outputContext.AccountReference = $createdAccount.Id
            } else {
                Write-Information '[DryRun] Create and correlate Scim account, will be executed during enforcement'
            }
            $auditLogMessage = "Create account was successful. AccountReference is: [$($outputContext.AccountReference)]"
            break
        }

        'CorrelateAccount' {
            Write-Information 'Correlating Scim account'

            $outputContext.Data = $correlatedAccount
            $outputContext.AccountReference = $correlatedAccount.Id
            $outputContext.AccountCorrelated = $true
            $auditLogMessage = "Correlated account: [$($outputContext.AccountReference)] on field: [$($correlationField)] with value: [$($correlationValue)]"
            break
        }
    }

    $outputContext.success = $true
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Action  = $action
            Message = $auditLogMessage
            IsError = $false
        })
} catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -Error $ex
        $auditMessage = "Could not create or correlate Scim account for: $($actionContext.Data.DisplayName). Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not create or correlate Scim account for: $($actionContext.Data.DisplayName). Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}