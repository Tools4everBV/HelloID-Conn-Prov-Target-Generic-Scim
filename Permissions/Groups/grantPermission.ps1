################################################################
# HelloID-Conn-Prov-Target-Generic-Scim-GrantPermission-Group
# PowerShell V2
################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
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

#endregion

# Begin
try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    $accessToken = Get-ScimOAuthToken -ClientID $actionContext.configuration.ClientID -ClientSecret $actionContext.configuration.ClientSecret -TokenUri $ActionContext.Configuration.TokenUrl
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "$($accessToken.token_type) $($accessToken.access_token)")


    Write-Information 'Verifying if a Generic-Scim account exists'
    $splatGetUser = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/Users/$($actionContext.References.Account)"
        Method  = 'GET'
        Headers = $headers
    }
    $correlatedAccount = Invoke-RestMethod @splatGetUser

    if ($null -ne $correlatedAccount) {
        $action = 'GrantPermission'
    } else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'GrantPermission' {
            # Make sure to test with special characters and if needed; add utf8 encoding.
             [System.Collections.Generic.List[object]]$operations = @()

            $operations.Add(
                [PSCustomObject]@{
                    op    = 'add'
                    path  = 'members'
                    value = @(
                        [PSCustomObject]@{
                            value = $actionContext.References.Account
                        }
                    )
                }
            )
            $body = [ordered]@{
                schemas    = @(
                    'urn:ietf:params:scim:api:messages:2.0:PatchOp'
                )
                Operations = $operations
            } | ConvertTo-Json -depth 10

            $splatGrantGroupMember = @{
                Uri     = "$($actionContext.Configuration.BaseUrl)/groups/$($actionContext.References.Permission.Reference)"
                Headers = $headers
                Body    = $body
                Method  = 'Patch'
                ContentType = 'application/json'
            }


            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Granting Generic-Scim permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Reference)]"
                $null = Invoke-RestMethod @splatGrantGroupMember                

            } else {
                Write-Information "[DryRun] Grant Generic-Scim permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Reference)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = "Grant permission [$($actionContext.PermissionDisplayName)] was successful"
                IsError = $false
            })
        }

        'NotFound' {
            Write-Information "Generic-Scim account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
            $outputContext.Success  = $false
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = "Generic-Scim account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
                IsError = $true
            })
            break
        }
    }
} catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Generic-ScimError -ErrorObject $ex
        $auditLogMessage = "Could not grant Generic-Scim permission. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditLogMessage = "Could not grant Generic-Scim permission. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
        Message = $auditLogMessage
        IsError = $true
    })
}