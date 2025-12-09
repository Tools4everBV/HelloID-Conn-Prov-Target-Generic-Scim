####################################################################
# HelloID-Conn-Prov-Target-Generic-Scim-ImportPermissions-Group
# PowerShell V2
####################################################################

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
#endregion

try {

    $accessToken = Get-ScimOAuthToken -ClientID $actionContext.configuration.ClientID -ClientSecret $actionContext.configuration.ClientSecret -TokenUri $ActionContext.Configuration.TokenUrl      
        
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "$($accessToken.token_type) $($accessToken.access_token)")
    $headers.Add('Accept', 'application/json')  

    $count = 20
    $startIndex = 0
    do {
        $splatImportAccountParams = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/groups?startIndex=$startIndex&count=$count"
            Method  = 'GET'
            Headers = $headers
        }
        $response = Invoke-RestMethod @splatImportAccountParams
        $result = $response.Resources  
        $totalResults = $response.totalResults     
        if ($result) {
            foreach ($importedPermission in $result) { 

                # Make sure the displayName has a value
                $displayName = "$($importedPermission.displayName)"
                if ([string]::IsNullOrEmpty($displayName)) {
                    $displayName = $importedPermission.Id
                }               

                $permission = @{
                    PermissionReference = @{
                        Reference = $importedPermission.id
                    }
                    Description         = "$($importedPermission.description)"
                    DisplayName         =  $displayName
                    AccountReferences   = $null
                }
                # The code below splits a list of permission-members into batches of <batchSize>
                # Each batch is assigned to $permission.AccountReferences and the permission object will be returned to HelloID for each batch
                # Ensure batching is based on the number of account references to prevent exceeding the maximum limit of 500 account references per batch
      
                $batchSize = 500
                for ($i = 0; $i -lt $importedPermission.members.Count; $i += $batchSize) {
                    $permission.AccountReferences = [array] $importedPermission.members[$i..([Math]::Min($i + $batchSize - 1, $importedPermission.members.Count - 1))].value
                    Write-Output $permission
                }
                
                $startIndex++
            }
        }
        else {
            break
        }        
    } while (($result.count -gt 0) -and ($startIndex -lt $totalResults))    
    
    Write-Information 'Generic-Scim permission group entitlement import completed'

} catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Generic-ScimError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        Write-Error "Could not import Generic-Scim permission group entitlements. Error: $($errorObj.FriendlyMessage)"
    } else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        Write-Error "Could not import Generic-Scim permission group entitlements. Error: $($ex.Exception.Message)"
    }
}