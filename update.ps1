#####################################################
# HelloID-Conn-Prov-Target-Generic-Scim-Update
#
# Version: 1.0.0.3
#####################################################
$VerbosePreference = 'Continue'

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$success = $false
$auditLogs = New-Object Collections.Generic.List[PSCustomObject]

$account = [PSCustomObject]@{
    ExternalId          = $pd.ExternalId.New
    UserName            = $pd.UserName.New
    GivenName           = $pd.Name.GivenName.New
    FamilyName          = $pd.Name.FamilyName.New
    FamilyNameFormatted = $pd.DisplayName.New
    FamilyNamePrefix    = $pd.DisplayName.FamilyNamePrefix.New
    IsUserActive        = $true
    EmailAddress        = $pd.Contact.Business.Email.New
    IsEmailPrimary      = $true
}

#region functions
function Get-GenericScimOAuthToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $ClientID,

        [Parameter(Mandatory = $true)]
        [string]
        $ClientSecret
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $headers = @{
            "content-type" = "application/x-www-form-urlencoded"
        }

        $body = @{
            client_id     = $ClientID
            client_secret = $ClientSecret
            grant_type    = "client_credentials"
        }

        $splatRestMethodParameters = @{
            Uri     = $TokenUri
            Method  = 'POST'
            Headers = $headers
            Body    = $body
        }
        Invoke-RestMethod @splatRestMethodParameters
        Write-Verbose 'Finished retrieving accessToken'
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $HttpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $HttpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $stream = $ErrorObject.Exception.Response.GetResponseStream()
            $stream.Position = 0
            $streamReader = New-Object System.IO.StreamReader $Stream
            $errorResponse = $StreamReader.ReadToEnd()
            $HttpErrorObj.ErrorMessage = $errorResponse
        }
        Write-Output $HttpErrorObj
    }
}
#endregion

try {
    # Begin
    # This is our 'Begin' block. Similar to a 'PS Begin' block in a function. Here, we setup our connection,
    # verify data (check if an account already exists),
    # and determine which path in the 'dryRun' block to follow. Either, create or correlate.
    Write-Verbose 'Retrieving accessToken'
    $accessToken = Get-GenericScimOAuthToken -ClientID $($config.ClientID) -ClientSecret $($config.ClientSecret)

    Write-Verbose 'Adding Authorization headers'
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $accessToken")

    # Process
    # The 'dryRun' block is similar to a 'Process' block. Here; we process our data,
    # or, in this case; update the account.
    if (-not($dryRun -eq $true)) {
        [System.Collections.Generic.List[object]]$operations = @()

        if ($account.ExternalId){
            $operations.Add(
                [PSCustomObject]@{
                    op = "Replace"
                    path = "externalId"
                    value = $account.ExternalId
                }
            )
        }

        if ($account.UserName){
            $operations.Add(
                [PSCustomObject]@{
                    op = "Replace"
                    path = "userName"
                    value = $account.UserName
                }
            )
        }

        if ($account.GivenName){
            $operations.Add(
                [PSCustomObject]@{
                    op = "Replace"
                    path = "name.givenName"
                    value = $account.GivenName
                }
            )
        }

        if ($account.FamilyName){
            $operations.Add(
                [PSCustomObject]@{
                    op = "Replace"
                    path = "name.familyName"
                    value = $account.FamilyName
                }
            )
        }

        if ($account.EmailAddress){
            $operations.Add(
                [PSCustomObject]@{
                    op = "Replace"
                    path = 'emails[type eq "work"].value'
                    value = $account.EmailAddress
                }
            )
        }

        $body = [ordered]@{
            schemas = @(
                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
            )
            Operations = $operations
        } | ConvertTo-Json

        $splatParams = @{
            Uri     = "$($config.BaseUrl)/scim/v2/Users/$aRef"
            Headers = $headers
            Body    = $body
            Method  = 'PATCH'
        }
        $response = Invoke-RestMethod @splatParams
        if ($response.id){
            $logMessage = "Account: $aRef for: $($p.DisplayName) successfully updated"
            Write-Verbose $logMessage
            $success = $true
            $auditLogs.Add([PSCustomObject]@{
                Message = $logMessage
                IsError = $False
            })
        }
    }
} catch {
    $success = $false
    $ex = $PSItem
    if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -Error $ex
        $errorMessage = "Could not update account: $aRef for: $($p.DisplayName). Error: $($errorObj.ErrorMessage)"
    } else {
        $errorMessage = "Could not update account: $aRef for: $($p.DisplayName). Error: $($ex.Exception.Message)"
    }
    Write-Error $errorMessage
    $auditLogs.Add([PSCustomObject]@{
        Message = $errorMessage
        IsError = $true
    })
# End
# The 'End' block is where we gather the results and send them back to HelloID.
} finally {
    $result = [PSCustomObject]@{
        Success      = $success
        Account      = $account
        AuditDetails = $auditMessage
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}