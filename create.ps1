#####################################################
# HelloID-Conn-Prov-Target-Generic-Scim-Create
#
# Version: 1.0.0.3
#####################################################
$VerbosePreference = "Continue"

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false
$auditLogs = New-Object Collections.Generic.List[PSCustomObject]

$account = [PSCustomObject]@{
    ExternalId          = $p.ExternalId
    UserName            = $p.UserName
    GivenName           = $p.Name.GivenName
    FamilyName          = $p.Name.FamilyName
    FamilyNameFormatted = $p.DisplayName
    FamilyNamePrefix    = ''
    IsUserActive        = $true
    EmailAddress        = $p.Contact.Business.Email
    EmailAddressType    = 'Work'
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

    # The 'action' variable determines which path to follow in the 'dryRun' using a switch statement.
    # This is an array, because there might be a situation where you'd want to create and update a user.
    # In that case you most likely want to loop through multiple switch statements.
    $action = @("Create")

    # Process
    # The 'dryRun' block is similar to a 'Process' block. Here; we process our data,
    # or, in this case; create or correlate the account.
    if (-not ($dryRun -eq $true)){
        switch ($action) {
            'Create' {
                Write-Verbose "Creating account for '$($p.DisplayName)'"

                [System.Collections.Generic.List[object]]$emailList = @()
                $emailList.Add(
                    [PSCustomObject]@{
                        primary = $account.IsEmailPrimary
                        type    = $account.EmailAddressType
                        display = $account.EmailAddress
                        value   = $account.EmailAddress
                    }
                )

                $body = [ordered]@{
                    schemas    = @(
                        "urn:ietf:params:scim:schemas:core:2.0:User",
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
                    )
                    externalId = $account.ExternalID
                    userName   = $account.UserName
                    active     = $account.IsUserActive
                    emails     = $emailList
                    meta       = @{
                        resourceType = "User"
                    }
                    name = [ordered]@{
                        formatted        = $account.NameFormatted
                        familyName       = $account.FamilyName
                        familyNamePrefix = $account.FamilyNamePrefix
                        givenName        = $account.GivenName
                    }
                } | ConvertTo-Json

                $splatParams = @{
                    Uri     = "$($config.BaseUrl)/scim/v2/Users"
                    Headers = $headers
                    Body    = $body
                    Method  = 'POST'
                }
                $response = Invoke-RestMethod @splatParams
                break
            }

            # The 'Correlate' action is currently not being used in this demo connector
            'Correlate'{
            }
        }

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
            Message = "$action account for: $($p.DisplayName) was successful. AccountReference is: $($response.Id)"
            IsError = $False
        })
    }
} catch {
    $success = $false
    $ex = $PSItem
    if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -Error $ex
        $errorMessage = "Could not create scim user. Error: $($errorObj.ErrorMessage)"
    } else {
        $errorMessage = "Could not create scim user. Error: $($ex.Exception.Message)"
    }
    Write-Error $errorMessage
    $auditLogs.Add([PSCustomObject]@{
        Message = "Could not create account for: $($p.DisplayName). Error: $errorMessage"
        IsError = $true
    })
# End
# The 'End' block is where we gather the results and send them back to HelloID.
} Finally {
    $result = [PSCustomObject]@{
        Success          = $success
        AccountReference = $response.Id
        Auditlogs        = $auditLogs
        Account          = $account
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
