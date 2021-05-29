#####################################################
# HelloID-Conn-Prov-Target-Generic-Scim-Update
#
# Version: 1.0.0.0
#####################################################
$VerbosePreference = "Continue"

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$personObj = $person | ConvertFrom-Json
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

#Region Helper Functions
function Get-GenericScimOAuthToken {
    <#
    .SYNOPSIS
    Retrieves the OAuth token from a SCIM API <http://www.simplecloud.info/>

    .PARAMETER ClientID
    The ClientID for the SCIM API

    .PARAMETER ClientSecret
    The ClientSecret for the SCIM API
    #>
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

function Invoke-GenericScimRestMethod {
    <#
    .SYNOPSIS
    Post data to a SCIM API <http://www.simplecloud.info/>

    .PARAMETER Uri
    The Uri to the SCIM API. <http://some-api/v1/scim>

    .PARAMETER Endpoint
    The path to the specific endpoint being queried. The endpoints follow the standards of the SCIM implementation

    .PARAMETER Headers
    The headers containing the AccessToken

    .PARAMETER Body
    The JSON body

    .PARAMETER Method
    The HTTP method. For example: POST, PATCH or PUT

    .PARAMETER IsConnectionTls12
    Adds TLS1.2 to the outgoing connection
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Uri]
        $Uri,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]
        $Headers,

        [Parameter(Mandatory = $true)]
        [object]
        $Body,

        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        $Method,

        [Parameter(Mandatory = $false)]
        [bool]
        $IsConnectionTls12
    )

    process {
        try {
            Write-Verbose "Invoking command '$($MyInvocation.MyCommand)' to endpoint '$Endpoint'"
            Write-Verbose "Setting 'Invoke-RestMethod' parameters: '$($PSBoundParameters.Keys)'"
            $splatRestMethodParameters = @{
                Uri         = "$Uri/$($Endpoint)"
                Method      = $Method
                ContentType = 'application/json'
                Headers     = $Headers
            }

            if ($IsConnectionTls12) {
                Write-Verbose 'Switching to TLS 1.2'
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
            }

            if ($body) {
                Write-Verbose 'adding body to request'
                $splatRestMethodParameters['Body'] = $Body
            }
            Invoke-RestMethod @splatRestMethodParameters
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
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
        $HttpErrorObj = @{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            InvocationInfo        = $ErrorObject.InvocationInfo.MyCommand
            TargetObject          = $ErrorObject.TargetObject.RequestUri
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $HttpErrorObj['ErrorMessage'] = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $stream = $ErrorObject.Exception.Response.GetResponseStream()
            $stream.Position = 0
            $streamReader = New-Object System.IO.StreamReader $Stream
            $errorResponse = $StreamReader.ReadToEnd()
            $HttpErrorObj['ErrorMessage'] = $errorResponse
        }
        Write-Output "'$($HttpErrorObj.ErrorMessage)', TargetObject: '$($HttpErrorObj.TargetObject), InvocationCommand: '$($HttpErrorObj.InvocationInfo)"
    }
}
#EndRegion

if (-not($dryRun -eq $true)) {
    try {
        Write-Verbose "Updating user '$($personObj.DisplayName)'"
        Write-Verbose "Retrieving accessToken"
        $accessToken = Get-GenericScimOAuthToken -ClientID $($config.ClientID) -ClientSecret $($config.ClientSecret)

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

        Write-Verbose 'Adding Authorization headers'
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", "Bearer $accessToken")
        $splatParams = @{
            Uri               = $($config.BaseUrl)
            Endpoint          = "Users/$aRef"
            Headers           = $headers
            Body              = $body
            Method            = 'Patch'
            IsConnectionTls12 = $($config.IsConnectionTls12)
        }
        $results = Invoke-GenericScimRestMethod @splatParams
        Write-Verbose "Finished updating user with id: '$($results.id)'"
        $success = $true
        $auditLogs.Add([PSCustomObject]@{
            Message = "Account for '$($personObj.DisplayName)' successfully updated"
            IsError = $False
        })
    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorMessage = Resolve-HTTPError -Error $ex
            $auditMessage = "Account for '$($personObj.DisplayName)' not updated. Error: $errorMessage"
        }
        else {
            $auditMessage = "Account for '$($personObj.DisplayName)' not updated. Error: $($ex.Exception.Message)"
        }
        $auditLogs.Add([PSCustomObject]@{
                Action  = "CreateAccount"
                Message = $auditMessage
                IsError = $true
            })
        Write-Error $auditMessage
    }
}

$result = [PSCustomObject]@{
    Success          = $success
    Account          = $account
    AccountReference = $aRef
    AuditDetails     = $auditMessage
}

Write-Output $result | ConvertTo-Json -Depth 10
