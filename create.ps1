#####################################################
# HelloID-Conn-Prov-Target-Generic-Scim-Create
#
# Version: 1.0.0.0
#####################################################
$VerbosePreference = "Continue"

# Initialize default value's
$config = $configuration | ConvertFrom-Json
$personObj = $person | ConvertFrom-Json
$success = $false
$account_guid = New-Guid
$auditLogs = New-Object Collections.Generic.List[PSCustomObject]

$account = [PSCustomObject]@{
    ExternalId = $personObj.ExternalId
    UserName = $personObj.UserName
    GivenName = $personObj.Name.GivenName
    FamilyName = $personObj.Name.FamilyName
    FamilyNameFormatted = $personObj.DisplayName
    FamilyNamePrefix = ''
    IsUserActive = $true
    EmailAddress = $personObj.Contact.Business.Email
    EmailAddressType = 'Work'
    IsEmailPrimary = $true
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
            client_id = $ClientID
            client_secret = $ClientSecret
            grant_type = "client_credentials"
        }

        $splatRestMethodParameters = @{
            Uri = $TokenUri
            Method = 'POST'
            Headers = $headers
            Body = $body
        }
        Invoke-RestMethod @splatRestMethodParameters
        Write-Verbose 'Finished retrieving accessToken'
    } catch {
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
                Uri = "$Uri/$($Endpoint)"
                Method = $Method
                ContentType = 'application/json'
                Headers = $Headers
            }

            if ($IsConnectionTls12){
                Write-Verbose 'Switching to TLS 1.2'
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
            }

            if ($body){
                Write-Verbose 'adding body to request'
                $splatRestMethodParameters['Body'] = $Body
            }
            Invoke-RestMethod @splatRestMethodParameters
        } catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
}

function Resolve-HTTPError {
    <#
    .SYNOPSIS
    Resolves an HTTP error for both Windows PowerShell 5.1 and PowerShell 7.0.3 Core
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$ErrorObject
    )

    $HttpErrorObj = @{
        FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
        InvocationInfo = $ErrorObject.InvocationInfo.MyCommand
        TargetObject  = $ErrorObject.TargetObject.RequestUri
    }

    if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException'){
        $HttpErrorObj['ErrorMessage'] = (($ErrorObject.ErrorDetails.Message) | ConvertFrom-Json).detail
    } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException'){
        $stream = $ErrorObject.Exception.Response.GetResponseStream()
        $stream.Position = 0
        $streamReader = New-Object System.IO.StreamReader $Stream
        $errorResponse = $StreamReader.ReadToEnd()
        $HttpErrorObj['ErrorMessage'] = ($errorResponse | ConvertFrom-Json).detail
    }

    Write-Output "'$($HttpErrorObj.ErrorMessage)', TargetObject: '$($HttpErrorObj.TargetObject), InvocationCommand: '$($HttpErrorObj.InvocationInfo)"
}
#EndRegion

if(-not($dryRun -eq $true)){
    try {
        Write-Verbose "Creating user '$($account.UserName)'"
        Write-Verbose "Retrieving accessToken"
        $accessToken = Get-GenericScimOAuthToken -ClientID $($config.ClientID) -ClientSecret $($config.ClientSecret)

        [System.Collections.Generic.List[object]]$roles = @()
        [System.Collections.Generic.List[object]]$emailList = @()
        $emailList.Add(
            [PSCustomObject]@{
                primary = $account.IsEmailPrimary
                type = $account.EmailAddressType
                display = $account.EmailAddress
                value = $account.EmailAddress
            }
        )

        $body = [ordered]@{
            schemas = @(
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
            )
            externalId = $account.ExternalID
            userName = $account.UserName
            active = $account.IsUserActive
            emails = $emailList
            meta = @{
                resourceType = "User"
            }
            name = [ordered]@{
                formatted = $account.NameFormatted
                familyName = $account.FamilyName
                familyNamePrefix = $account.FamilyNamePrefix
                givenName = $account.GivenName
            }
            roles = $roles
        } | ConvertTo-Json

        Write-Verbose 'Adding Authorization headers'
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", "Bearer $accessToken")

        $splatParams = @{
            Uri = $($config.BaseUrl)
            Endpoint = 'Users'
            Headers = $headers
            Body = $body
            Method = 'Post'
            IsConnectionTls12 = $($config.IsConnectionTls12)
        }
        $results = Invoke-GenericScimRestMethod @splatParams
        Write-Verbose "Finished creating user with id: '$($results.id)'"
        $success = $true
        $auditLogs.Add([PSCustomObject]@{
            Message = "Account for '$($personObj.DisplayName)' successfully created with id: '$($results.id)'"
            IsError = $False
        })
    } catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')){
            $errorMessage = Resolve-HTTPError -Error $ex
            $auditMessage = "Account for '$($personObj.DisplayName)' not created. Error: $errorMessage"
        }
        else {
            $auditMessage = "Account for '$($personObj.DisplayName)' not created. Error: $($ex.Exception.Message)"
        }
        $auditLogs.Add([PSCustomObject]@{
            Action = "CreateAccount"
            Message = $auditMessage
            IsError = $true
        })
        Write-Error $auditMessage
    }
}

$result = [PSCustomObject]@{
    Success = $success
    Account = $account
    AccountReference = $account_guid
    AuditLogs = $auditLogs
}

Write-Output $result | ConvertTo-Json -Depth 10
