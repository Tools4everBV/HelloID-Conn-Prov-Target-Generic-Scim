# HelloID-Conn-Prov-Target-Generic-Scim
[Work in progress]

![scimLogo](./assets/scim.png)

## Introduction

The _'HelloID-Conn-Prov-Target-Generic-Scim'_ connector is a working example target connector based on scim based API's. http://www.simplecloud.info.

## Prerequisites

- When using the HelloID On-Premises agent, Windows PowerShell 5.1 must be installed.

- When the connector needs to be modified, make sure to have installed VSCode/PowerShell extension.

## Getting started

This connector is a working example for a scim based API.

> Although this is a working example, changes might have to be made according to your own environment.

Before implementing the connector in HelloID, make sure to test the connector in VSCode.

### PowerShell functions

The _persons.ps1_ file contains a few functions. All of which contain basic comment based help.

The functions that are available in version _1.0.0.0_:

- Get-GenericScimOAuthToken
- Invoke-GenericScimRestMethod
- Resolve-HTTPError

### Supported PowerShell versions

The connector is created for both Windows PowerShell 5.1 and PowerShell Core 7.0.3. This means that the connector can be executed in both cloud and on-premises using the HelloID Agent.

> Older versions of Windows PowerShell are not supported.

## Setup the PowerShell connector

1. Make sure you have access to the scim based API for your application.

2. Add a new 'Target System' to HelloID.

3. On the _Account_ tab, click __Custom connector configuration__ and import the code from the _configuration.json_ file.

4. Under __Account Create__ click __Configure__ and import the code from the _create.ps1_ file.

5. Go to the _Configuration_ tab and fill in the required fields.

![config](./assets/configuration.png)

| Parameter         | Description                                        |
| ----------------- | -------------------------------------------------- |
| ClientID          | The ClientID for the SCIM API                      |
| ClientSecret      | The ClientSecret for the SCIM API                  |
| Uri               | The Uri to the SCIM API. <http://some-api/v1/scim> |
| IsConnectionTls12 | Enables TLS 1.2 (Only necessary when using Windows PowerShell 5.1)        |

# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
