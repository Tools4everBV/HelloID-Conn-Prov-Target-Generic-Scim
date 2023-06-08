# HelloID-Conn-Prov-Target-Generic-Scim

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |
<br />
<p align="center">
  <img src="https://www.tools4ever.nl/connector-logos/scim-logo-2.png">
</p>

## Table of contents

- [Introduction](#Introduction)
- [Getting started](#Getting-started)
  + [Connection settings](#Connection-settings)
  + [Prerequisites](#Prerequisites)
  + [Contents](#Contents)
  + [PowerShell functions](#PowerShell-functions)
  + [Supported PowerShell versions](#Supported-PowerShell-versions)
- [Setup the connector](#Setup-the-connector)
- [Getting help](#Getting-help)
- [Contributing](#Contributing)
- [HelloID Docs](#HelloID-Docs)
- [Release history](#Release-history)

## Introduction

The _'HelloID-Conn-Prov-Target-Generic-Scim'_ connector is a working example target connector based on scim based API's. http://www.simplecloud.info. You can use this connector as a basis for applications using an API based on SCIM. The example connector uses OAuth for authentication. Before implementing this connector in your environment, make sure to check if OAUth is supported or if there's a different method of authentication.

## Getting started

### Connection settings

| Setting     | Description |
| ------------ | ----------- |
| ClientID          | The ClientID for the SCIM API                      |
| ClientSecret      | The ClientSecret for the SCIM API                  |
| Uri               | The Uri to the SCIM API. <http://some-api/v1/scim> |

### Prerequisites

- When using the HelloID On-Premises agent, Windows PowerShell 5.1 must be installed.

- When the connector needs to be modified, make sure to have installed VSCode/PowerShell extension.

### Supported PowerShell versions

The connector is created for both Windows PowerShell 5.1 and PowerShell Core. This means that the connector can be executed in both cloud and on-premises using the HelloID Agent.

> Older versions of Windows PowerShell are not supported.

## Setup the connector

1. Make sure you have access to the scim based API for your application.

2. Add a new 'Target System' to HelloID.

3. On the _Account_ tab, click __Custom connector configuration__ and import the code from the _configuration.json_ file.

4. Under __Account Create__ click __Configure__ and import the code from the _create.ps1_ file.

5. Go to the _Configuration_ tab and fill in the required fields.

| Parameter         | Description                                        |
| ----------------- | -------------------------------------------------- |
| ClientID          | The ClientID for the SCIM API                      |
| ClientSecret      | The ClientSecret for the SCIM API                  |
| Uri               | The Uri to the SCIM API. <http://some-api/v1/scim> |

## Getting help

> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012557600-Configure-a-custom-PowerShell-source-system) pages_

## Contributing

Find a bug or have an idea! Open an issue or submit a pull request!

## HelloID Docs

The official HelloID documentation can be found at: https://docs.helloid.com/

## Release history

### Create/Update.ps1 (version: 1.0.0.3)

- Create/Update both implement a 'Begin/Process/End' style.
- Added 'Switch' statement to: _Create.ps1_ to accomodate a 'create' and 'correlate' action.
- Improved errorHandling
- Added inline documentation
