# HelloID-Conn-Prov-Target-Generic-Scim

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |
<br />
<p align="center">
  <img src="https://www.tools4ever.nl/connector-logos/scim-logo-2.png">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Generic-Scim](#helloid-conn-prov-target-connectorname)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Supported features](#supported-features)
  - [Getting started](#getting-started)
    - [HelloID Icon URL](#helloid-icon-url)
    - [Requirements](#requirements)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
    - [Account Reference](#account-reference)
  - [Remarks](#remarks)
  - [Development resources](#development-resources)
    - [API endpoints](#api-endpoints)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)


## Introduction

The _'HelloID-Conn-Prov-Target-Generic-Scim'_ connector is a working example target connector based on scim based API's. http://www.simplecloud.info. You can use this connector as a basis for applications using an API based on SCIM. The example connector uses OAuth for authentication. Before implementing this connector in your environment, make sure to check if OAUth is supported or if there's a different method of authentication.

## Supported features

The following features are available:

| Feature                                   | Supported | Actions                                 | Remarks           |
| ----------------------------------------- | --------- | --------------------------------------- | ----------------- |
| **Account Lifecycle**                     | ✅         | Create, Update, Enable, Disable, Delete |                   |
| **Permissions\Groups**                    | ✅         | Retrieve, Grant, Revoke                 | Static   |
| **Resources**                             | ❌         | -                                       |                   |
| **Entitlement Import: Accounts**          | ✅         | -                                       |                   |
| **Entitlement Import: Permissions\groups**       | ✅         | -                                       |                   |
| **Governance Reconciliation Resolutions** | ✅      | -                                       |                   |


## Getting started

### HelloID Icon URL
URL of the icon used for the HelloID Provisioning target system.
```
https://www.tools4ever.nl/connector-logos/scim-logo-2.png
```

### Requirements

- When using the HelloID On-Premises agent, Windows PowerShell 5.1 must be installed.

- When the connector needs to be modified, make sure to have installed VSCode/

### Supported PowerShell versions

The connector is created for both Windows PowerShell 5.1 and PowerShell Core. This means that the connector can be executed in both cloud and on-premises using the HelloID Agent.

> Older versions of Windows PowerShell are not supported.

### Connection settings

| Setting     | Description |
| ------------ | ----------- |
| ClientID          | The ClientID for the SCIM API                      |
| ClientSecret      | The ClientSecret for the SCIM API                  |
| BaseUrl           | The Uri to the SCIM API. <http://some-api/scim>|
| TokenUrl          | The Uri to the Token generation endpoint. <http://some-api/oauth/token>

### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _{connectorName}_ to a person in _HelloID_.

As this is a template, below values are only an example, it may differ for specific implementations.

| Setting                   | Value                             |
| ------------------------- | --------------------------------- |
| Enable correlation        | `True`                            |
| Person correlation field  | `PersonContext.Person.ExternalId` |
| Account correlation field | `ExternalId` 

                |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.


### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

### Account Reference

The account reference is populated with the property `id` 


## Remarks
- There is duplicate mapping logic in both the *create* and *update*. If you modify the field mapping, be sure to update both files accordingly.
- In the *create* operation, all users are currently retrieved. In many cases, this can be optimized using a filter.  
  If filtering is not possible and fetching all users takes too long, consider moving this logic to a resource script.

## Setup the connector

1. Make sure you have access to the scim based API for your application.

2. Add a new 'Target System' to HelloID.

3. On the _Account_ tab, click __Custom connector configuration__ and import the code from the _configuration.json_ file.

4. Under __Account Create__ click __Configure__ and import the code from the _create.ps1_ file.

5. Go to the _Configuration_ tab and fill in the required fields.


## Development resources

### API endpoints

The following endpoints are used by the connector

| Endpoint | Description               |
| -------- | ------------------------- |
| GET /Users   | Retrieve user information, used in correlation and import |
| GET /Users/{id} | Retrieve a specific user. used in update, enable,disable and delete |
| POST /Users  | create an user |
| PATCH /Users/{id} | update a specific user
| GET /Groups     | Retrieve available groups. used in permissions.ps1, and import.ps1 |
| PATCH /Groups   | add a member to a group |


### API documentation


https://scim.cloud/#Overview



## Getting help

> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012557600-Configure-a-custom-PowerShell-source-system) pages_

## Contributing

Find a bug or have an idea! Open an issue or submit a pull request!

## HelloID Docs

The official HelloID documentation can be found at: https://docs.helloid.com/

