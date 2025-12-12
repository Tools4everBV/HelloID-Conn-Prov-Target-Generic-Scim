# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).


## [2.1.1] - 2025-12-12

### Changed
- Updated code to align the to the latest Template
- Bugfix for comparison in update script
- Corrected the version number in the changelog from 2.0.1 to 2.1.0 to accurately reflect the new release.


## [2.1.0]

This is the first official release of _HelloID-Conn-Prov-Target-Generic-Scim_.

### Create/Update.ps1 (version: 1.0.0.3)

- Create/Update both implement a 'Begin/Process/End' style.
- Added 'Switch' statement to: _Create.ps1_ to accomodate a 'create' and 'correlate' action.
- Improved errorHandling
- Added inline documentation

### Permissions and import added (version: 1.1.0) 2025-12-12

### Added
- Added Permissions/groups ps1 files
- Added account import.ps1
- Changed configuration to allow for specification of the token generation url
- checked compliance with curruent template

### Changed

### Deprecated

### Removed