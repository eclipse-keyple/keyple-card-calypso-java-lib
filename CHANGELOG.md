# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.0.3` (issue [#28]).

## [2.0.1] - 2021-11-22
### Added
- `CHANGELOG.md` file (issue [eclipse/keyple#6]).
- CI: Forbid the publication of a version already released (issue [#20]).
### Changed
- Merging of internal builders and parsers of APDU commands (issue [#24]).
### Fixed
- Take into account the last DF status for `isDfInvalidated()` method (issue [#22]).
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.0.2`
- "Keyple Service Resource Library" to version `2.0.1`
### Deprecated
- `addSuccessfulStatusWord` method (issue [calypsonet/calypsonet-terminal-calypso-java-api#11]).

## [2.0.0] - 2021-10-06
This is the initial release.
It follows the extraction of Keyple 1.0 components contained in the `eclipse/keyple-java` repository to dedicated repositories.
It also brings many major API changes.

[unreleased]: https://github.com/eclipse/keyple-card-calypso-java-lib/compare/2.0.1...HEAD
[2.0.1]: https://github.com/eclipse/keyple-card-calypso-java-lib/compare/2.0.0...2.0.1
[2.0.0]: https://github.com/eclipse/keyple-card-calypso-java-lib/releases/tag/2.0.0

[#28]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/28
[#24]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/24
[#22]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/22
[#20]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/20

[eclipse/keyple#6]: https://github.com/eclipse/keyple/issues/6

[calypsonet/calypsonet-terminal-calypso-java-api#11]: https://github.com/calypsonet/calypsonet-terminal-calypso-java-api/issues/11