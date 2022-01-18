# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Implementation of `EF_LIST` and `TRACEABILITY_INFORMATION` tags to `prepareGetData` methods (issue [#33]).
- Implementation of `prepareUpdateBinary` and `prepareWriteBinary` methods (issue [#34]).
- Implementation of `prepareReadBinary` method (issue [#35]).
- Implementation of `prepareReadRecordMultiple` methods (issue [#36]).
- Implementation of `prepareSearchRecordMultiple` methods (issue [#37]).
- Implementation of `processChangeKey` methods (issue [#39]).
### Fixed
- Revision 2 case for `prepareSelectFile` method (issue [#32]).
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.1.0`.

## [2.0.3] - 2021-12-17
### Fixed
- Commands anticipation management during `processClosing` method (issue [#30]).
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.0.5`.

## [2.0.2] - 2021-12-15
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

[unreleased]: https://github.com/eclipse/keyple-card-calypso-java-lib/compare/2.0.3...HEAD
[2.0.3]: https://github.com/eclipse/keyple-card-calypso-java-lib/compare/2.0.2...2.0.3
[2.0.2]: https://github.com/eclipse/keyple-card-calypso-java-lib/compare/2.0.1...2.0.2
[2.0.1]: https://github.com/eclipse/keyple-card-calypso-java-lib/compare/2.0.0...2.0.1
[2.0.0]: https://github.com/eclipse/keyple-card-calypso-java-lib/releases/tag/2.0.0

[#39]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/39
[#37]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/37
[#36]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/36
[#35]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/35
[#34]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/34
[#33]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/33
[#32]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/32
[#30]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/30
[#28]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/28
[#24]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/24
[#22]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/22
[#20]: https://github.com/eclipse/keyple-card-calypso-java-lib/issues/20

[eclipse/keyple#6]: https://github.com/eclipse/keyple/issues/6

[calypsonet/calypsonet-terminal-calypso-java-api#11]: https://github.com/calypsonet/calypsonet-terminal-calypso-java-api/issues/11