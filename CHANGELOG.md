# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.1.8] - 2025-04-11
:warning: Security Fix
### Security
- Fix length check

## [3.1.7] - 2025-03-20
:warning: Security Fix
### Security
- Restrict methods `prepareGetData`, `preparePutData`, `prepareReadRecord`, `prepareReadRecordsPartially` and `prepareSearchRecords` from
  being used in secure session
### Upgraded
- Keypop Calypso Card API `2.1.0` -> `2.1.2`

## [3.1.6] - 2025-01-17
### Fixed
- Fix postponed data issue for increase/decrease counter commands for PACA cards revision 2 having the following startup
  information pattern:
  - `0A 28 13 02 10 12 2B` (Contributed by SNCF Connect).

## [3.1.5] - 2024-10-25
### Fixed
- Fix postponed data issue for increase/decrease counter commands for OURA cards revision 2 having the following startup
  information pattern:
  - `0A 2E 13 02 00 01 01` (issue [#119]) (Contributed by SNCF Connect).

## [3.1.4] - 2024-09-25
### Fixed
- Revert version `3.1.3` due to useless fixed of distributed backward compatibility for legacy keyple-less clients.

## [3.1.3] - 2024-09-19
### Fixed
- Fixed distributed backward compatibility for legacy keyple-less clients.

## [3.1.2] - 2024-06-25
### Fixed
- Fixed the name of the field `stopOnUnsuccessfulStatusWord` in the adapter of the `CardRequestSpi` (issue [#115]).
### Changed
- Logging improvement.

## [3.1.1] - 2024-04-12
### Changed
- Java source and target levels `1.6` -> `1.8`
### Added
- Added dependency to "Keypop Calypso Crypto Asymmetric API" `0.1.0`
- Added support for PKI card transactions. 
### Fixed
- Fixed `Le` value sent in SV Get card command.
- Fixed postponed data issue for increase/decrease counter commands for PACA cards revision 2 having the following 
  startup information pattern:
  - `0A 0A 01 02 20 03 11` (issue [#109]) (Contributed by SNCF Connect).
### Upgraded
- Keypop Reader API `2.0.0` -> `2.0.1`
- Keypop Card API `2.0.0` -> `2.0.1`
- Keypop Calypso Card API `2.0.0` -> `2.1.0`
- Keypop Calypso Crypto Symmetric API `0.1.0` -> `0.1.1`
- Keypop Calypso Crypto Asymmetric API `0.1.0` -> `0.2.0`
- Keyple Common API `2.0.0` -> `2.0.1`
- Keyple Util Lib `2.3.1` -> `2.4.0`
- Gradle `6.8.3` -> `7.6.4`

## [3.0.1] - 2023-12-06
### Fixed
- `InvalidPinException` exception is now thrown instead of the generic `UnexpectedCommandStatusException` when the PIN
  entered is incorrect.

## [3.0.0] - 2023-11-28
:warning: Major version! Following the migration of the "Calypsonet Terminal" APIs to the
[Eclipse Keypop project](https://keypop.org), this library now implements Keypop interfaces.
### Fixed
- Fixed the crash that occurred when using "Read" commands in best-effort mode during a free card transaction.
### Added
- Added dependency to "Keypop Calypso Crypto Symmetric API" `0.1.0`
- Added the method `CalypsoCardApiFactory getCalypsoCardApiFactory()` to the `CalypsoExtensionService` class to
  get an implementation of the `CalypsoCardApiFactory` Keypop interface.
### Removed
- Removed dependency to "Keyple Service Resource Library".
- Removed methods from `CalypsoExtensionService`:
  - `getContextSetting()` (now provided by specific Calypso crypto module)
  - `createSearchCommandData()` (now provided by the `CalypsoCardApiFactory` Keypop interface)
  - `createBasicSignatureComputationData()` (now provided by specific Calypso crypto module)
  - `createTraceableSignatureComputationData()` (now provided by specific Calypso crypto module)
  - `createBasicSignatureVerificationData()` (now provided by specific Calypso crypto module)
  - `createTraceableSignatureVerificationData()` (now provided by specific Calypso crypto module)
  - `createCardSelection()` (now provided by the `CalypsoCardApiFactory` Keypop interface)
  - `createSamSelection()` (now provided by specific Calypso crypto module)
  - `createSamResourceProfileExtension(...)` (now provided by specific Calypso crypto module)
  - `createCardSecuritySetting()` (now provided by the `CalypsoCardApiFactory` Keypop interface)
  - `createCardTransaction(...)` (now provided by the `CalypsoCardApiFactory` Keypop interface)
  - `createCardTransactionWithoutSecurity(...)` (now provided by the `CalypsoCardApiFactory` Keypop interface)
  - `createSamSecuritySetting()` (now provided by specific Calypso crypto module)
  - `createSamTransaction(...)` (now provided by specific Calypso crypto module)
  - `createSamTransactionWithoutSecurity(...)` (now provided by specific Calypso crypto module)
- Removed interface `ContextSetting` (now provided by specific Calypso crypto module)
### Upgraded
- Calypsonet Terminal Reader API `1.3.0` -> Keypop Reader API `2.0.0`
- Calypsonet Terminal Card API `1.0.0` -> Keypop Card API `2.0.0`
- Calypsonet Terminal Calypso API `1.8.0` -> Keypop Calypso Card API `2.0.0`
- Keyple Util Library `2.3.0` -> `2.3.1` (source code not impacted)
- Removed dependency to "Keyple Service Resource Library" (used only by crypto components)

## [2.3.8] - 2023-09-11
### Added
- Added S1D3 to S1D7 to the list of SAM types recognized by the library (issue [#99]).
### Fixed
- Fixed the `prepareSetCounter(...)` method to allow the use of simulated counters (issue [#100]).
### Upgraded
- Keyple Util Library `2.3.0` -> `2.3.1` (source code not impacted)

## [2.3.7] - 2023-06-29
### Fixed
- Fixed remaining PIN attempt value in `CalypsoCard` after the PIN has been successfully changed.
- Fixed DF invalidation status in `CalypsoCard` after a successful invalidation or rehabilitation.
- Fixed an error that occurred with simulated counters.
### Upgraded
- Calypsonet Terminal Reader API `1.2.0` -> `1.3.0` (source code not impacted)

## [2.3.6] - 2023-06-20
### Added
- Added project status badges on `README.md` file.
### Fixed
- Fixed the unexpected behavior of card transactions containing only SAM commands, such as signature computation or 
  verification, in which SAM commands were not taken into account.
- Fixed the `prepareIncreaseCounter` and `prepareDecreaseCounter` methods to allow the use of simulated counters.
- CI: code coverage report when releasing.

## [2.3.5] - 2023-05-09
### Fixed
- An issue with "Select File" and "Read Record" commands when the card is a legacy ASK Tango card having the following 
startup information value:
  - `03 08 03 04 00 02 00`
### Upgraded
- "Keyple Service Resource Library" to version `2.1.1`.

## [2.3.4] - 2023-04-04
### Changed
- Prevent internal fields serialization.
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.8.0` (initialize SAM context for next transaction).

## [2.3.3] - 2023-03-08
### Fixed
- SV reload and debit logs are now updated in `CalypsoCard` during a transaction.
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.7.0` (pre-open secure session variant).

## [2.3.2] - 2023-02-17
### Changed
- The errors raised by the "Read Record" command executed during the card selection process are no longer blocking.
### Upgraded
- "Calypsonet Terminal Reader API" to version `1.2.0`.
- "Calypsonet Terminal Calypso API" to version `1.6.0` (replacement of "process" commands by "prepare" commands).
- "Google Gson Library" (com.google.code.gson) to version `2.10.1`.

## [2.3.1] - 2022-12-22
### Fixed
- SAM exception management for signature command.
- Increase/Decrease commands postponed data management for legacy cards.
### Deprecated
- `CalypsoExtensionService.createSamSecuritySetting` method.
- `CalypsoExtensionService.createSamTransaction` method.
- `CalypsoExtensionService.createSamTransactionWithoutSecurity` method.
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.5.0` (extended mode management).

## [2.3.0] - 2022-12-06
### Added
- `ContextSetting` setting to `CalypsoExtensionService` to manage the limitations of some not fully compliant terminals.
### Fixed
- Maximum payload length management for card and SAM APDUs.
- Exception management within a secure session.

## [2.2.5] - 2022-10-17
### Fixed
- Signature issue when doing SV operation in secure session.

## [2.2.4] - 2022-10-17
### Fixed
- Take card revision into account when parsing the FCP structure (issue [#83]).
- Generate multiple increase/decrease counter commands when the card does not support Increase/DecreaseMultiple
  commands (issue [#84]).
- Expected length issue in "Read Binary" card command.
- Set payload capacity to 235 for cards revision 3 having the following startup information pattern:
  `xx 3C xx xx xx 10 xx`
- Set payload capacity to 128 for cards revision 1 & 2.
- Fix postponed data issue for increase/decrease counter commands for cards revision 1 & 2 having the following startup 
  information pattern:
  - `06 xx 01 03 xx xx xx`
  - `06 0A 01 02 xx xx xx`
  - `xx xx 0x xx 15 xx xx`
  - `xx xx 1x xx 15 xx xx`
### Changed
- Enable binary commands with `PRIME_REVISION_2` cards.
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.4.1`.
- "Keyple Util Library" to version `2.3.0`.

## [2.2.3] - 2022-10-27
### Added
- JSON serializers for the new import/export feature of the card selection manager.
### Changed
- Merge of internal `setApduResponse` and `checkStatus` methods to `parseApduResponse` method.
- Improvement of the card command parsing process.
- Internal identification of the currently selected file.
### Fixed
- Management of "Read Records" card command for cards not supporting multiple record reads.
### Upgraded
- "Calypsonet Terminal Reader API" to version `1.1.0`.
- "Calypsonet Terminal Calypso API" to version `1.4.0` (issues [#40], [#41], [#42]).

## [2.2.2] - 2022-10-04
### Changed
- Use the SAM "Digest Update Multiple" command whenever possible.
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.3.0`.

## [2.2.1] - 2022-07-25
### Fixed
- Problem occurring when reusing a `CalypsoSamSelection` containing unlocking data.
### Upgraded
- "Keyple Service Resource Library" to version `2.0.2`.

## [2.2.0] - 2022-05-30
### Added
- `CalypsoExtensionService.createBasicSignatureComputationData` method.
- `CalypsoExtensionService.createTraceableSignatureComputationData` method.
- `CalypsoExtensionService.createBasicSignatureVerificationData` method.
- `CalypsoExtensionService.createTraceableSignatureVerificationData` method.
- `CalypsoExtensionService.createSamSecuritySetting` method.
- `CalypsoExtensionService.createSamTransaction` method.
- `CalypsoExtensionService.createSamTransactionWithoutSecurity` method.
- Additional Calypso requirements related to Stored Value operations (issue [#59]).
- Additional Calypso requirements related to abortion of a secure session (issue [#57]).
- Additional Calypso requirement related to the analysis of the APDU response length (issue [#62]).
- Additional Calypso requirement related to the card extended mode command management (issue [#64]).
- Additional Calypso requirement related to the card transaction counter (issue [#66]).
- Additional Calypso requirement related to the transaction audit data (issue [#68]).
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.2.0` (issue [#66]).
- "Keyple Util Library" to version `2.1.0`.
### Fixed
- Null Pointer Exception raised when the "open secure session" command returns an unexpected status word [#70]
- JSON serialization for interfaces in objects trees (issue [#71]).

## [2.1.0] - 2022-02-01
### Added
- Implementation of `EF_LIST` and `TRACEABILITY_INFORMATION` tags to `prepareGetData` methods (issue [#33]).
- Implementation of `prepareUpdateBinary` and `prepareWriteBinary` methods (issue [#34]).
- Implementation of `prepareReadBinary` method (issue [#35]).
- Implementation of `prepareReadRecordsPartially` method (issue [#36]).
- Implementation of `prepareSearchRecords` method (issue [#37]).
- Implementation of `prepareIncreaseCounters` and `prepareDecreaseCounters` methods (issue [#38]).
- Implementation of `processChangeKey` method (issue [#39]).
- Management of EFs with SFI equal to 0 (issue [#55]).
### Changed
- Internal parameter P2 to FFh for the "Change PIN" card APDU command.
### Fixed
- Revision 2 case for `prepareSelectFile` method (issue [#32]).
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.1.0` (issue [#53]).

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
- `CHANGELOG.md` file (issue [eclipse-keyple/keyple#6]).
- CI: Forbid the publication of a version already released (issue [#20]).
### Changed
- Merging of internal builders and parsers of APDU commands (issue [#24]).
### Fixed
- Take into account the last DF status for `isDfInvalidated()` method (issue [#22]).
### Upgraded
- "Calypsonet Terminal Calypso API" to version `1.0.2`
- "Keyple Service Resource Library" to version `2.0.1`

## [2.0.0] - 2021-10-06
This is the initial release.
It follows the extraction of Keyple 1.0 components contained in the `eclipse-keyple/keyple-java` repository to dedicated 
repositories.
It also brings many major API changes.

[unreleased]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/3.1.8...HEAD
[3.1.8]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/3.1.7...3.1.8
[3.1.7]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/3.1.6...3.1.7
[3.1.6]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/3.1.5...3.1.6
[3.1.5]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/3.1.4...3.1.5
[3.1.4]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/3.1.3...3.1.4
[3.1.3]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/3.1.2...3.1.3
[3.1.2]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/3.1.1...3.1.2
[3.1.1]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/3.0.1...3.1.1
[3.0.1]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/3.0.0...3.0.1
[3.0.0]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.3.8...3.0.0
[2.3.8]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.3.7...2.3.8
[2.3.7]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.3.6...2.3.7
[2.3.6]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.3.5...2.3.6
[2.3.5]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.3.4...2.3.5
[2.3.4]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.3.3...2.3.4
[2.3.3]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.3.2...2.3.3
[2.3.2]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.3.1...2.3.2
[2.3.1]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.3.0...2.3.1
[2.3.0]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.2.5...2.3.0
[2.2.5]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.2.4...2.2.5
[2.2.4]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.2.3...2.2.4
[2.2.3]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.2.2...2.2.3
[2.2.2]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.2.1...2.2.2
[2.2.1]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.2.0...2.2.1
[2.2.0]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.1.0...2.2.0
[2.1.0]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.0.3...2.1.0
[2.0.3]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.0.2...2.0.3
[2.0.2]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.0.1...2.0.2
[2.0.1]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/compare/2.0.0...2.0.1
[2.0.0]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/releases/tag/2.0.0

[#119]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/119
[#115]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/115
[#109]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/109
[#100]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/100
[#99]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/99
[#84]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/84
[#83]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/83
[#71]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/71
[#70]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/70
[#68]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/68
[#66]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/66
[#64]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/64
[#62]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/62
[#59]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/59
[#57]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/57
[#55]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/55
[#53]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/53
[#42]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/42
[#41]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/41
[#40]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/40
[#39]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/39
[#38]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/38
[#37]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/37
[#36]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/36
[#35]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/35
[#34]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/34
[#33]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/33
[#32]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/32
[#30]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/30
[#28]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/28
[#24]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/24
[#22]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/22
[#20]: https://github.com/eclipse-keyple/keyple-card-calypso-java-lib/issues/20

[eclipse-keyple/keyple#6]: https://github.com/eclipse-keyple/keyple/issues/6
