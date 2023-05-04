/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.card.calypso;

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.*;
import org.calypsonet.terminal.calypso.GetDataTag;
import org.calypsonet.terminal.calypso.SelectFileControl;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.transaction.*;
import org.calypsonet.terminal.calypso.transaction.InconsistentDataException;
import org.calypsonet.terminal.card.*;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.calypsonet.terminal.reader.CardReader;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link org.calypsonet.terminal.calypso.transaction.CardTransactionManager}.
 *
 * <ul>
 *   <li>CL-APP-ISOL.1
 *   <li>CL-CMD-SEND.1
 *   <li>CL-CMD-RECV.1
 *   <li>CL-CMD-CASE.1
 *   <li>CL-CMD-LCLE.1
 *   <li>CL-CMD-DATAIN.1
 *   <li>CL-C1-5BYTE.1
 *   <li>CL-C1-MAC.1
 *   <li>CL-C4-LE.1
 *   <li>CL-CLA-CMD.1
 *   <li>CL-RFU-FIELDCMD.1
 *   <li>CL-RFU-VALUECMD.1
 *   <li>CL-RFU-FIELDRSP.1
 *   <li>CL-SW-ANALYSIS.1
 *   <li>CL-SW-SUCCESS.1
 *   <li>CL-SF-SFI.1
 *   <li>CL-PERF-HFLOW.1
 *   <li>CL-CSS-INFOEND.1
 *   <li>CL-SW-CHECK.1
 *   <li>CL-CSS-SMEXCEED.1
 *   <li>CL-CSS-6D006E00.1
 *   <li>CL-CSS-UNEXPERR.1
 *   <li>CL-CSS-INFOCSS.1
 *   <li>CL-CSS-OSSMODE.1
 *   <li>CL-SV-CMDMODE.1
 * </ul>
 *
 * @since 2.0.0
 */
final class CardTransactionManagerAdapter
    extends CommonTransactionManagerAdapter<CardTransactionManager, CardSecuritySetting>
    implements CardTransactionManager {

  private static final Logger logger = LoggerFactory.getLogger(CardTransactionManagerAdapter.class);
  private static final String PATTERN_1_BYTE_HEX = "%02Xh";

  /* Prefix/suffix used to compose exception messages */
  private static final String MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_NB_COMMANDS =
      "The number of commands/responses does not match: nb commands = ";
  private static final String MSG_NB_RESPONSES = ", nb responses = ";
  private static final String MSG_CARD_READER_COMMUNICATION_ERROR =
      "A communication error with the card reader occurred ";
  private static final String MSG_CARD_COMMUNICATION_ERROR =
      "A communication error with the card occurred ";
  private static final String MSG_CARD_COMMAND_ERROR = "A card command error occurred ";
  private static final String MSG_PIN_NOT_AVAILABLE = "PIN is not available for this card";
  private static final String MSG_CARD_SESSION_MAC_NOT_VERIFIABLE =
      "Unable to verify the card session MAC associated to the successfully closed secure session.";
  private static final String MSG_CARD_SV_MAC_NOT_VERIFIABLE =
      "Unable to verify the card SV MAC associated to the SV operation.";
  private static final String MSG_INVALID_CARD_SESSION_MAC = "Invalid card session MAC";
  private static final String MSG_MSS_COMMAND_NOT_SUPPORTED =
      "'Manage Secure Session' command not available for this context (Card and/or SAM does not support extended mode)";
  private static final String MSG_ENCRYPTION_ALREADY_ACTIVE = "Encryption already active";
  private static final String MSG_ENCRYPTION_NOT_ACTIVE = "Encryption not active";
  private static final String SECURE_SESSION_NOT_OPEN = "Secure session not open";
  private static final String SECURE_SESSION_OPEN = "Secure session open";

  private static final String RECORD_NUMBER = "record number";
  private static final String OFFSET = "offset";
  private static final String MSG_RECORD_DATA = "record data";
  private static final String MSG_RECORD_DATA_LENGTH = "record data length";

  // commands that modify the content of the card in session have a cost on the session buffer equal
  // to the length of the outgoing data plus 6 bytes
  private static final int SESSION_BUFFER_CMD_ADDITIONAL_COST = 6;
  private static final int APDU_HEADER_LENGTH = 5;

  private static final ApduResponseApi RESPONSE_OK =
      new ApduResponseAdapter(new byte[] {(byte) 0x90, (byte) 0x00});

  private static final ApduResponseApi RESPONSE_OK_POSTPONED =
      new ApduResponseAdapter(new byte[] {(byte) 0x62, (byte) 0x00});

  /* Final fields */
  private final ProxyReaderApi cardReader;
  private final CalypsoCardAdapter card;
  private final CardSecuritySettingAdapter securitySetting; // Do not use anymore
  private final SymmetricCryptoSecuritySettingAdapter symmetricCryptoSecuritySetting;
  private final SymmetricCryptoTransactionManagerSpi symmetricCryptoTransactionManagerSpi;
  private final LegacySamCardTransactionCryptoExtension cryptoExtension;
  private final List<CardCommand> cardCommands = new ArrayList<CardCommand>();
  private final SortedMap<Integer, ManageSecureSessionDto> manageSecureSessionMap =
      new TreeMap<Integer, ManageSecureSessionDto>();
  private final int cardPayloadCapacity;

  /* Dynamic fields */
  private boolean isSecureSessionOpen;
  private WriteAccessLevel writeAccessLevel;
  private ChannelControl channelControl = ChannelControl.KEEP_OPEN;
  private int modificationsCounter;
  private SvOperation svOperation;
  private SvAction svAction;
  private CardCommandRef svLastCommandRef;
  private CardCommand svLastModifyingCommand;
  private boolean isSvOperationComplete;
  private int svPostponedDataIndex;
  private int nbPostponedData;
  private boolean isExtendedMode;
  private boolean isEncryptionRequested;
  private boolean isEncryptionActive;

  /* New fields */
  private final TransactionContextDto _transactionContext;
  private Boolean _isLastApiLevelUsed;
  private final List<CardCommand> _cardCommands = new ArrayList<CardCommand>();
  private WriteAccessLevel _writeAccessLevel;
  private boolean _isSecureSessionOpen;
  private boolean _isEncryptionActive;
  private int _modificationsCounter;
  private int _nbPostponedData;
  private int _svPostponedDataIndex = -1;
  private boolean _isSvGet;
  private SvOperation _svOperation;
  private boolean _isSvOperationInSecureSession;

  /**
   * Checks the compliance of the API level used by the user.
   *
   * @param isLastApiLevelUsed Is last API level used?
   */
  private void checkApiLevelCompliance(boolean isLastApiLevelUsed) {
    if (_isLastApiLevelUsed == null) {
      _isLastApiLevelUsed = isLastApiLevelUsed;
    } else if (isLastApiLevelUsed != _isLastApiLevelUsed) {
      throw new IllegalStateException(
          "Prohibition to combine the use of new methods released since version 1.6"
              + " of the Terminal Calypso API with those marked as deprecated");
    }
  }

  /**
   * @return The current command context as a new DTO instance containing a reference to the global
   *     transaction context.
   */
  private CommandContextDto getCommandContext() {
    return new CommandContextDto(_isSecureSessionOpen, _isEncryptionActive);
  }

  /**
   * Creates an instance of {@link CardTransactionManager}.
   *
   * <p>Secure operations are enabled by the presence of {@link CardSecuritySetting}.
   *
   * @param cardReader The reader through which the card communicates.
   * @param card The initial card data provided by the selection process.
   * @param securitySetting The security settings.
   * @since 2.0.0
   */
  CardTransactionManagerAdapter(
      ProxyReaderApi cardReader,
      CalypsoCardAdapter card,
      CardSecuritySettingAdapter securitySetting,
      ContextSettingAdapter contextSetting) {
    super(card, securitySetting, null);

    this.cardReader = cardReader;
    this.card = card;
    this.securitySetting = securitySetting;

    if (securitySetting != null && securitySetting.getControlSam() != null) {
      // Secure operations mode
      symmetricCryptoSecuritySetting =
          buildSymmetricCryptoSecuritySetting(securitySetting, contextSetting);
      SymmetricCryptoTransactionManagerFactoryAdapter cryptoTransactionManagerFactory =
          symmetricCryptoSecuritySetting.getCryptoTransactionManagerFactory();
      // Extended mode flag
      isExtendedMode =
          card.isExtendedModeSupported()
              && cryptoTransactionManagerFactory.isExtendedModeSupported();
      if (!isExtendedMode) {
        disablePreOpenMode();
      }
      // Adjust card & SAM payload capacities
      cardPayloadCapacity =
          Math.min(
              card.getPayloadCapacity(),
              cryptoTransactionManagerFactory.getMaxCardApduLengthSupported() - APDU_HEADER_LENGTH);
      // CL-SAM-CSN.1
      symmetricCryptoTransactionManagerSpi =
          cryptoTransactionManagerFactory.createTransactionManager(
              card.getCalypsoSerialNumberFull(), isExtendedMode, getTransactionAuditData());
      cryptoExtension =
          (LegacySamCardTransactionCryptoExtension) symmetricCryptoTransactionManagerSpi;
    } else {
      // Non-secure operations mode
      symmetricCryptoSecuritySetting = null;
      isExtendedMode = card.isExtendedModeSupported();
      cardPayloadCapacity = card.getPayloadCapacity();
      symmetricCryptoTransactionManagerSpi = null;
      cryptoExtension = null;
    }

    modificationsCounter = card.getModificationsCounter();
    _modificationsCounter = card.getModificationsCounter();
    _transactionContext = new TransactionContextDto(card, symmetricCryptoTransactionManagerSpi);
  }

  private static SymmetricCryptoSecuritySettingAdapter buildSymmetricCryptoSecuritySetting(
      CardSecuritySettingAdapter src, ContextSettingAdapter contextSetting) {
    SymmetricCryptoSecuritySettingAdapter dest = new SymmetricCryptoSecuritySettingAdapter();
    dest.setCryptoTransactionManager(
        new SymmetricCryptoTransactionManagerFactoryAdapter(
            src.getControlSamReader(),
            src.getControlSam(),
            contextSetting != null ? contextSetting.getContactReaderPayloadCapacity() : null,
            src));
    if (src.isMultipleSessionEnabled()) {
      dest.enableMultipleSession();
    }
    if (src.isRatificationMechanismEnabled()) {
      dest.enableRatificationMechanism();
    }
    if (src.isPinPlainTransmissionEnabled()) {
      dest.enablePinPlainTransmission();
    }
    if (src.isSvLoadAndDebitLogEnabled()) {
      dest.enableSvLoadAndDebitLog();
    }
    if (src.isSvNegativeBalanceAuthorized()) {
      dest.authorizeSvNegativeBalance();
    }
    dest.getKifMap().putAll(src.getKifMap());
    dest.getDefaultKifMap().putAll(src.getDefaultKifMap());
    dest.getDefaultKvcMap().putAll(src.getDefaultKvcMap());
    dest.getAuthorizedSessionKeys().addAll(src.getAuthorizedSessionKeys());
    dest.getAuthorizedSvKeys().addAll(src.getAuthorizedSvKeys());
    if (src.getPinVerificationCipheringKif() != null) {
      dest.setPinVerificationCipheringKey(
          src.getPinVerificationCipheringKif(), src.getPinVerificationCipheringKvc());
    }
    if (src.getPinModificationCipheringKif() != null) {
      dest.setPinModificationCipheringKey(
          src.getPinModificationCipheringKif(), src.getPinModificationCipheringKvc());
    }
    return dest;
  }

  /** Clears the info associated with the "pre-open" mode. */
  private void disablePreOpenMode() {
    card.setPreOpenWriteAccessLevel(null);
    card.setPreOpenDataOut(null);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Deprecated
  @Override
  public CardReader getCardReader() {
    return (CardReader) cardReader;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Deprecated
  @Override
  public CalypsoCard getCalypsoCard() {
    return card;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Override
  @Deprecated
  public CardSecuritySetting getCardSecuritySetting() {
    return getSecuritySetting();
  }

  /**
   * Checks if the control SAM is set.
   *
   * @throws IllegalStateException If control SAM is not set.
   */
  private void checkSymmetricCryptoTransactionManager() {
    if (symmetricCryptoTransactionManagerSpi == null) {
      throw new IllegalStateException("Crypto service not configured");
    }
  }

  /**
   * Returns the KVC to use according to the provided write access and the card's KVC.
   *
   * @param writeAccessLevel The write access level.
   * @param kvc The card KVC value.
   * @return Null if the card did not provide a KVC value and if there's no default KVC value.
   */
  private Byte computeKvc(WriteAccessLevel writeAccessLevel, Byte kvc) {
    if (kvc != null) {
      return kvc;
    }
    return symmetricCryptoSecuritySetting.getDefaultKvc(writeAccessLevel);
  }

  /**
   * Returns the KIF to use according to the provided write access level and KVC.
   *
   * @param writeAccessLevel The write access level.
   * @param kif The card KIF value.
   * @param kvc The previously computed KVC value.
   * @return Null if the card did not provide a KIF value and if there's no default KIF value.
   */
  private Byte computeKif(WriteAccessLevel writeAccessLevel, Byte kif, Byte kvc) {
    // CL-KEY-KIF.1
    if ((kif != null && kif != (byte) 0xFF) || (kvc == null)) {
      return kif;
    }
    // CL-KEY-KIFUNK.1
    Byte result = symmetricCryptoSecuritySetting.getKif(writeAccessLevel, kvc);
    if (result == null) {
      result = symmetricCryptoSecuritySetting.getDefaultKif(writeAccessLevel);
    }
    return result;
  }

  /**
   * Provides data to be processed by the symmetric key crypto service to prepare the computation of
   * the secure session MAC.
   *
   * @param apduRequests A list of APDU commands.
   * @param apduResponses A list of APDU responses.
   * @param fromIndex (inclusive)
   * @param toIndex (exclusive)
   */
  private void updateTerminalSessionMac(
      List<ApduRequestSpi> apduRequests,
      List<ApduResponseApi> apduResponses,
      int fromIndex,
      int toIndex) {
    for (int i = fromIndex; i < toIndex; i++) {
      try {
        symmetricCryptoTransactionManagerSpi.updateTerminalSessionMac(
            apduRequests.get(i).getApdu());
        symmetricCryptoTransactionManagerSpi.updateTerminalSessionMac(
            apduResponses.get(i).getApdu());
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      } catch (SymmetricCryptoIOException e) {
        throw (RuntimeException) e.getCause();
      }
    }
  }

  /**
   * Open a single Secure Session.
   *
   * @param cardCommands the card commands inside session.
   * @throws IllegalStateException if no {@link CardSecuritySetting} is available.
   */
  private void processAtomicOpening(List<CardCommand> cardCommands) {

    card.backupFiles();
    nbPostponedData = 0;

    if (cardCommands == null) {
      cardCommands = new ArrayList<CardCommand>();
    }

    int manageSecureSessionIndexOffset;
    int sfi = 0;
    int recordNumber = 0;

    if (isEncryptionActive) {
      manageSecureSessionIndexOffset = 2; // Open session + Manage session commands
      // It is only possible in case of a "new" multiple session.
      // We add an MSS command first in order to activate the encryption.
      // We use the key 0 because we are sure that there is no entry in the map for this case.
      cardCommands.add(0, new CmdCardManageSession(card, true, null));
      ManageSecureSessionDto dto = new ManageSecureSessionDto();
      dto.index = -1; // Index is set to -1 in order to be correctly incremented by the offset.
      dto.isEncryptionRequested = true;
      manageSecureSessionMap.put(0, dto);
    } else {
      manageSecureSessionIndexOffset = 1; // Open session command inserted at index 0.
      // Let's check if we have a read record command at the top of the command list.
      // If so, then the command is withdrawn in favour of its equivalent executed at the same
      // time as the open secure session command.
      // The sfi and record number to be read when the open secure session command is executed.
      // The default value is 0 (no record to read) but we will optimize the exchanges if a read
      // record command has been prepared.
      // Note: This case can happen only during the first opening.
      if (!cardCommands.isEmpty()) {
        CardCommand cardCommand = cardCommands.get(0);
        if (cardCommand.getCommandRef() == CardCommandRef.READ_RECORDS
            && ((CmdCardReadRecords) cardCommand).getReadMode()
                == CmdCardReadRecords.ReadMode.ONE_RECORD) {
          sfi = ((CmdCardReadRecords) cardCommand).getSfi();
          recordNumber = ((CmdCardReadRecords) cardCommand).getFirstRecordNumber();
          cardCommands.remove(0);
          manageSecureSessionIndexOffset = 0;
        }
      }
    }

    // initialize the crypto service for a new secure session and retrieve the terminal challenge
    byte[] samChallenge;
    try {
      samChallenge = symmetricCryptoTransactionManagerSpi.initTerminalSecureSessionContext();
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }

    // Build the "Open Secure Session" card command.
    CmdCardOpenSecureSession cmdCardOpenSecureSession =
        new CmdCardOpenSecureSession(
            card, writeAccessLevel, samChallenge, sfi, recordNumber, isExtendedMode);

    // Add the "Open Secure Session" card command in first position.
    cardCommands.add(0, cmdCardOpenSecureSession);

    isSecureSessionOpen = true;
    _isSecureSessionOpen = true;

    // List of APDU requests to hold Open Secure Session and other optional commands
    List<ApduRequestSpi> apduRequests =
        new ArrayList<ApduRequestSpi>(getApduRequests(cardCommands));

    if (containsNoManageSecureSessionCommand(
        apduRequests.size() - manageSecureSessionIndexOffset)) {
      // Standard process for all commands.
      executeCardCommandsForOpening(
          cardCommands, apduRequests, apduRequests.size(), cmdCardOpenSecureSession);
    } else {
      // There is at least one MSS command to execute.
      // Note: inserting the open session command shifted the indexes.
      // We first perform the standard process for all commands preceding the first MSS command (MSS
      // excluded).
      int firstManageSecureSessionIndex =
          manageSecureSessionMap.get(manageSecureSessionMap.firstKey()).index
              + manageSecureSessionIndexOffset;
      executeCardCommandsForOpening(
          cardCommands, apduRequests, firstManageSecureSessionIndex, cmdCardOpenSecureSession);
      // Then we execute all the following commands until the last MSS command (MSS included).
      int nextIndex =
          executeCardCommandsWithManageSecureSession(
              cardCommands,
              apduRequests,
              firstManageSecureSessionIndex,
              manageSecureSessionIndexOffset);
      // Finally, we perform the standard process for any remaining commands.
      if (nextIndex < apduRequests.size()) {
        executeCardCommands(
            cardCommands, apduRequests, nextIndex, apduRequests.size(), ChannelControl.KEEP_OPEN);
      }
    }
  }

  /**
   * Returns true if a "Manage Secure Session" command is not contained in index range
   * [0..maxIndex[.
   *
   * @param maxIndex The max index value (exclusive).
   * @return true if no one "Manage Secure Session" command is contained in index range
   *     [0..maxIndex[.
   */
  private boolean containsNoManageSecureSessionCommand(int maxIndex) {
    return manageSecureSessionMap.isEmpty()
        || manageSecureSessionMap.get(manageSecureSessionMap.firstKey()).index >= maxIndex;
  }

  /**
   * Executes commands containing at least one "Manage Secure Session" command.
   *
   * @param cardCommands The card commands.
   * @param apduRequests The APDU requests.
   * @param fromIndex Index of the first command to execute.
   * @param manageSecureSessionIndexOffset Offset of the index to use to retrieve "Manage Secure
   *     Session" commands in the whole list.
   * @return The index of the next command to execute.
   */
  private int executeCardCommandsWithManageSecureSession(
      List<CardCommand> cardCommands,
      List<ApduRequestSpi> apduRequests,
      int fromIndex,
      int manageSecureSessionIndexOffset) {
    int nextIndex = fromIndex;
    for (ManageSecureSessionDto manageSecureSessionDto : manageSecureSessionMap.values()) {
      int toIndex =
          manageSecureSessionDto.index
              + manageSecureSessionIndexOffset
              + 1; // Include the MSS command
      if (toIndex > apduRequests.size()) {
        break;
      }
      if (manageSecureSessionDto.isEarlyMutualAuthenticationRequested) {
        // MSS with mutual authentication.
        // We execute first all the commands until the next MSS command (MSS excluded).
        executeCardCommands(
            cardCommands, apduRequests, nextIndex, toIndex - 1, ChannelControl.KEEP_OPEN);
        // Then we generate the terminal session MAC, finalize and execute the MSS command.
        generateTerminalSessionMac(
            apduRequests.get(manageSecureSessionDto.index + manageSecureSessionIndexOffset));
        executeCardCommands(
            cardCommands, apduRequests, toIndex - 1, toIndex, ChannelControl.KEEP_OPEN);
        checkCardSessionMac(
            (CmdCardManageSession)
                cardCommands.get(manageSecureSessionDto.index + manageSecureSessionIndexOffset));
      } else {
        // MSS with encryption only.
        // We execute all the commands until the next MSS command (MSS included).
        executeCardCommands(
            cardCommands, apduRequests, nextIndex, toIndex, ChannelControl.KEEP_OPEN);
      }
      if (manageSecureSessionDto.isEncryptionRequested) {
        isEncryptionActive = true;
        try {
          symmetricCryptoTransactionManagerSpi.activateEncryption();
        } catch (SymmetricCryptoException e) {
          throw (RuntimeException) e.getCause();
        } catch (SymmetricCryptoIOException e) {
          throw (RuntimeException) e.getCause();
        }
      } else {
        isEncryptionActive = false;
        try {
          symmetricCryptoTransactionManagerSpi.deactivateEncryption();
        } catch (SymmetricCryptoException e) {
          throw (RuntimeException) e.getCause();
        } catch (SymmetricCryptoIOException e) {
          throw (RuntimeException) e.getCause();
        }
      }
      nextIndex = toIndex;
    }
    return nextIndex;
  }

  /** Aborts the secure session without raising any exception. */
  private void abortSecureSessionSilently() {
    if (isSecureSessionOpen) {
      try {
        processCancel();
      } catch (RuntimeException e) {
        logger.warn(
            "An error occurred while aborting the current secure session: {}", e.getMessage());
      }
      isSecureSessionOpen = false;
      _isSecureSessionOpen = false;
    }
  }

  /**
   * Process card commands in a Secure Session.
   *
   * <ul>
   *   <li>On the card reader, generates a CardRequest with channelControl set to KEEP_OPEN, and
   *       ApduRequests with the card commands.
   *   <li>In case the secure session is active, the "cache" of SAM commands is completed with the
   *       corresponding Digest Update commands.
   *   <li>If a session is open and channelControl is set to CLOSE_AFTER, the current card session
   *       is aborted
   *   <li>Returns the corresponding card CardResponse.
   * </ul>
   *
   * @param cardCommands the card commands inside session.
   * @param channelControl indicated if the card channel of the card reader must be closed after the
   *     last command.
   */
  private void processAtomicCardCommands(
      List<CardCommand> cardCommands, ChannelControl channelControl) {

    // Get the list of C-APDU to transmit
    List<ApduRequestSpi> apduRequests = getApduRequests(cardCommands);

    if (containsNoManageSecureSessionCommand(apduRequests.size())) {
      // Standard process for all commands.
      executeCardCommands(cardCommands, apduRequests, 0, apduRequests.size(), channelControl);
    } else {
      // There is at least one MSS command to execute.
      // We execute all the commands until the last MSS command (MSS included).
      int nextIndex = executeCardCommandsWithManageSecureSession(cardCommands, apduRequests, 0, 0);
      // Then we perform the standard process for any remaining commands.
      if (nextIndex < apduRequests.size()) {
        executeCardCommands(
            cardCommands, apduRequests, nextIndex, apduRequests.size(), ChannelControl.KEEP_OPEN);
      }
    }
  }

  /**
   * Finalizes the "Manage Secure Session" card command for mutual authentication request.
   *
   * @param apduRequest The APDU request to complete.
   */
  private void generateTerminalSessionMac(ApduRequestSpi apduRequest) {
    try {
      byte[] terminalSessionMac = symmetricCryptoTransactionManagerSpi.generateTerminalSessionMac();
      System.arraycopy(
          terminalSessionMac,
          0,
          apduRequest.getApdu(),
          apduRequest.getApdu().length - 9,
          terminalSessionMac.length);
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }
  }

  /**
   * Checks card session MAC during the early authentication process.
   *
   * @param cardCommand The card command.
   * @throws InvalidCardSignatureException If the card session MAC is invalid.
   */
  private void checkCardSessionMac(CmdCardManageSession cardCommand) {
    try {
      if (!symmetricCryptoTransactionManagerSpi.isCardSessionMacValid(
          cardCommand.getCardSessionMac())) {
        throw new InvalidCardSignatureException("Invalid card (authentication failed!)");
      }
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }
  }

  /**
   * Executes the APDU requests and updates the associated card commands.
   *
   * @param cardCommands The card commands.
   * @param apduRequests The APDU requests.
   * @param toIndex To index (exclusive).
   * @param cmdCardOpenSecureSession The "Open Secure Session" card command.
   */
  private void executeCardCommandsForOpening(
      List<CardCommand> cardCommands,
      List<ApduRequestSpi> apduRequests,
      int toIndex,
      CmdCardOpenSecureSession cmdCardOpenSecureSession) {

    cardCommands = cardCommands.subList(0, toIndex);
    apduRequests = apduRequests.subList(0, toIndex);

    // Wrap the list of C-APDUs into a card request
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, true);

    // Open a secure session, transmit the commands to the card and keep channel open
    CardResponseApi cardResponse = transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);

    // Retrieve the list of R-APDUs
    List<ApduResponseApi> apduResponses =
        cardResponse.getApduResponses(); // NOSONAR cardResponse is not null

    // Parse all the responses and fills the CalypsoCard object with the command data.
    try {
      parseApduResponses(cardCommands, apduResponses);
    } catch (CardCommandException e) {
      throw new UnexpectedCommandStatusException(
          MSG_CARD_COMMAND_ERROR
              + "while processing the response to open session: "
              + e.getCommandRef()
              + getTransactionAuditDataAsString(),
          e);
    } catch (InconsistentDataException e) {
      throw new InconsistentDataException(e.getMessage() + getTransactionAuditDataAsString());
    } finally {
      if (isExtendedMode && !card.isExtendedModeSupported()) {
        isExtendedMode = false;
      }
    }

    // The card KIF/KVC (KVC may be null for card Rev 1.0)
    Byte cardKif = cmdCardOpenSecureSession.getKif();
    Byte cardKvc = cmdCardOpenSecureSession.getKvc();

    if (logger.isDebugEnabled()) {
      logger.debug(
          "processAtomicOpening => opening: CARD_CHALLENGE={}, CARD_KIF={}, CARD_KVC={}",
          HexUtil.toHex(cmdCardOpenSecureSession.getCardChallenge()),
          cardKif != null ? String.format(PATTERN_1_BYTE_HEX, cardKif) : null,
          cardKvc != null ? String.format(PATTERN_1_BYTE_HEX, cardKvc) : null);
    }

    Byte kvc = computeKvc(writeAccessLevel, cardKvc);
    Byte kif = computeKif(writeAccessLevel, cardKif, kvc);

    if (!symmetricCryptoSecuritySetting.isSessionKeyAuthorized(kif, kvc)) {
      throw new UnauthorizedKeyException(
          String.format(
              "Unauthorized key error: KIF=%s, KVC=%s %s",
              kif != null ? String.format(PATTERN_1_BYTE_HEX, kif) : null,
              kvc != null ? String.format(PATTERN_1_BYTE_HEX, kvc) : null,
              getTransactionAuditDataAsString()));
    }

    // Initialize a new secure session.
    try {
      symmetricCryptoTransactionManagerSpi.initTerminalSessionMac(
          apduResponses.get(0).getDataOut(), kif, kvc);
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }

    // Add all commands data to the digest computation. The first command in the list is the
    // open secure session command. This command is not included in the digest computation, so
    // we skip it and start the loop at index 1.
    updateTerminalSessionMac(apduRequests, apduResponses, 1, apduRequests.size());
  }

  /**
   * Executes the APDU requests and updates the associated card commands.
   *
   * @param cardCommands The card commands.
   * @param apduRequests The APDU requests.
   * @param fromIndex From index (inclusive).
   * @param toIndex To index (exclusive).
   * @param channelControl The channel control.
   */
  private void executeCardCommands(
      List<CardCommand> cardCommands,
      List<ApduRequestSpi> apduRequests,
      int fromIndex,
      int toIndex,
      ChannelControl channelControl) {

    if (isEncryptionActive) {
      for (int i = fromIndex; i < toIndex; i++) {
        boolean isManageSecureSessionCommand =
            cardCommands.get(i).getCommandRef() == CardCommandRef.MANAGE_SECURE_SESSION;

        // Encrypt APDU
        ApduRequestSpi apduRequest = apduRequests.get(i);
        if (!isManageSecureSessionCommand) {
          try {
            byte[] encryptedApdu =
                symmetricCryptoTransactionManagerSpi.updateTerminalSessionMac(
                    apduRequest.getApdu());
            System.arraycopy(encryptedApdu, 0, apduRequest.getApdu(), 0, encryptedApdu.length);
          } catch (SymmetricCryptoException e) {
            throw (RuntimeException) e.getCause();
          } catch (SymmetricCryptoIOException e) {
            throw (RuntimeException) e.getCause();
          }
        }

        // Wrap the list of C-APDUs into a card request
        CardRequestSpi cardRequest =
            new CardRequestAdapter(Collections.singletonList(apduRequest), true);

        // Transmit the commands to the card
        CardResponseApi cardResponse = transmitCardRequest(cardRequest, channelControl);

        // Retrieve the list of R-APDUs
        List<ApduResponseApi> apduResponses =
            cardResponse.getApduResponses(); // NOSONAR cardResponse is not null

        // Decrypt APDU
        ApduResponseApi apduResponse = apduResponses.get(0);
        if (!isManageSecureSessionCommand) {
          try {
            byte[] decryptedApdu =
                symmetricCryptoTransactionManagerSpi.updateTerminalSessionMac(
                    apduResponse.getApdu());
            System.arraycopy(decryptedApdu, 0, apduResponse.getApdu(), 0, decryptedApdu.length);
          } catch (SymmetricCryptoException e) {
            throw (RuntimeException) e.getCause();
          } catch (SymmetricCryptoIOException e) {
            throw (RuntimeException) e.getCause();
          }
        }

        try {
          parseApduResponse(cardCommands.get(i), apduResponse);
        } catch (CardCommandException e) {
          throw new UnexpectedCommandStatusException(
              MSG_CARD_COMMAND_ERROR
                  + "while processing response to card command: "
                  + e.getCommandRef()
                  + getTransactionAuditDataAsString(),
              e);
        } catch (InconsistentDataException e) {
          throw new InconsistentDataException(e.getMessage() + getTransactionAuditDataAsString());
        }
      }
    } else {
      cardCommands = cardCommands.subList(fromIndex, toIndex);
      apduRequests = apduRequests.subList(fromIndex, toIndex);

      if (apduRequests.isEmpty()) {
        return;
      }

      // Wrap the list of C-APDUs into a card request
      CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, true);

      // Transmit the commands to the card
      CardResponseApi cardResponse = transmitCardRequest(cardRequest, channelControl);

      // Retrieve the list of R-APDUs
      List<ApduResponseApi> apduResponses =
          cardResponse.getApduResponses(); // NOSONAR cardResponse is not null

      try {
        parseApduResponses(cardCommands, apduResponses);
      } catch (CardCommandException e) {
        throw new UnexpectedCommandStatusException(
            MSG_CARD_COMMAND_ERROR
                + "while processing responses to card commands: "
                + e.getCommandRef()
                + getTransactionAuditDataAsString(),
            e);
      } catch (InconsistentDataException e) {
        throw new InconsistentDataException(e.getMessage() + getTransactionAuditDataAsString());
      }

      // If this method is invoked within a secure session, then add all commands data to the digest
      // computation.
      if (isSecureSessionOpen) {
        updateTerminalSessionMac(
            apduRequests,
            apduResponses,
            0,
            cardCommands.get(cardCommands.size() - 1).getCommandRef()
                    == CardCommandRef.MANAGE_SECURE_SESSION
                ? cardCommands.size() - 1
                : cardCommands.size());
      }
    }
  }

  /**
   * Executes the APDU requests and updates the associated card commands.
   *
   * @param cardCommands The card commands.
   * @param apduRequests The APDU requests.
   * @param fromIndex From index (inclusive).
   * @param toIndex To index (exclusive).
   * @param channelControl The channel control.
   * @param isRatificationMechanismEnabled true if the ratification is closed not ratified and a
   *     ratification command must be sent.
   */
  private void executeCardCommandsForClosing(
      List<CardCommand> cardCommands,
      List<ApduRequestSpi> apduRequests,
      int fromIndex,
      int toIndex,
      ChannelControl channelControl,
      boolean isRatificationMechanismEnabled) {

    if (isEncryptionActive) {
      executeCardCommands(cardCommands, apduRequests, fromIndex, toIndex, ChannelControl.KEEP_OPEN);
      fromIndex = cardCommands.size();
      toIndex = cardCommands.size();
    }

    cardCommands = cardCommands.subList(fromIndex, toIndex);
    apduRequests = apduRequests.subList(fromIndex, toIndex);

    // Build the expected APDU responses of the card commands
    List<ApduResponseApi> expectedApduResponses = buildAnticipatedResponses(cardCommands);

    // Add all commands data to the digest computation.
    updateTerminalSessionMac(apduRequests, expectedApduResponses, 0, apduRequests.size());

    // All SAM digest operations will now run at once.
    // Get Terminal Signature from the latest response.
    byte[] terminalSessionMac;
    try {
      terminalSessionMac = symmetricCryptoTransactionManagerSpi.finalizeTerminalSessionMac();
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }

    // Build the last "Close Secure Session" card command.
    CmdCardCloseSecureSession cmdCardCloseSecureSession =
        new CmdCardCloseSecureSession(card, !isRatificationMechanismEnabled, terminalSessionMac);

    apduRequests.add(cmdCardCloseSecureSession.getApduRequest());

    // Add the card Ratification command if any
    boolean isRatificationCommandAdded;
    if (isRatificationMechanismEnabled && ((CardReader) cardReader).isContactless()) {
      // CL-RAT-CMD.1
      // CL-RAT-DELAY.1
      // CL-RAT-NXTCLOSE.1
      apduRequests.add(CmdCardRatificationBuilder.getApduRequest(card.getCardClass()));
      isRatificationCommandAdded = true;
    } else {
      isRatificationCommandAdded = false;
    }

    // Transfer card commands
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, true);

    // Transmit the commands to the card
    CardResponseApi cardResponse;
    try {
      cardResponse = transmitCardRequest(cardRequest, channelControl);
    } catch (CardIOException e) {
      AbstractApduException cause = (AbstractApduException) e.getCause();
      cardResponse = cause.getCardResponse();
      // The current exception may have been caused by a communication issue with the card
      // during the ratification command.
      // In this case, we do not stop the process and consider the Secure Session close. We'll
      // check the signature.
      // We should have one response less than requests.
      if (!isRatificationCommandAdded
          || cardResponse == null
          || cardResponse.getApduResponses().size() != apduRequests.size() - 1) {
        throw e;
      }
    }

    // Retrieve the list of R-APDUs
    // We copy the list because it is not mutable, and we plan to remove some elements.
    List<ApduResponseApi> apduResponses =
        new ArrayList<ApduResponseApi>(
            cardResponse.getApduResponses()); // NOSONAR cardResponse is not null

    // Remove response of ratification command if present.
    if (isRatificationCommandAdded && apduResponses.size() == cardCommands.size() + 2) {
      apduResponses.remove(apduResponses.size() - 1);
    }

    // Retrieve response of "Close Secure Session" command if present.
    ApduResponseApi closeSecureSessionApduResponse = null;
    if (apduResponses.size() == cardCommands.size() + 1) {
      closeSecureSessionApduResponse = apduResponses.remove(apduResponses.size() - 1);
    }

    // Check the commands executed before closing the secure session (only responses to these
    // commands will be taken into account)
    try {
      parseApduResponses(cardCommands, apduResponses);
    } catch (CardCommandException e) {
      throw new UnexpectedCommandStatusException(
          MSG_CARD_COMMAND_ERROR
              + "while processing of responses preceding the close of the session: "
              + e.getCommandRef()
              + getTransactionAuditDataAsString(),
          e);
    } catch (InconsistentDataException e) {
      throw new InconsistentDataException(e.getMessage() + getTransactionAuditDataAsString());
    }

    isSecureSessionOpen = false;
    _isSecureSessionOpen = false;

    // Check the card's response to Close Secure Session
    try {
      cmdCardCloseSecureSession.setApduResponseAndCheckStatus(closeSecureSessionApduResponse);
    } catch (CardSecurityDataException e) {
      throw new UnexpectedCommandStatusException(
          "Invalid card session" + getTransactionAuditDataAsString(), e);
    } catch (CardCommandException e) {
      throw new UnexpectedCommandStatusException(
          MSG_CARD_COMMAND_ERROR
              + "while processing the response to close session: "
              + e.getCommandRef()
              + getTransactionAuditDataAsString(),
          e);
    }

    // Check the card signature
    // CL-CSS-MACVERIF.1
    try {
      if (!symmetricCryptoTransactionManagerSpi.isCardSessionMacValid(
          cmdCardCloseSecureSession.getSignatureLo())) {
        throw new InvalidCardSignatureException(MSG_INVALID_CARD_SESSION_MAC);
      }
    } catch (SymmetricCryptoIOException e) {
      throw new CardSignatureNotVerifiableException(MSG_CARD_SESSION_MAC_NOT_VERIFIABLE, e);
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    }
    // If necessary, we check the status of the SV after the session has been successfully
    // closed.
    // CL-SV-POSTPON.1
    if (isSvOperationCompleteOneTime()) {
      try {
        if (!symmetricCryptoTransactionManagerSpi.isCardSvMacValid(
            cmdCardCloseSecureSession.getPostponedData().get(svPostponedDataIndex))) {
          throw new InvalidCardSignatureException(MSG_INVALID_CARD_SESSION_MAC);
        }
      } catch (SymmetricCryptoIOException e) {
        throw new CardSignatureNotVerifiableException(MSG_CARD_SV_MAC_NOT_VERIFIABLE, e);
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      }
    }
  }

  /**
   * Parses a single APDU response
   *
   * @param command The associate command.
   * @param apduResponse The response.
   * @throws CardCommandException If a response from the card was unexpected.
   * @throws InconsistentDataException If the number of commands/responses does not match.
   */
  private void parseApduResponse(CardCommand command, ApduResponseApi apduResponse)
      throws CardCommandException {
    parseApduResponses(Collections.singletonList(command), Collections.singletonList(apduResponse));
  }

  /**
   * Parses the APDU responses and updates the Calypso card image.
   *
   * @param commands The list of commands that get the responses.
   * @param apduResponses The APDU responses returned by the card to all commands.
   * @throws CardCommandException If a response from the card was unexpected.
   * @throws InconsistentDataException If the number of commands/responses does not match.
   */
  private void parseApduResponses(List<CardCommand> commands, List<ApduResponseApi> apduResponses)
      throws CardCommandException {

    // If there are more responses than requests, then we are unable to fill the card image. In this
    // case we stop processing immediately because it may be a case of fraud, and we throw a
    // desynchronized exception.
    if (apduResponses.size() > commands.size()) {
      throw new InconsistentDataException(
          MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_NB_COMMANDS
              + commands.size()
              + MSG_NB_RESPONSES
              + apduResponses.size());
    }

    // We go through all the responses (and not the requests) because there may be fewer in the
    // case of an error that occurred in strict mode. In this case the last response will raise an
    // exception.
    for (int i = 0; i < apduResponses.size(); i++) {
      try {
        commands.get(i).setApduResponseAndCheckStatus(apduResponses.get(i));
      } catch (CardCommandException e) {
        CardCommandRef commandRef = commands.get(i).getCommandRef();
        if (e instanceof CardDataAccessException) {
          if (commandRef == CardCommandRef.READ_RECORDS
              || commandRef == CardCommandRef.READ_RECORD_MULTIPLE
              || commandRef == CardCommandRef.SEARCH_RECORD_MULTIPLE
              || commandRef == CardCommandRef.READ_BINARY) {
            checkResponseStatusForStrictAndBestEffortMode(commands.get(i), e);
          } else if (commandRef == CardCommandRef.SELECT_FILE) {
            throw new SelectFileException("File not found", e);
          }
        } else {
          throw new UnexpectedCommandStatusException(
              MSG_CARD_COMMAND_ERROR
                  + "while processing responses to card commands: "
                  + commandRef
                  + getTransactionAuditDataAsString(),
              e);
        }
      }
    }

    // Finally, if no error has occurred and there are fewer responses than requests, then we
    // throw a desynchronized exception.
    if (apduResponses.size() < commands.size()) {
      throw new InconsistentDataException(
          MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_NB_COMMANDS
              + commands.size()
              + MSG_NB_RESPONSES
              + apduResponses.size());
    }
  }

  /**
   * Sets the response to the command and check the status for strict and best effort mode.
   *
   * @param command The command.
   * @throws CardCommandException If needed.
   */
  private void checkResponseStatusForStrictAndBestEffortMode(
      CardCommand command, CardCommandException e) throws CardCommandException {
    if (isSecureSessionOpen) {
      throw e;
    } else {
      // best effort mode, do not throw exception for "file not found" and "record not found"
      // errors.
      if (command.getApduResponse().getStatusWord() != 0x6A82
          && command.getApduResponse().getStatusWord() != 0x6A83) {
        throw e;
      }
    }
  }

  /**
   * Close the Secure Session.
   *
   * <ul>
   *   <li>The SAM cache is completed with the Digest Update commands related to the new card
   *       commands to be sent and their anticipated responses. A Digest Close command is also added
   *       to the SAM command cache.
   *   <li>On the SAM session reader side, a CardRequest is transmitted with SAM commands from the
   *       command cache. The SAM command cache is emptied.
   *   <li>The SAM certificate is retrieved from the Digest Close response. The terminal signature
   *       is identified.
   *   <li>Then, on the card reader, a CardRequest is transmitted with a {@link ChannelControl} set
   *       to CLOSE_AFTER or KEEP_OPEN depending on whether or not prepareReleaseCardChannel was
   *       invoked, and apduRequests including the new card commands to send in the session, a Close
   *       Session command (defined with the SAM certificate), and optionally a ratificationCommand.
   *       <ul>
   *         <li>The management of ratification is conditioned by the mode of communication.
   *             <ul>
   *               <li>If the communication mode is CONTACTLESS, a specific ratification command is
   *                   sent after the Close Session command. No ratification is requested in the
   *                   Close Session command.
   *               <li>If the communication mode is CONTACTS, no ratification command is sent after
   *                   the Close Session command. Ratification is requested in the Close Session
   *                   command.
   *             </ul>
   *         <li>Otherwise, the card Close Secure Session command is defined to directly set the
   *             card as ratified.
   *       </ul>
   *   <li>The card responses of the cardModificationCommands are compared with the
   *       cardAnticipatedResponses. The card signature is identified from the card Close Session
   *       response.
   *   <li>The card certificate is recovered from the Close Session response. The card signature is
   *       identified.
   *   <li>Finally, on the SAM session reader, a Digest Authenticate is automatically operated in
   *       order to verify the card signature.
   *   <li>Returns the corresponding card CardResponse.
   * </ul>
   *
   * The method is marked as deprecated because the advanced variant defined below must be used at
   * the application level.
   *
   * @param cardCommands The list of last card commands to transmit inside the secure session.
   * @param isRatificationMechanismEnabled true if the ratification is closed not ratified and a
   *     ratification command must be sent.
   * @param channelControl indicates if the card channel of the card reader must be closed after the
   *     last command.
   */
  private void processAtomicClosing(
      List<CardCommand> cardCommands,
      boolean isRatificationMechanismEnabled,
      ChannelControl channelControl) {

    if (cardCommands == null) {
      cardCommands = new ArrayList<CardCommand>(0);
    }

    // Get the list of C-APDU to transmit
    List<ApduRequestSpi> apduRequests = getApduRequests(cardCommands);

    if (containsNoManageSecureSessionCommand(apduRequests.size())) {
      // Standard process for all commands.
      executeCardCommandsForClosing(
          cardCommands,
          apduRequests,
          0,
          apduRequests.size(),
          channelControl,
          isRatificationMechanismEnabled);
    } else {
      // There is at least one MSS command to execute.
      // We execute all the commands until the last MSS command (MSS included).
      int nextIndex = executeCardCommandsWithManageSecureSession(cardCommands, apduRequests, 0, 0);
      // Then we perform the standard process for any remaining commands.
      executeCardCommandsForClosing(
          cardCommands,
          apduRequests,
          nextIndex,
          apduRequests.size(),
          channelControl,
          isRatificationMechanismEnabled);
    }
  }

  /**
   * Builds the anticipated expected responses to the commands sent in processClosing.<br>
   * These commands are supposed to be "modifying commands" only.
   *
   * @param cardCommands the list of card commands sent.
   * @return An empty list if there is no command.
   * @throws IllegalStateException if the anticipation process failed
   */
  private List<ApduResponseApi> buildAnticipatedResponses(List<CardCommand> cardCommands) {
    List<ApduResponseApi> apduResponses = new ArrayList<ApduResponseApi>();
    if (cardCommands != null) {
      for (CardCommand command : cardCommands) {
        switch (command.getCommandRef()) {
          case INCREASE:
          case DECREASE:
            if (card.isCounterValuePostponed()) {
              apduResponses.add(RESPONSE_OK_POSTPONED);
              nbPostponedData++;
            } else {
              apduResponses.add(
                  new ApduResponseAdapter(
                      ((CmdCardIncreaseOrDecrease) command).buildAnticipatedResponse()));
            }
            break;
          case INCREASE_MULTIPLE:
          case DECREASE_MULTIPLE:
            apduResponses.add(
                new ApduResponseAdapter(
                    ((CmdCardIncreaseOrDecreaseMultiple) command).buildAnticipatedResponse()));
            break;
          case SV_RELOAD:
          case SV_DEBIT:
          case SV_UNDEBIT:
            apduResponses.add(RESPONSE_OK_POSTPONED);
            svPostponedDataIndex = nbPostponedData;
            nbPostponedData++;
            break;
          default: // Append/Update/Write Record: response = 9000
            apduResponses.add(RESPONSE_OK);
        }
      }
    }
    return apduResponses;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Deprecated
  @Override
  public CardTransactionManager processOpening(WriteAccessLevel writeAccessLevel) {
    checkApiLevelCompliance(false);
    try {
      if (symmetricCryptoSecuritySetting == null) {
        throw new IllegalStateException("Security settings not specified");
      }
      if (isSecureSessionOpen) {
        throw new IllegalStateException("Secure session already opened");
      }
      isEncryptionActive = false;
      prepareManageSecureSessionIfNeeded(true);

      // CL-KEY-INDEXPO.1
      this.writeAccessLevel = writeAccessLevel;

      // Create a sublist of AbstractCardCommand to be sent atomically
      List<CardCommand> cardAtomicCommands = new ArrayList<CardCommand>();

      for (CardCommand command : cardCommands) {
        // Check if the command is a modifying command.
        if (command.isSessionBufferUsed()) {
          modificationsCounter -= computeCommandSessionBufferSize(command);
          if (modificationsCounter < 0) {
            checkMultipleSessionEnabled(command);
            // Process an intermediate secure session with the current commands.
            processAtomicOpening(cardAtomicCommands);
            processAtomicClosing(null, false, ChannelControl.KEEP_OPEN);
            // Reset and update the buffer counter.
            modificationsCounter = card.getModificationsCounter();
            modificationsCounter -= computeCommandSessionBufferSize(command);
            // Clear the list.
            resetCommandList(cardAtomicCommands);
          }
        }
        cardAtomicCommands.add(command);
      }

      processAtomicOpening(cardAtomicCommands);

      // sets the flag indicating that the commands have been executed
      notifyCommandsProcessed();

      // CL-SV-1PCSS.1
      _isSvOperationInSecureSession = false;

      return this;

    } catch (RuntimeException e) {
      abortSecureSessionSilently();
      throw e;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public CardTransactionManager prepareOpenSecureSession(WriteAccessLevel writeAccessLevel) {
    try {
      checkApiLevelCompliance(true);
      Assert.getInstance().notNull(writeAccessLevel, "writeAccessLevel");
      checkSymmetricCryptoTransactionManager();
      checkNoSecureSession();
      if (card.getPreOpenWriteAccessLevel() != null
          && card.getPreOpenWriteAccessLevel() != writeAccessLevel) {
        logger.warn(
            "Pre-open mode cancelled because writeAccessLevel '{}' mismatches the writeAccessLevel used for"
                + " pre-open mode '{}'",
            writeAccessLevel,
            card.getPreOpenWriteAccessLevel());
        disablePreOpenMode();
      }
      _cardCommands.add(
          new CmdCardOpenSecureSession(
              _transactionContext,
              getCommandContext(),
              symmetricCryptoSecuritySetting,
              writeAccessLevel,
              isExtendedMode));
      _writeAccessLevel = writeAccessLevel; // CL-KEY-INDEXPO.1
      _isSecureSessionOpen = true;
      _isEncryptionActive = false;
      _modificationsCounter = card.getModificationsCounter();
      _nbPostponedData = 0;
      _svPostponedDataIndex = -1;
      _isSvOperationInSecureSession = false;
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * Throws an exception if the multiple session is not enabled.
   *
   * @param command The command.
   * @throws SessionBufferOverflowException If the multiple session is not allowed.
   */
  private void checkMultipleSessionEnabled(CardCommand command) {
    // CL-CSS-REQUEST.1
    // CL-CSS-SMEXCEED.1
    // CL-CSS-INFOCSS.1
    if (!symmetricCryptoSecuritySetting.isMultipleSessionEnabled()) {
      throw new SessionBufferOverflowException(
          "ATOMIC mode error! This command would overflow the card modifications buffer: "
              + command.getName()
              + getTransactionAuditDataAsString());
    }
  }

  /**
   * Process all prepared card commands (outside a Secure Session).
   *
   * <p>Note: commands prepared prior to the invocation of this method shall not require the use of
   * a SAM.
   */
  private void processCommandsOutsideSession() {

    // card commands sent outside a Secure Session. No modifications buffer limitation.
    processAtomicCardCommands(cardCommands, channelControl);

    // sets the flag indicating that the commands have been executed
    notifyCommandsProcessed();

    // If an SV transaction was performed, we check the signature returned by the card here
    if (isSvOperationCompleteOneTime()) {
      try {
        if (!symmetricCryptoTransactionManagerSpi.isCardSvMacValid(
            card.getSvOperationSignature())) {
          throw new InvalidCardSignatureException(MSG_INVALID_CARD_SESSION_MAC);
        }
      } catch (SymmetricCryptoIOException e) {
        throw new CardSignatureNotVerifiableException(MSG_CARD_SV_MAC_NOT_VERIFIABLE, e);
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      }
    } else {
      // Execute all prepared SAM commands.
      processSamPreparedCommands();
    }
  }

  /**
   * Process all prepared card commands in a Secure Session.
   *
   * <p>The multiple session mode is handled according to the session settings.
   */
  private void processCommandsInsideSession() {
    try {
      // A session is open, we have to care about the card modifications buffer
      List<CardCommand> cardAtomicCommands = new ArrayList<CardCommand>();
      boolean isAtLeastOneReadCommand = false;

      for (CardCommand command : cardCommands) {
        // Check if the command is a modifying command.
        if (command.isSessionBufferUsed()) {
          modificationsCounter -= computeCommandSessionBufferSize(command);
          if (modificationsCounter < 0) {
            checkMultipleSessionEnabled(command);
            // Close the current secure session with the current commands and open a new one.
            if (isAtLeastOneReadCommand) {
              processAtomicCardCommands(cardAtomicCommands, ChannelControl.KEEP_OPEN);
              resetCommandList(cardAtomicCommands);
            }
            processAtomicClosing(cardAtomicCommands, false, ChannelControl.KEEP_OPEN);
            processAtomicOpening(null);
            // Reset and update the buffer counter.
            modificationsCounter = card.getModificationsCounter();
            modificationsCounter -= computeCommandSessionBufferSize(command);
            isAtLeastOneReadCommand = false;
            // Clear the list.
            resetCommandList(cardAtomicCommands);
          }
        } else {
          isAtLeastOneReadCommand = true;
        }
        cardAtomicCommands.add(command);
      }

      processAtomicCardCommands(cardAtomicCommands, ChannelControl.KEEP_OPEN);
      // sets the flag indicating that the commands have been executed
      notifyCommandsProcessed();

      processSamPreparedCommands();

    } catch (RuntimeException e) {
      abortSecureSessionSilently();
      throw e;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   * @deprecated
   */
  @Deprecated
  @Override
  public CardSecuritySetting getSecuritySetting() {
    return securitySetting;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public CardTransactionManager prepareComputeSignature(CommonSignatureComputationData data) {
    try {
      checkSymmetricCryptoTransactionManager();
      cryptoExtension.prepareComputeSignature(data);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public CardTransactionManager prepareVerifySignature(CommonSignatureVerificationData data) {
    try {
      checkSymmetricCryptoTransactionManager();
      cryptoExtension.prepareVerifySignature(data);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   * @deprecated
   */
  @Deprecated
  @Override
  public CardTransactionManager processCommands() {
    checkApiLevelCompliance(false);
    finalizeSvCommandIfNeeded();
    prepareManageSecureSessionIfNeeded(isSecureSessionOpen);
    if (isSecureSessionOpen) {
      processCommandsInsideSession();
    } else {
      processCommandsOutsideSession();
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * <p>For each prepared command, if a pre-processing is required, then we try to execute the
   * post-processing of each of the previous commands in anticipation. If at least one
   * post-processing cannot be anticipated, then we execute the block of previous commands first.
   *
   * @since 2.3.2
   */
  @Override
  public CardTransactionManager processCommands(boolean closePhysicalChannel) {
    checkApiLevelCompliance(true);
    if (_cardCommands.isEmpty()) {
      return this;
    }
    try {
      List<CardCommand> cardRequestCommands = new ArrayList<CardCommand>();
      for (CardCommand command : _cardCommands) {
        if (command.isCryptoServiceRequiredToFinalizeRequest()) {
          if (!synchronizeCryptoServiceBeforeCardProcessing(cardRequestCommands)) {
            executeCardCommands(cardRequestCommands, false);
            cardRequestCommands.clear();
          }
        }
        command.finalizeRequest();
        cardRequestCommands.add(command);
      }
      executeCardCommands(cardRequestCommands, closePhysicalChannel);
      processSamPreparedCommands();
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      _cardCommands.clear();
      if (isExtendedMode && !card.isExtendedModeSupported()) {
        isExtendedMode = false;
      }
    }
    return this;
  }

  /**
   * Resets the transaction fields and try to cancel silently the current secure session if opened,
   * without raising any exception.
   */
  private void resetTransaction() {
    _isSecureSessionOpen = false;
    _isEncryptionActive = false;
    _modificationsCounter = card.getModificationsCounter();
    _nbPostponedData = 0;
    _svPostponedDataIndex = -1;
    _isSvGet = false;
    _svOperation = null;
    _isSvOperationInSecureSession = false;
    disablePreOpenMode();
    _cardCommands.clear();
    if (_transactionContext.isSecureSessionOpen()) {
      try {
        CmdCardCloseSecureSession cancelSecureSessionCommand =
            new CmdCardCloseSecureSession(_transactionContext, getCommandContext());
        cancelSecureSessionCommand.finalizeRequest();
        List<CardCommand> commands = new ArrayList<CardCommand>(1);
        commands.add(cancelSecureSessionCommand);
        executeCardCommands(commands, false);
      } catch (RuntimeException e) {
        logger.debug("Secure session abortion error: {}", e.getMessage());
      } finally {
        card.restoreFiles();
        _transactionContext.setSecureSessionOpen(false);
      }
    }
  }

  /**
   * Attempts to synchronize the crypto service before executing the finalized command on the card
   * and returns "true" on successful execution.
   *
   * @param commands The commands.
   * @return "false" if the crypto service could not be synchronized before transmitting the
   *     commands to the card.
   */
  private boolean synchronizeCryptoServiceBeforeCardProcessing(List<CardCommand> commands) {
    for (CardCommand command : commands) {
      if (!command.synchronizeCryptoServiceBeforeCardProcessing()) {
        return false;
      }
    }
    return true;
  }

  /**
   * Executes the provided commands.
   *
   * @param commands The commands.
   * @param closePhysicalChannel "true" if the physical channel must be closed after the operation.
   */
  private void executeCardCommands(List<CardCommand> commands, boolean closePhysicalChannel) {

    // Retrieve the list of C-APDUs
    List<ApduRequestSpi> apduRequests = getApduRequests(commands);

    // Wrap the list of C-APDUs into a card request
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, true);

    // Transmit the commands to the card
    CardResponseApi cardResponse =
        transmitCardRequest(
            cardRequest,
            closePhysicalChannel ? ChannelControl.CLOSE_AFTER : ChannelControl.KEEP_OPEN);

    // Retrieve the list of R-APDUs
    List<ApduResponseApi> apduResponses = cardResponse.getApduResponses();

    // If there are more responses than requests, then we are unable to fill the card image. In this
    // case we stop processing immediately because it may be a case of fraud, and we throw a
    // desynchronized exception.
    if (apduResponses.size() > commands.size()) {
      throw new InconsistentDataException(
          MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_NB_COMMANDS
              + commands.size()
              + MSG_NB_RESPONSES
              + apduResponses.size()
              + getTransactionAuditDataAsString());
    }

    // We go through all the responses (and not the requests) because there may be fewer in the
    // case of an error that occurred in strict mode. In this case the last response will raise an
    // exception.
    for (int i = 0; i < apduResponses.size(); i++) {
      CardCommand command = commands.get(i);
      try {
        command.parseResponse(apduResponses.get(i));
      } catch (CardCommandException e) {
        throw new UnexpectedCommandStatusException(
            MSG_CARD_COMMAND_ERROR
                + "while processing responses to card commands: "
                + command.getCommandRef()
                + getTransactionAuditDataAsString(),
            e);
      }
    }

    // Finally, if no error has occurred and there are fewer responses than requests, then we
    // throw a desynchronized exception.
    if (apduResponses.size() < commands.size()) {
      throw new InconsistentDataException(
          MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_NB_COMMANDS
              + commands.size()
              + MSG_NB_RESPONSES
              + apduResponses.size()
              + getTransactionAuditDataAsString());
    }
  }

  /** Process any prepared SAM commands if control SAM is set. */
  private void processSamPreparedCommands() {
    if (symmetricCryptoTransactionManagerSpi != null) {
      try {
        symmetricCryptoTransactionManagerSpi.synchronize();
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      } catch (SymmetricCryptoIOException e) {
        throw (RuntimeException) e.getCause();
      }
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated Use {@link #processCommands()} instead.
   */
  @Override
  @Deprecated
  public CardTransactionManager processCardCommands() {
    return processCommands();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Deprecated
  @Override
  public CardTransactionManager processClosing() {
    checkApiLevelCompliance(false);
    try {
      if (!isSecureSessionOpen) {
        throw new IllegalStateException("Secure session not opened");
      }
      finalizeSvCommandIfNeeded();
      prepareManageSecureSessionIfNeeded(true);
      isEncryptionRequested = false;

      List<CardCommand> cardAtomicCommands = new ArrayList<CardCommand>();
      boolean isAtLeastOneReadCommand = false;

      for (CardCommand command : cardCommands) {
        // Check if the command is a modifying command.
        if (command.isSessionBufferUsed()) {
          modificationsCounter -= computeCommandSessionBufferSize(command);
          if (modificationsCounter < 0) {
            checkMultipleSessionEnabled(command);
            // Close the current secure session with the current commands and open a new one.
            if (isAtLeastOneReadCommand) {
              processAtomicCardCommands(cardAtomicCommands, ChannelControl.KEEP_OPEN);
              resetCommandList(cardAtomicCommands);
            }
            processAtomicClosing(cardAtomicCommands, false, ChannelControl.KEEP_OPEN);
            processAtomicOpening(null);
            // Reset and update the buffer counter.
            modificationsCounter = card.getModificationsCounter();
            modificationsCounter -= computeCommandSessionBufferSize(command);
            isAtLeastOneReadCommand = false;
            // Clear the list.
            resetCommandList(cardAtomicCommands);
          }
        } else {
          isAtLeastOneReadCommand = true;
        }
        cardAtomicCommands.add(command);
      }

      if (isAtLeastOneReadCommand) {
        processAtomicCardCommands(cardAtomicCommands, ChannelControl.KEEP_OPEN);
        resetCommandList(cardAtomicCommands);
      }

      processAtomicClosing(
          cardAtomicCommands,
          symmetricCryptoSecuritySetting.isRatificationMechanismEnabled(),
          channelControl);

      // sets the flag indicating that the commands have been executed
      notifyCommandsProcessed();

      return this;

    } catch (RuntimeException e) {
      abortSecureSessionSilently();
      throw e;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public CardTransactionManager prepareCloseSecureSession() {
    try {
      checkApiLevelCompliance(true);
      checkSecureSession();
      if (symmetricCryptoSecuritySetting.isRatificationMechanismEnabled()
          && ((CardReader) cardReader).isContactless()) {
        // CL-RAT-CMD.1
        // CL-RAT-DELAY.1
        // CL-RAT-NXTCLOSE.1
        _cardCommands.add(
            new CmdCardCloseSecureSession(
                _transactionContext, getCommandContext(), false, _svPostponedDataIndex));
        _cardCommands.add(new CmdCardRatification(_transactionContext, getCommandContext()));
      } else {
        _cardCommands.add(
            new CmdCardCloseSecureSession(
                _transactionContext, getCommandContext(), true, _svPostponedDataIndex));
      }
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      _isSecureSessionOpen = false;
      _isEncryptionActive = false;
      disablePreOpenMode();
    }
    return this;
  }

  /**
   * Checks if a secure session is open.
   *
   * @throws IllegalStateException If no secure session is open.
   */
  private void checkSecureSession() {
    if (!_isSecureSessionOpen) {
      throw new IllegalStateException(SECURE_SESSION_NOT_OPEN);
    }
  }

  /**
   * Checks if no secure session is open.
   *
   * @throws IllegalStateException If a secure session is open.
   */
  private void checkNoSecureSession() {
    if (_isSecureSessionOpen) {
      throw new IllegalStateException(SECURE_SESSION_OPEN);
    }
  }

  /**
   * Clears the input commands list and refreshes the map containing the "Manage Secure Command"
   * command info.<br>
   * Removes all processed entries and update the index off all remaining commands.
   *
   * @param cardAtomicCommands The list to reset
   */
  private void resetCommandList(List<CardCommand> cardAtomicCommands) {
    // Update the indexes of the MSS commands.
    int nbComputedCommands = cardAtomicCommands.size();
    Set<Integer> keysToRemove = new HashSet<Integer>();
    for (Map.Entry<Integer, ManageSecureSessionDto> entry : manageSecureSessionMap.entrySet()) {
      if (entry.getValue().index >= nbComputedCommands) {
        entry.getValue().index -= nbComputedCommands;
      } else {
        keysToRemove.add(entry.getKey());
      }
    }
    // Remove the processed entries.
    for (Integer key : keysToRemove) {
      manageSecureSessionMap.remove(key);
    }
    // Clear the list.
    cardAtomicCommands.clear();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Deprecated
  @Override
  public CardTransactionManager processCancel() {
    checkApiLevelCompliance(false);
    if (isSecureSessionOpen) {
      card.restoreFiles();
    }

    // Build the card Close Session command (in "abort" mode since no signature is provided).
    CmdCardCloseSecureSession cmdCardCloseSecureSession = new CmdCardCloseSecureSession(card);

    // card ApduRequestAdapter List to hold Close Secure Session command
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    apduRequests.add(cmdCardCloseSecureSession.getApduRequest());

    // Transfer card commands
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, false);
    CardResponseApi cardResponse = transmitCardRequest(cardRequest, channelControl);
    try {
      cmdCardCloseSecureSession.setApduResponseAndCheckStatus(
          cardResponse.getApduResponses().get(0)); // NOSONAR cardResponse is not null
    } catch (CardCommandException e) {
      throw new UnexpectedCommandStatusException(
          MSG_CARD_COMMAND_ERROR
              + "while processing the response to close session: "
              + e.getCommandRef()
              + getTransactionAuditDataAsString(),
          e);
    }

    // sets the flag indicating that the commands have been executed
    notifyCommandsProcessed();

    // session is now considered closed regardless the previous state or the result of the abort
    // session command sent to the card.
    isSecureSessionOpen = false;
    _isSecureSessionOpen = false;

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public CardTransactionManager prepareCancelSecureSession() {
    try {
      checkApiLevelCompliance(true);
      _cardCommands.add(new CmdCardCloseSecureSession(_transactionContext, getCommandContext()));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      _isSecureSessionOpen = false;
      _isEncryptionActive = false;
      disablePreOpenMode();
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.4
   */
  @Override
  public void initSamContextForNextTransaction() {
    checkApiLevelCompliance(true);
    checkSymmetricCryptoTransactionManager();
    if (!_cardCommands.isEmpty()) {
      throw new IllegalStateException("Unprocessed card commands are pending");
    }
    try {
      symmetricCryptoTransactionManagerSpi.preInitTerminalSecureSessionContext();
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Deprecated
  @Override
  public CardTransactionManager processVerifyPin(byte[] pin) {
    checkApiLevelCompliance(false);
    try {
      Assert.getInstance()
          .notNull(pin, "pin")
          .isEqual(pin.length, CalypsoCardConstant.PIN_LENGTH, "PIN length");

      if (!card.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
      }

      if (!cardCommands.isEmpty()) {
        throw new IllegalStateException(
            "No commands should have been prepared prior to a PIN submission.");
      }

      finalizeSvCommandIfNeeded();
      prepareManageSecureSessionIfNeeded(isSecureSessionOpen);

      // CL-PIN-PENCRYPT.1
      if (symmetricCryptoSecuritySetting != null
          && !symmetricCryptoSecuritySetting.isPinPlainTransmissionEnabled()) {

        // CL-PIN-GETCHAL.1
        cardCommands.add(new CmdCardGetChallenge(card));

        // transmit and receive data with the card
        processAtomicCardCommands(cardCommands, ChannelControl.KEEP_OPEN);

        // sets the flag indicating that the commands have been executed
        notifyCommandsProcessed();

        // Get the encrypted PIN with the help of the symmetric key crypto service
        byte[] cipheredPin = cipherPinForPresentation(pin);

        cardCommands.add(new CmdCardVerifyPin(card, true, cipheredPin));
      } else {
        cardCommands.add(new CmdCardVerifyPin(card, false, pin));
      }

      // transmit and receive data with the card
      processAtomicCardCommands(cardCommands, channelControl);
      // sets the flag indicating that the commands have been executed
      notifyCommandsProcessed();

      processSamPreparedCommands();

      return this;

    } catch (RuntimeException e) {
      abortSecureSessionSilently();
      throw e;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public CardTransactionManager prepareVerifyPin(byte[] pin) {
    try {
      checkApiLevelCompliance(true);
      Assert.getInstance()
          .notNull(pin, "pin")
          .isEqual(pin.length, CalypsoCardConstant.PIN_LENGTH, "PIN length");
      if (!card.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
      }
      if (symmetricCryptoSecuritySetting == null
          || symmetricCryptoSecuritySetting.isPinPlainTransmissionEnabled()) {
        _cardCommands.add(new CmdCardVerifyPin(_transactionContext, getCommandContext(), pin));
      } else {
        // CL-PIN-PENCRYPT.1
        // CL-PIN-GETCHAL.1
        _cardCommands.add(new CmdCardGetChallenge(_transactionContext, getCommandContext()));
        _cardCommands.add(
            new CmdCardVerifyPin(
                _transactionContext,
                getCommandContext(),
                pin,
                symmetricCryptoSecuritySetting.getPinVerificationCipheringKif(),
                symmetricCryptoSecuritySetting.getPinVerificationCipheringKvc()));
      }
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * Returns the ciphered PIN for presentation.
   *
   * @param pin The plain-text PIN to be ciphered.
   * @return A not empty byte-array.
   */
  private byte[] cipherPinForPresentation(byte[] pin) {
    try {
      return symmetricCryptoTransactionManagerSpi.cipherPinForPresentation(
          card.getChallenge(),
          pin,
          symmetricCryptoSecuritySetting.getPinVerificationCipheringKif(),
          symmetricCryptoSecuritySetting.getPinVerificationCipheringKvc());
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Deprecated
  @Override
  public CardTransactionManager processChangePin(byte[] newPin) {
    checkApiLevelCompliance(false);
    try {
      Assert.getInstance()
          .notNull(newPin, "newPin")
          .isEqual(newPin.length, CalypsoCardConstant.PIN_LENGTH, "PIN length");

      if (!card.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
      }

      if (isSecureSessionOpen) {
        throw new IllegalStateException("'Change PIN' not allowed when a secure session is open.");
      }

      finalizeSvCommandIfNeeded();
      prepareManageSecureSessionIfNeeded(false);

      // CL-PIN-MENCRYPT.1
      if (symmetricCryptoSecuritySetting.isPinPlainTransmissionEnabled()) {
        // transmission in plain mode
        if (card.getPinAttemptRemaining() >= 0) {
          cardCommands.add(new CmdCardChangePin(card, newPin));
        }
      } else {
        // CL-PIN-GETCHAL.1
        cardCommands.add(new CmdCardGetChallenge(card));

        // transmit and receive data with the card
        processAtomicCardCommands(cardCommands, ChannelControl.KEEP_OPEN);

        // sets the flag indicating that the commands have been executed
        notifyCommandsProcessed();

        // Get the encrypted PIN with the help of the SAM
        byte[] currentPin = new byte[4]; // all zeros as required
        // Get the encrypted PIN with the help of the symmetric key crypto service
        byte[] newPinData = cipherPinForModification(newPin, currentPin);

        cardCommands.add(new CmdCardChangePin(card, newPinData));
      }

      // transmit and receive data with the card
      processAtomicCardCommands(cardCommands, channelControl);
      // sets the flag indicating that the commands have been executed
      notifyCommandsProcessed();

      processSamPreparedCommands();

      return this;

    } catch (RuntimeException e) {
      abortSecureSessionSilently();
      throw e;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public CardTransactionManager prepareChangePin(byte[] newPin) {
    try {
      checkApiLevelCompliance(true);
      Assert.getInstance()
          .notNull(newPin, "newPin")
          .isEqual(newPin.length, CalypsoCardConstant.PIN_LENGTH, "PIN length");
      if (!card.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
      }
      checkNoSecureSession();
      // CL-PIN-MENCRYPT.1
      if (symmetricCryptoSecuritySetting == null
          || symmetricCryptoSecuritySetting.isPinPlainTransmissionEnabled()) {
        _cardCommands.add(new CmdCardChangePin(_transactionContext, getCommandContext(), newPin));
      } else {
        // CL-PIN-GETCHAL.1
        _cardCommands.add(new CmdCardGetChallenge(_transactionContext, getCommandContext()));
        _cardCommands.add(
            new CmdCardChangePin(
                _transactionContext,
                getCommandContext(),
                newPin,
                symmetricCryptoSecuritySetting.getPinModificationCipheringKif(),
                symmetricCryptoSecuritySetting.getPinModificationCipheringKvc()));
      }
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * Returns the ciphered new PIN for modification.
   *
   * @param newPin The plain-text new PIN.
   * @param currentPin the plain-text current PIN.
   * @return A not empty byte-array.
   */
  private byte[] cipherPinForModification(byte[] newPin, byte[] currentPin) {
    try {
      return symmetricCryptoTransactionManagerSpi.cipherPinForModification(
          card.getChallenge(),
          currentPin,
          newPin,
          symmetricCryptoSecuritySetting.getPinModificationCipheringKif(),
          symmetricCryptoSecuritySetting.getPinModificationCipheringKvc());
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   * @deprecated
   */
  @Deprecated
  @Override
  public CardTransactionManager processChangeKey(
      int keyIndex, byte newKif, byte newKvc, byte issuerKif, byte issuerKvc) {
    checkApiLevelCompliance(false);

    if (card.getProductType() == CalypsoCard.ProductType.BASIC) {
      throw new UnsupportedOperationException(
          "The 'Change Key' command is not available for this card.");
    }

    if (isSecureSessionOpen) {
      throw new IllegalStateException("'Change Key' not allowed when a secure session is open.");
    }

    Assert.getInstance().isInRange(keyIndex, 1, 3, "keyIndex");

    finalizeSvCommandIfNeeded();
    prepareManageSecureSessionIfNeeded(false);

    // CL-KEY-CHANGE.1
    cardCommands.add(new CmdCardGetChallenge(card));

    // transmit and receive data with the card
    processAtomicCardCommands(cardCommands, ChannelControl.KEEP_OPEN);

    // sets the flag indicating that the commands have been executed
    notifyCommandsProcessed();

    // Get the encrypted key with the help of the SAM
    byte[] cipheredKey;
    try {
      cipheredKey =
          symmetricCryptoTransactionManagerSpi.generateCipheredCardKey(
              card.getChallenge(), issuerKif, issuerKvc, newKif, newKvc);
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }

    cardCommands.add(new CmdCardChangeKey(card, (byte) keyIndex, cipheredKey));

    // transmit and receive data with the card
    processAtomicCardCommands(cardCommands, channelControl);

    // sets the flag indicating that the commands have been executed
    notifyCommandsProcessed();

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public CardTransactionManager prepareChangeKey(
      int keyIndex, byte newKif, byte newKvc, byte issuerKif, byte issuerKvc) {
    try {
      checkApiLevelCompliance(true);
      if (card.getProductType() == CalypsoCard.ProductType.BASIC) {
        throw new UnsupportedOperationException("'Change Key' command not available for this card");
      }
      checkNoSecureSession();
      Assert.getInstance().isInRange(keyIndex, 1, 3, "keyIndex");
      // CL-KEY-CHANGE.1
      _cardCommands.add(new CmdCardGetChallenge(_transactionContext, getCommandContext()));
      _cardCommands.add(
          new CmdCardChangeKey(
              _transactionContext,
              getCommandContext(),
              (byte) keyIndex,
              newKif,
              newKvc,
              issuerKif,
              issuerKvc));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * Transmits a card request, processes and converts any exceptions.
   *
   * @param cardRequest The card request to transmit.
   * @param channelControl The channel control.
   * @return The card response.
   */
  private CardResponseApi transmitCardRequest(
      CardRequestSpi cardRequest, ChannelControl channelControl) {
    CardResponseApi cardResponse;
    try {
      cardResponse = cardReader.transmitCardRequest(cardRequest, channelControl);
    } catch (ReaderBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse());
      throw new ReaderIOException(
          MSG_CARD_READER_COMMUNICATION_ERROR
              + MSG_WHILE_TRANSMITTING_COMMANDS
              + getTransactionAuditDataAsString(),
          e);
    } catch (CardBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse());
      throw new CardIOException(
          MSG_CARD_COMMUNICATION_ERROR
              + MSG_WHILE_TRANSMITTING_COMMANDS
              + getTransactionAuditDataAsString(),
          e);
    } catch (UnexpectedStatusWordException e) {
      if (logger.isDebugEnabled()) {
        logger.debug("A card command has failed: {}", e.getMessage());
      }
      cardResponse = e.getCardResponse();
    }
    saveTransactionAuditData(cardRequest, cardResponse);
    return cardResponse;
  }

  /**
   * Finalizes the last SV modifying command using the control SAM if an SV operation is pending.
   */
  private void finalizeSvCommandIfNeeded() {

    if (svLastModifyingCommand == null) {
      return;
    }

    SvCommandSecurityDataApiAdapter svCommandSecurityData = new SvCommandSecurityDataApiAdapter();
    svCommandSecurityData.setSvGetRequest(card.getSvGetHeader());
    svCommandSecurityData.setSvGetResponse(card.getSvGetData());

    if (svLastModifyingCommand.getCommandRef() == CardCommandRef.SV_RELOAD) {

      // SV RELOAD: get the security data from the SAM
      CmdCardSvReload svCommand = (CmdCardSvReload) svLastModifyingCommand;

      svCommandSecurityData.setSvCommandPartialRequest(svCommand.getSvReloadData());

      try {
        symmetricCryptoTransactionManagerSpi.computeSvCommandSecurityData(svCommandSecurityData);
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      } catch (SymmetricCryptoIOException e) {
        throw (RuntimeException) e.getCause();
      }

      // finalize the SV command with the data provided by the SAM
      svCommand.finalizeCommand(svCommandSecurityData);

    } else {

      // SV DEBIT/UNDEBIT: get the security data from the SAM
      CmdCardSvDebitOrUndebit svCommand = (CmdCardSvDebitOrUndebit) svLastModifyingCommand;

      svCommandSecurityData.setSvCommandPartialRequest(svCommand.getSvDebitOrUndebitData());

      try {
        symmetricCryptoTransactionManagerSpi.computeSvCommandSecurityData(svCommandSecurityData);
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      } catch (SymmetricCryptoIOException e) {
        throw (RuntimeException) e.getCause();
      }

      // finalize the SV command with the data provided by the SAM
      svCommand.finalizeCommand(svCommandSecurityData);
    }
  }

  /**
   * Computes the session buffer size of the provided command.<br>
   * The size may be a number of bytes or 1 depending on the card specificities.
   *
   * @param command The command.
   * @return A positive value.
   */
  private int computeCommandSessionBufferSize(CardCommand command) {
    return card.isModificationsCounterInBytes()
        ? command.getApduRequest().getApdu().length
            + SESSION_BUFFER_CMD_ADDITIONAL_COST
            - APDU_HEADER_LENGTH
        : 1;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Deprecated
  @Override
  public CardTransactionManager prepareReleaseCardChannel() {
    checkApiLevelCompliance(false);
    channelControl = ChannelControl.CLOSE_AFTER;
    return this;
  }

  /**
   * Gets or creates a {@link ManageSecureSessionDto} at the current index.
   *
   * @return A not null reference.
   */
  private ManageSecureSessionDto getOrCreateManageSecureSessionDto() {
    ManageSecureSessionDto dto = manageSecureSessionMap.get(cardCommands.size());
    if (dto == null) {
      dto = new ManageSecureSessionDto();
      manageSecureSessionMap.put(cardCommands.size(), dto);
    }
    return dto;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public CardTransactionManager prepareEarlyMutualAuthentication() {
    try {
      if (!isExtendedMode) {
        throw new UnsupportedOperationException(MSG_MSS_COMMAND_NOT_SUPPORTED);
      }
      if (_isLastApiLevelUsed != null && _isLastApiLevelUsed) {
        checkSecureSession();
      }
      // Add a new command or update the last command if it is an MSS command.
      if (!_cardCommands.isEmpty()
          && _cardCommands.get(_cardCommands.size() - 1).getCommandRef()
              == CardCommandRef.MANAGE_SECURE_SESSION) {
        ((CmdCardManageSession) _cardCommands.get(_cardCommands.size() - 1))
            .setMutualAuthenticationRequested(true);
      } else {
        _cardCommands.add(
            new CmdCardManageSession(_transactionContext, getCommandContext())
                .setMutualAuthenticationRequested(true)
                .setEncryptionRequested(_isEncryptionActive));
      }
      // TODO legacy
      ManageSecureSessionDto dto = getOrCreateManageSecureSessionDto();
      dto.isEarlyMutualAuthenticationRequested = true;
      dto.isEncryptionRequested = isEncryptionRequested;
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public CardTransactionManager prepareActivateEncryption() {
    try {
      if (!isExtendedMode) {
        throw new UnsupportedOperationException(MSG_MSS_COMMAND_NOT_SUPPORTED);
      }
      if (_isLastApiLevelUsed != null && _isLastApiLevelUsed) {
        checkSecureSession();
      }
      if (_isEncryptionActive) {
        throw new IllegalStateException(MSG_ENCRYPTION_ALREADY_ACTIVE);
      }
      // Add a new command or update the last command if it is an MSS command.
      if (!_cardCommands.isEmpty()
          && _cardCommands.get(_cardCommands.size() - 1).getCommandRef()
              == CardCommandRef.MANAGE_SECURE_SESSION) {
        ((CmdCardManageSession) _cardCommands.get(_cardCommands.size() - 1))
            .setEncryptionRequested(true);
      } else {
        _cardCommands.add(
            new CmdCardManageSession(_transactionContext, getCommandContext())
                .setEncryptionRequested(true));
      }
      _isEncryptionActive = true;
      // TODO legacy
      ManageSecureSessionDto dto = getOrCreateManageSecureSessionDto();
      dto.isEncryptionRequested = true;
      isEncryptionRequested = true;
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public CardTransactionManager prepareDeactivateEncryption() {
    try {
      if (!isExtendedMode) {
        throw new UnsupportedOperationException(MSG_MSS_COMMAND_NOT_SUPPORTED);
      }
      if (_isLastApiLevelUsed != null && _isLastApiLevelUsed) {
        checkSecureSession();
      }
      if (!_isEncryptionActive) {
        throw new IllegalStateException(MSG_ENCRYPTION_NOT_ACTIVE);
      }
      // Add a new command or update the last command if it is an MSS command.
      if (!_cardCommands.isEmpty()
          && _cardCommands.get(_cardCommands.size() - 1).getCommandRef()
              == CardCommandRef.MANAGE_SECURE_SESSION) {
        ((CmdCardManageSession) _cardCommands.get(_cardCommands.size() - 1))
            .setEncryptionRequested(false);
      } else {
        _cardCommands.add(
            new CmdCardManageSession(_transactionContext, getCommandContext())
                .setEncryptionRequested(false));
      }
      _isEncryptionActive = false;
      // TODO legacy
      ManageSecureSessionDto dto = getOrCreateManageSecureSessionDto();
      dto.isEncryptionRequested = false;
      isEncryptionRequested = false;
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * Prepares all "Manage Secure Session" card commands, if any.
   *
   * @param isInsideSession True if it is in the context of a secure session.
   */
  private void prepareManageSecureSessionIfNeeded(boolean isInsideSession) {
    if (manageSecureSessionMap.isEmpty()) {
      return;
    }
    if (!isInsideSession) {
      throw new IllegalStateException(
          "'Manage Secure Session' command cannot be executed outside a secure session!");
    }
    int i = 0;
    for (Map.Entry<Integer, ManageSecureSessionDto> entry : manageSecureSessionMap.entrySet()) {
      int index = entry.getKey() + i;
      entry.getValue().index = index;
      cardCommands.add(
          index,
          new CmdCardManageSession(
              card,
              entry.getValue().isEncryptionRequested,
              entry.getValue().isEarlyMutualAuthenticationRequested ? new byte[8] : null));
      i++;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Override
  @Deprecated
  public CardTransactionManager prepareSelectFile(byte[] lid) {
    Assert.getInstance().notNull(lid, "lid").isEqual(lid.length, 2, "lid length");
    return prepareSelectFile((short) ByteArrayUtil.extractInt(lid, 0, 2, false));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareSelectFile(short lid) {
    try {
      _cardCommands.add(new CmdCardSelectFile(_transactionContext, getCommandContext(), lid));
      // TODO legacy
      cardCommands.add(new CmdCardSelectFile(card, lid));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSelectFile(SelectFileControl selectFileControl) {
    try {
      Assert.getInstance().notNull(selectFileControl, "selectFileControl");
      _cardCommands.add(
          new CmdCardSelectFile(_transactionContext, getCommandContext(), selectFileControl));
      // TODO legacy
      cardCommands.add(new CmdCardSelectFile(card, selectFileControl));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareGetData(GetDataTag tag) {
    try {
      Assert.getInstance().notNull(tag, "tag");
      switch (tag) {
        case FCI_FOR_CURRENT_DF:
          _cardCommands.add(new CmdCardGetDataFci(_transactionContext, getCommandContext()));
          // TODO legacy
          cardCommands.add(new CmdCardGetDataFci(card));
          break;
        case FCP_FOR_CURRENT_FILE:
          _cardCommands.add(new CmdCardGetDataFcp(_transactionContext, getCommandContext()));
          // TODO legacy
          cardCommands.add(new CmdCardGetDataFcp(card));
          break;
        case EF_LIST:
          _cardCommands.add(new CmdCardGetDataEfList(_transactionContext, getCommandContext()));
          // TODO legacy
          cardCommands.add(new CmdCardGetDataEfList(card));
          break;
        case TRACEABILITY_INFORMATION:
          _cardCommands.add(
              new CmdCardGetDataTraceabilityInformation(_transactionContext, getCommandContext()));
          // TODO legacy
          cardCommands.add(new CmdCardGetDataTraceabilityInformation(card));
          break;
        default:
          throw new UnsupportedOperationException("Unsupported Get Data tag: " + tag.name());
      }
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Override
  @Deprecated
  public CardTransactionManager prepareReadRecordFile(byte sfi, int recordNumber) {
    return prepareReadRecord(sfi, recordNumber);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Override
  @Deprecated
  public CardTransactionManager prepareReadRecordFile(
      byte sfi, int firstRecordNumber, int numberOfRecords, int recordSize) {
    return prepareReadRecords(
        sfi, firstRecordNumber, firstRecordNumber + numberOfRecords - 1, recordSize);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Override
  @Deprecated
  public CardTransactionManager prepareReadCounterFile(byte sfi, int countersNumber) {
    return prepareReadCounter(sfi, countersNumber);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareReadRecord(byte sfi, int recordNumber) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              recordNumber,
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              RECORD_NUMBER);

      // A record size of 0 indicates that the card determines the output length.
      // However, "legacy case 1" cards require a non-zero value.
      int recordSize = card.isLegacyCase1() ? CalypsoCardConstant.LEGACY_REC_LENGTH : 0;

      // Try to group the first read record command with the open secure session command.
      if (canConfigureReadOnOpenSecureSession()) {
        ((CmdCardOpenSecureSession) _cardCommands.get(_cardCommands.size() - 1))
            .configureReadMode(sfi, recordNumber);
      } else {
        if (_isSecureSessionOpen && !((CardReader) cardReader).isContactless()) {
          throw new IllegalStateException(
              "Explicit record size is expected inside a secure session in contact mode.");
        }
        _cardCommands.add(
            new CmdCardReadRecords(
                _transactionContext,
                getCommandContext(),
                sfi,
                recordNumber,
                CmdCardReadRecords.ReadMode.ONE_RECORD,
                recordSize,
                recordSize));
      }
      // TODO legacy
      cardCommands.add(
          new CmdCardReadRecords(
              card,
              sfi,
              recordNumber,
              CmdCardReadRecords.ReadMode.ONE_RECORD,
              recordSize,
              recordSize));

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * @return True if it is possible to configure the auto read record into the open secure session
   *     command.
   */
  private boolean canConfigureReadOnOpenSecureSession() {
    return _isSecureSessionOpen
        && !securitySetting.isReadOnSessionOpeningDisabled()
        && card.getPreOpenWriteAccessLevel() == null // No pre-open mode
        && !_cardCommands.isEmpty()
        && _cardCommands.get(_cardCommands.size() - 1).getCommandRef()
            == CardCommandRef.OPEN_SECURE_SESSION
        && !((CmdCardOpenSecureSession) _cardCommands.get(_cardCommands.size() - 1))
            .isReadModeConfigured();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareReadRecords(
      byte sfi, int fromRecordNumber, int toRecordNumber, int recordSize) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              fromRecordNumber,
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              "fromRecordNumber")
          .isInRange(
              toRecordNumber, fromRecordNumber, CalypsoCardConstant.NB_REC_MAX, "toRecordNumber")
          .isInRange(recordSize, 0, cardPayloadCapacity, "recordSize");

      if (toRecordNumber == fromRecordNumber
          || (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3
              && card.getProductType() != CalypsoCard.ProductType.LIGHT)) {
        // Creates N unitary "Read Records" commands.
        // Try to group the first read record command with the open secure session command.
        if (canConfigureReadOnOpenSecureSession()) {
          ((CmdCardOpenSecureSession) _cardCommands.get(_cardCommands.size() - 1))
              .configureReadMode(sfi, fromRecordNumber);
          // TODO legacy
          cardCommands.add(
              new CmdCardReadRecords(
                  card,
                  sfi,
                  fromRecordNumber,
                  CmdCardReadRecords.ReadMode.ONE_RECORD,
                  recordSize,
                  recordSize));
          fromRecordNumber++;
        }
        for (int i = fromRecordNumber; i <= toRecordNumber; i++) {
          _cardCommands.add(
              new CmdCardReadRecords(
                  _transactionContext,
                  getCommandContext(),
                  sfi,
                  i,
                  CmdCardReadRecords.ReadMode.ONE_RECORD,
                  recordSize,
                  recordSize));
          // TODO legacy
          cardCommands.add(
              new CmdCardReadRecords(
                  card, sfi, i, CmdCardReadRecords.ReadMode.ONE_RECORD, recordSize, recordSize));
        }
      } else {
        // Manages the reading of multiple records taking into account the transmission capacity
        // of the card and the response format (2 extra bytes).
        // Multiple APDUs can be generated depending on record size and transmission capacity.
        int nbBytesPerRecord = recordSize + 2;
        int nbRecordsPerApdu = cardPayloadCapacity / nbBytesPerRecord;
        int dataSizeMaxPerApdu = nbRecordsPerApdu * nbBytesPerRecord;

        int currentRecordNumber = fromRecordNumber;
        int nbRecordsRemainingToRead = toRecordNumber - fromRecordNumber + 1;
        int currentLength;

        while (currentRecordNumber < toRecordNumber) {
          currentLength =
              nbRecordsRemainingToRead <= nbRecordsPerApdu
                  ? nbRecordsRemainingToRead * nbBytesPerRecord
                  : dataSizeMaxPerApdu;

          _cardCommands.add(
              new CmdCardReadRecords(
                  _transactionContext,
                  getCommandContext(),
                  sfi,
                  currentRecordNumber,
                  CmdCardReadRecords.ReadMode.MULTIPLE_RECORD,
                  currentLength,
                  recordSize));
          // TODO legacy
          cardCommands.add(
              new CmdCardReadRecords(
                  card,
                  sfi,
                  currentRecordNumber,
                  CmdCardReadRecords.ReadMode.MULTIPLE_RECORD,
                  currentLength,
                  recordSize));

          currentRecordNumber += (currentLength / nbBytesPerRecord);
          nbRecordsRemainingToRead -= (currentLength / nbBytesPerRecord);
        }

        // Optimization: prepare a read "one record" if possible for last iteration.
        if (currentRecordNumber == toRecordNumber) {
          _cardCommands.add(
              new CmdCardReadRecords(
                  _transactionContext,
                  getCommandContext(),
                  sfi,
                  currentRecordNumber,
                  CmdCardReadRecords.ReadMode.ONE_RECORD,
                  recordSize,
                  recordSize));
          // TODO legacy
          cardCommands.add(
              new CmdCardReadRecords(
                  card,
                  sfi,
                  currentRecordNumber,
                  CmdCardReadRecords.ReadMode.ONE_RECORD,
                  recordSize,
                  recordSize));
        }
      }

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareReadRecordsPartially(
      byte sfi, int fromRecordNumber, int toRecordNumber, int offset, int nbBytesToRead) {
    try {
      if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3
          && card.getProductType() != CalypsoCard.ProductType.LIGHT) {
        throw new UnsupportedOperationException(
            "The 'Read Record Multiple' command is not available for this card.");
      }

      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              fromRecordNumber,
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              "fromRecordNumber")
          .isInRange(
              toRecordNumber, fromRecordNumber, CalypsoCardConstant.NB_REC_MAX, "toRecordNumber")
          .isInRange(offset, CalypsoCardConstant.OFFSET_MIN, CalypsoCardConstant.OFFSET_MAX, OFFSET)
          .isInRange(
              nbBytesToRead,
              CalypsoCardConstant.DATA_LENGTH_MIN,
              cardPayloadCapacity,
              "nbBytesToRead");

      int nbRecordsPerApdu = cardPayloadCapacity / nbBytesToRead;

      int currentRecordNumber = fromRecordNumber;

      while (currentRecordNumber <= toRecordNumber) {
        _cardCommands.add(
            new CmdCardReadRecordMultiple(
                _transactionContext,
                getCommandContext(),
                sfi,
                (byte) currentRecordNumber,
                (byte) offset,
                (byte) nbBytesToRead));
        // TODO legacy
        cardCommands.add(
            new CmdCardReadRecordMultiple(
                card, sfi, (byte) currentRecordNumber, (byte) offset, (byte) nbBytesToRead));
        currentRecordNumber += nbRecordsPerApdu;
      }

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareReadBinary(byte sfi, int offset, int nbBytesToRead) {
    try {
      if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3) {
        if (card.getProductType() == CalypsoCard.ProductType.PRIME_REVISION_2) {
          logger.warn(
              "The 'Read Binary' command may not be supported by this PRIME_REVISION_2 card.");
        } else {
          throw new UnsupportedOperationException(
              "The 'Read Binary' command is not available for this card.");
        }
      }

      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              offset, CalypsoCardConstant.OFFSET_MIN, CalypsoCardConstant.OFFSET_BINARY_MAX, OFFSET)
          .greaterOrEqual(nbBytesToRead, 1, "nbBytesToRead");

      if (sfi > 0 && offset > 255) { // FFh
        // Tips to select the file: add a "Read Binary" command (read one byte at offset 0).
        _cardCommands.add(
            new CmdCardReadBinary(_transactionContext, getCommandContext(), sfi, 0, 1));
        // TODO legacy
        cardCommands.add(new CmdCardReadBinary(card, sfi, 0, 1));
      }

      int currentLength;
      int currentOffset = offset;
      int nbBytesRemainingToRead = nbBytesToRead;
      do {
        currentLength = Math.min(nbBytesRemainingToRead, cardPayloadCapacity);

        _cardCommands.add(
            new CmdCardReadBinary(
                _transactionContext, getCommandContext(), sfi, currentOffset, currentLength));
        // TODO legacy
        cardCommands.add(new CmdCardReadBinary(card, sfi, currentOffset, currentLength));

        currentOffset += currentLength;
        nbBytesRemainingToRead -= currentLength;
      } while (nbBytesRemainingToRead > 0);

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareReadCounter(byte sfi, int nbCountersToRead) {
    return prepareReadRecords(sfi, 1, 1, nbCountersToRead * 3);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareSearchRecords(SearchCommandData data) {
    try {
      if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3) {
        throw new UnsupportedOperationException(
            "The 'Search Record Multiple' command is not available for this card.");
      }

      if (!(data instanceof SearchCommandDataAdapter)) {
        throw new IllegalArgumentException(
            "The provided data must be an instance of 'SearchCommandDataAdapter'");
      }

      SearchCommandDataAdapter dataAdapter = (SearchCommandDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, "data")
          .isInRange(
              (int) dataAdapter.getSfi(),
              CalypsoCardConstant.SFI_MIN,
              CalypsoCardConstant.SFI_MAX,
              "sfi")
          .isInRange(
              dataAdapter.getRecordNumber(),
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              "startAtRecord")
          .isInRange(
              dataAdapter.getOffset(),
              CalypsoCardConstant.OFFSET_MIN,
              CalypsoCardConstant.OFFSET_MAX,
              OFFSET)
          .notNull(dataAdapter.getSearchData(), "searchData")
          .isInRange(
              dataAdapter.getSearchData().length,
              CalypsoCardConstant.DATA_LENGTH_MIN,
              cardPayloadCapacity,
              "searchData");
      if (dataAdapter.getMask() != null) {
        Assert.getInstance()
            .isInRange(
                dataAdapter.getMask().length,
                CalypsoCardConstant.DATA_LENGTH_MIN,
                dataAdapter.getSearchData().length,
                "mask");
      }

      _cardCommands.add(
          new CmdCardSearchRecordMultiple(_transactionContext, getCommandContext(), dataAdapter));
      // TODO legacy
      cardCommands.add(new CmdCardSearchRecordMultiple(card, dataAdapter));

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareAppendRecord(byte sfi, byte[] recordData) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .notNull(recordData, MSG_RECORD_DATA)
          .isInRange(recordData.length, 0, cardPayloadCapacity, MSG_RECORD_DATA_LENGTH);
      CmdCardAppendRecord command =
          new CmdCardAppendRecord(_transactionContext, getCommandContext(), sfi, recordData);
      prepareNewSecureSessionIfNeeded(command);
      _cardCommands.add(command);
      // TODO legacy
      cardCommands.add(new CmdCardAppendRecord(card, sfi, recordData));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareUpdateRecord(byte sfi, int recordNumber, byte[] recordData) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              recordNumber,
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              RECORD_NUMBER)
          .notNull(recordData, MSG_RECORD_DATA)
          .isInRange(recordData.length, 0, cardPayloadCapacity, MSG_RECORD_DATA_LENGTH);
      CmdCardUpdateRecord command =
          new CmdCardUpdateRecord(
              _transactionContext, getCommandContext(), sfi, recordNumber, recordData);
      prepareNewSecureSessionIfNeeded(command);
      _cardCommands.add(command);
      // TODO legacy
      cardCommands.add(new CmdCardUpdateRecord(card, sfi, recordNumber, recordData));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareWriteRecord(byte sfi, int recordNumber, byte[] recordData) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              recordNumber,
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              RECORD_NUMBER)
          .notNull(recordData, MSG_RECORD_DATA)
          .isInRange(recordData.length, 0, cardPayloadCapacity, MSG_RECORD_DATA_LENGTH);
      CmdCardWriteRecord command =
          new CmdCardWriteRecord(
              _transactionContext, getCommandContext(), sfi, recordNumber, recordData);
      prepareNewSecureSessionIfNeeded(command);
      _cardCommands.add(command);
      // TODO legacy
      cardCommands.add(new CmdCardWriteRecord(card, sfi, recordNumber, recordData));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareUpdateBinary(byte sfi, int offset, byte[] data) {
    return prepareUpdateOrWriteBinary(true, sfi, offset, data);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareWriteBinary(byte sfi, int offset, byte[] data) {
    return prepareUpdateOrWriteBinary(false, sfi, offset, data);
  }

  /**
   * Prepare an "Update/Write Binary" command.
   *
   * @param isUpdateCommand True if it is an "Update Binary" command, false if it is a "Write
   *     Binary" command.
   * @param sfi The SFI.
   * @param offset The offset.
   * @param data The data to update/write.
   * @return The current instance.
   */
  private CardTransactionManager prepareUpdateOrWriteBinary(
      boolean isUpdateCommand, byte sfi, int offset, byte[] data) {
    try {
      if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3) {
        if (card.getProductType() == CalypsoCard.ProductType.PRIME_REVISION_2) {
          logger.warn(
              "The 'Update/Write Binary' command may not be supported by this PRIME_REVISION_2 card.");
        } else {
          throw new UnsupportedOperationException(
              "The 'Update/Write Binary' command is not available for this card.");
        }
      }

      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              offset, CalypsoCardConstant.OFFSET_MIN, CalypsoCardConstant.OFFSET_BINARY_MAX, OFFSET)
          .notEmpty(data, "data");

      if (sfi > 0 && offset > 255) { // FFh
        // Tips to select the file: add a "Read Binary" command (read one byte at offset 0).
        _cardCommands.add(
            new CmdCardReadBinary(_transactionContext, getCommandContext(), sfi, 0, 1));
        // TODO legacy
        cardCommands.add(new CmdCardReadBinary(card, sfi, 0, 1));
      }

      int dataLength = data.length;

      int currentLength;
      int currentOffset = offset;
      int currentIndex = 0;
      do {
        currentLength = Math.min(dataLength - currentIndex, cardPayloadCapacity);

        CmdCardUpdateOrWriteBinary command =
            new CmdCardUpdateOrWriteBinary(
                isUpdateCommand,
                _transactionContext,
                getCommandContext(),
                sfi,
                currentOffset,
                Arrays.copyOfRange(data, currentIndex, currentIndex + currentLength));
        prepareNewSecureSessionIfNeeded(command);
        _cardCommands.add(command);
        // TODO legacy
        cardCommands.add(
            new CmdCardUpdateOrWriteBinary(
                isUpdateCommand,
                card,
                sfi,
                currentOffset,
                Arrays.copyOfRange(data, currentIndex, currentIndex + currentLength)));

        currentOffset += currentLength;
        currentIndex += currentLength;
      } while (currentIndex < dataLength);

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /** Factorisation of prepareDecreaseCounter and prepareIncreaseCounter. */
  private CardTransactionManager prepareIncreaseOrDecreaseCounter(
      boolean isDecreaseCommand, byte sfi, int counterNumber, int incDecValue) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              counterNumber,
              CalypsoCardConstant.NB_CNT_MIN,
              cardPayloadCapacity / 3,
              "counterNumber")
          .isInRange(
              incDecValue,
              CalypsoCardConstant.CNT_VALUE_MIN,
              CalypsoCardConstant.CNT_VALUE_MAX,
              "incDecValue");
      CmdCardIncreaseOrDecrease command =
          new CmdCardIncreaseOrDecrease(
              isDecreaseCommand,
              _transactionContext,
              getCommandContext(),
              sfi,
              counterNumber,
              incDecValue);
      prepareNewSecureSessionIfNeeded(command);
      _cardCommands.add(command);
      if (_isSecureSessionOpen && card.isCounterValuePostponed()) {
        _nbPostponedData++;
      }
      // TODO legacy
      cardCommands.add(
          new CmdCardIncreaseOrDecrease(isDecreaseCommand, card, sfi, counterNumber, incDecValue));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareIncreaseCounter(byte sfi, int counterNumber, int incValue) {
    return prepareIncreaseOrDecreaseCounter(false, sfi, counterNumber, incValue);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareDecreaseCounter(byte sfi, int counterNumber, int decValue) {
    return prepareIncreaseOrDecreaseCounter(true, sfi, counterNumber, decValue);
  }

  /**
   * Closes and opens a new secure session if the three following conditions are satisfied:
   *
   * <ul>
   *   <li>a secure session is open
   *   <li>the command will overflow the modifications buffer size
   *   <li>the multiple session mode is allowed
   * </ul>
   *
   * @param command The command.
   * @throws SessionBufferOverflowException If the command will overflow the modifications buffer
   *     size and the multiple session is not allowed.
   */
  private void prepareNewSecureSessionIfNeeded(CardCommand command) {
    if (!_isSecureSessionOpen) {
      return;
    }
    _modificationsCounter -= computeCommandSessionBufferSize(command);
    if (_modificationsCounter < 0) {
      checkMultipleSessionEnabled(command);
      _cardCommands.add(
          new CmdCardCloseSecureSession(
              _transactionContext, getCommandContext(), true, _svPostponedDataIndex));
      disablePreOpenMode();
      _cardCommands.add(
          new CmdCardOpenSecureSession(
              _transactionContext,
              getCommandContext(),
              symmetricCryptoSecuritySetting,
              _writeAccessLevel,
              isExtendedMode));
      if (_isEncryptionActive) {
        _cardCommands.add(
            new CmdCardManageSession(_transactionContext, getCommandContext())
                .setEncryptionRequested(true));
      }
      _modificationsCounter = card.getModificationsCounter();
      _modificationsCounter -= computeCommandSessionBufferSize(command);
      _nbPostponedData = 0;
      _svPostponedDataIndex = -1;
      _isSvOperationInSecureSession = false;
    }
  }

  /** Factorisation of prepareDecreaseMultipleCounters and prepareIncreaseMultipleCounters. */
  private CardTransactionManager prepareIncreaseOrDecreaseCounters(
      boolean isDecreaseCommand, byte sfi, Map<Integer, Integer> counterNumberToIncDecValueMap) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              counterNumberToIncDecValueMap.size(),
              CalypsoCardConstant.NB_CNT_MIN,
              cardPayloadCapacity / 3,
              "counterNumberToIncDecValueMap");

      for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
        Assert.getInstance()
            .isInRange(
                entry.getKey(),
                CalypsoCardConstant.NB_CNT_MIN,
                cardPayloadCapacity / 3,
                "counterNumberToIncDecValueMapKey")
            .isInRange(
                entry.getValue(),
                CalypsoCardConstant.CNT_VALUE_MIN,
                CalypsoCardConstant.CNT_VALUE_MAX,
                "counterNumberToIncDecValueMapValue");
      }

      if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3
          && card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_2) {
        for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
          if (isDecreaseCommand) {
            prepareDecreaseCounter(sfi, entry.getKey(), entry.getValue());
          } else {
            prepareIncreaseCounter(sfi, entry.getKey(), entry.getValue());
          }
        }
      } else {
        int nbCountersPerApdu = cardPayloadCapacity / 4;
        if (counterNumberToIncDecValueMap.size() <= nbCountersPerApdu) {
          CmdCardIncreaseOrDecreaseMultiple command =
              new CmdCardIncreaseOrDecreaseMultiple(
                  isDecreaseCommand,
                  _transactionContext,
                  getCommandContext(),
                  sfi,
                  new TreeMap<Integer, Integer>(counterNumberToIncDecValueMap));
          prepareNewSecureSessionIfNeeded(command);
          _cardCommands.add(command);
          // TODO legacy
          cardCommands.add(
              new CmdCardIncreaseOrDecreaseMultiple(
                  isDecreaseCommand,
                  card,
                  sfi,
                  new TreeMap<Integer, Integer>(counterNumberToIncDecValueMap)));
        } else {
          // the number of counters exceeds the payload capacity, let's split into several apdu
          // commands
          int i = 0;
          TreeMap<Integer, Integer> map = new TreeMap<Integer, Integer>();
          for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
            i++;
            map.put(entry.getKey(), entry.getValue());
            if (i == nbCountersPerApdu) {
              CmdCardIncreaseOrDecreaseMultiple command =
                  new CmdCardIncreaseOrDecreaseMultiple(
                      isDecreaseCommand,
                      _transactionContext,
                      getCommandContext(),
                      sfi,
                      new TreeMap<Integer, Integer>(map));
              prepareNewSecureSessionIfNeeded(command);
              _cardCommands.add(command);
              // TODO legacy
              cardCommands.add(
                  new CmdCardIncreaseOrDecreaseMultiple(
                      isDecreaseCommand, card, sfi, new TreeMap<Integer, Integer>(map)));
              i = 0;
              map.clear();
            }
          }
          if (!map.isEmpty()) {
            CmdCardIncreaseOrDecreaseMultiple command =
                new CmdCardIncreaseOrDecreaseMultiple(
                    isDecreaseCommand, _transactionContext, getCommandContext(), sfi, map);
            prepareNewSecureSessionIfNeeded(command);
            _cardCommands.add(command);
            // TODO legacy
            cardCommands.add(
                new CmdCardIncreaseOrDecreaseMultiple(isDecreaseCommand, card, sfi, map));
          }
        }
      }

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareIncreaseCounters(
      byte sfi, Map<Integer, Integer> counterNumberToIncValueMap) {
    return prepareIncreaseOrDecreaseCounters(false, sfi, counterNumberToIncValueMap);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareDecreaseCounters(
      byte sfi, Map<Integer, Integer> counterNumberToDecValueMap) {
    return prepareIncreaseOrDecreaseCounters(true, sfi, counterNumberToDecValueMap);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSetCounter(byte sfi, int counterNumber, int newValue) {
    try {
      Integer oldValue = null;
      ElementaryFile ef = card.getFileBySfi(sfi);
      if (ef != null) {
        oldValue = ef.getData().getContentAsCounterValue(counterNumber);
      }
      if (oldValue == null) {
        throw new IllegalStateException(
            "The value for counter " + counterNumber + " in file " + sfi + " is not available");
      }
      int delta = newValue - oldValue;
      if (delta > 0) {
        if (logger.isTraceEnabled()) {
          logger.trace(
              "Increment counter {} (file {}) from {} to {}",
              counterNumber,
              sfi,
              newValue - delta,
              newValue);
        }
        prepareIncreaseCounter(sfi, counterNumber, delta);
      } else if (delta < 0) {
        if (logger.isTraceEnabled()) {
          logger.trace(
              "Decrement counter {} (file {}) from {} to {}",
              counterNumber,
              sfi,
              newValue - delta,
              newValue);
        }
        prepareDecreaseCounter(sfi, counterNumber, -delta);
      } else {
        logger.info(
            "The counter {} (SFI {}) is already set to the desired value {}.",
            counterNumber,
            sfi,
            newValue);
      }

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareCheckPinStatus() {
    try {
      if (!card.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
      }
      _cardCommands.add(new CmdCardVerifyPin(_transactionContext, getCommandContext()));
      // TODO legacy
      cardCommands.add(new CmdCardVerifyPin(card));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSvGet(SvOperation svOperation, SvAction svAction) {
    try {
      Assert.getInstance().notNull(svOperation, "svOperation").notNull(svAction, "svAction");

      if (!card.isSvFeatureAvailable()) {
        throw new UnsupportedOperationException("Stored Value is not available for this card.");
      }

      if (symmetricCryptoSecuritySetting.isSvLoadAndDebitLogEnabled() && (!isExtendedMode)) {
        // @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit logs are requested
        // for a non rev3.2 card add two SvGet commands (for RELOAD then for DEBIT).
        // CL-SV-GETNUMBER.1
        SvOperation operation1 =
            svOperation == SvOperation.RELOAD ? SvOperation.DEBIT : SvOperation.RELOAD;
        _cardCommands.add(
            new CmdCardSvGet(_transactionContext, getCommandContext(), operation1, false));
        // TODO legacy
        addStoredValueCommand(new CmdCardSvGet(card, operation1, false), operation1);
      }
      _cardCommands.add(
          new CmdCardSvGet(_transactionContext, getCommandContext(), svOperation, isExtendedMode));
      _isSvGet = true;
      _svOperation = svOperation;
      // TODO legacy
      addStoredValueCommand(new CmdCardSvGet(card, svOperation, isExtendedMode), svOperation);
      this.svAction = svAction;
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSvReload(int amount, byte[] date, byte[] time, byte[] free) {
    try {
      Assert.getInstance()
          .isInRange(
              amount,
              CalypsoCardConstant.SV_LOAD_MIN_VALUE,
              CalypsoCardConstant.SV_LOAD_MAX_VALUE,
              "amount")
          .notNull(date, "date")
          .notNull(time, "time")
          .notNull(free, "free")
          .isEqual(date.length, 2, "date")
          .isEqual(time.length, 2, "time")
          .isEqual(free.length, 2, "free");

      checkSvModifyingCommandPreconditions(SvOperation.RELOAD);

      CmdCardSvReload command =
          new CmdCardSvReload(
              _transactionContext, getCommandContext(), amount, date, time, free, isExtendedMode);
      prepareNewSecureSessionIfNeeded(command);
      _cardCommands.add(command);

      // TODO legacy
      // create the initial command with the application data
      addStoredValueCommand(
          new CmdCardSvReload(card, amount, date, time, free, isExtendedMode), SvOperation.RELOAD);

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * Checks if the preconditions of an SV modifying command are satisfied and updates the
   * corresponding flags.
   *
   * @throws IllegalStateException If preconditions are not satisfied.
   */
  private void checkSvModifyingCommandPreconditions(SvOperation svOperation) {
    // CL-SV-GETDEBIT.1
    // CL-SV-GETRLOAD.1
    if (!_isSvGet) {
      throw new IllegalStateException("SV modifying command must follow an SV Get command");
    }
    _isSvGet = false;
    if (svOperation != _svOperation) {
      throw new IllegalStateException("Inconsistent SV operation");
    }
    // CL-SV-1PCSS.1
    if (_isSecureSessionOpen) {
      if (_isSvOperationInSecureSession) {
        throw new IllegalStateException(
            "Only one SV modifying command is allowed per Secure Session");
      }
      _isSvOperationInSecureSession = true;
      _svPostponedDataIndex = _nbPostponedData;
      _nbPostponedData++;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSvReload(int amount) {
    byte[] zero = {0x00, 0x00};
    prepareSvReload(amount, zero, zero, zero);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSvDebit(int amount, byte[] date, byte[] time) {
    try {
      /* @see Calypso Layer ID 8.02 (200108) */
      // CL-SV-DEBITVAL.1
      Assert.getInstance()
          .isInRange(
              amount,
              CalypsoCardConstant.SV_DEBIT_MIN_VALUE,
              CalypsoCardConstant.SV_DEBIT_MAX_VALUE,
              "amount")
          .notNull(date, "date")
          .notNull(time, "time")
          .isEqual(date.length, 2, "date")
          .isEqual(time.length, 2, "time");

      checkSvModifyingCommandPreconditions(SvOperation.DEBIT);

      CmdCardSvDebitOrUndebit command =
          new CmdCardSvDebitOrUndebit(
              svAction == SvAction.DO,
              _transactionContext,
              getCommandContext(),
              amount,
              date,
              time,
              isExtendedMode,
              symmetricCryptoSecuritySetting.isSvNegativeBalanceAuthorized());
      prepareNewSecureSessionIfNeeded(command);
      _cardCommands.add(command);

      // TODO legacy
      // create the initial command with the application data
      addStoredValueCommand(
          new CmdCardSvDebitOrUndebit(
              svAction == SvAction.DO, card, amount, date, time, isExtendedMode),
          SvOperation.DEBIT);

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSvDebit(int amount) {
    byte[] zero = {0x00, 0x00};
    prepareSvDebit(amount, zero, zero);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSvReadAllLogs() {
    try {
      if (!card.isSvFeatureAvailable()) {
        throw new UnsupportedOperationException("Stored Value is not available for this card.");
      }
      if (card.getApplicationSubtype() != CalypsoCardConstant.STORED_VALUE_FILE_STRUCTURE_ID) {
        throw new UnsupportedOperationException(
            "The currently selected application is not an SV application.");
      }
      // reset SV data in CalypsoCard if any
      card.setSvData((byte) 0, null, null, 0, 0);
      prepareReadRecords(
          CalypsoCardConstant.SV_RELOAD_LOG_FILE_SFI,
          1,
          CalypsoCardConstant.SV_RELOAD_LOG_FILE_NB_REC,
          CalypsoCardConstant.SV_LOG_FILE_REC_LENGTH);
      prepareReadRecords(
          CalypsoCardConstant.SV_DEBIT_LOG_FILE_SFI,
          1,
          CalypsoCardConstant.SV_DEBIT_LOG_FILE_NB_REC,
          CalypsoCardConstant.SV_LOG_FILE_REC_LENGTH);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareInvalidate() {
    try {
      if (card.isDfInvalidated()) {
        throw new IllegalStateException("Card already invalidated");
      }
      CmdCardInvalidate command = new CmdCardInvalidate(_transactionContext, getCommandContext());
      prepareNewSecureSessionIfNeeded(command);
      _cardCommands.add(command);
      // TODO legacy
      cardCommands.add(new CmdCardInvalidate(card));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareRehabilitate() {
    try {
      if (!card.isDfInvalidated()) {
        throw new IllegalStateException("Card not invalidated");
      }
      CmdCardRehabilitate command =
          new CmdCardRehabilitate(_transactionContext, getCommandContext());
      prepareNewSecureSessionIfNeeded(command);
      _cardCommands.add(command);
      // TODO legacy
      cardCommands.add(new CmdCardRehabilitate(card));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * Add a StoredValue command to the list.
   *
   * <p>Set up a mini state machine to manage the scheduling of Stored Value commands.
   *
   * <p>The {@link SvOperation} and {@link SvAction} are also used to check the consistency of the
   * SV process.
   *
   * <p>The svOperationPending flag is set when an SV operation (Reload/Debit/Undebit) command is
   * added.
   *
   * @param command the StoredValue command.
   * @param svOperation the type of the current SV operation (Reload/Debit/Undebit).
   * @throws IllegalStateException if the provided command is not an SV command or not properly
   *     used.
   */
  private void addStoredValueCommand(CardCommand command, SvOperation svOperation) {
    // Check the logic of the SV command sequencing
    switch (command.getCommandRef()) {
      case SV_GET:
        this.svOperation = svOperation;
        break;
      case SV_RELOAD:
      case SV_DEBIT:
      case SV_UNDEBIT:
        // CL-SV-GETDEBIT.1
        // CL-SV-GETRLOAD.1
        //        if (!cardCommands.isEmpty()) {
        //          throw new IllegalStateException(
        //              "This SV command can only be placed in the first position in the list of
        // prepared commands");
        //        }
        if (svLastCommandRef != CardCommandRef.SV_GET) {
          throw new IllegalStateException("This SV command must follow an SV Get command");
        }
        // here, we expect the command and the SV operation to be consistent
        if (svOperation != this.svOperation) {
          logger.error("Sv operation = {}, current command = {}", this.svOperation, svOperation);
          throw new IllegalStateException("Inconsistent SV operation.");
        }
        isSvOperationComplete = true;
        svLastModifyingCommand = command;
        break;
      default:
        throw new IllegalStateException("An SV command is expected.");
    }
    svLastCommandRef = command.getCommandRef();
    cardCommands.add(command);
  }

  /**
   * Informs that the commands have been processed.
   *
   * <p>Just record the information. The initialization of the list of commands will be done only
   * the next time a command is added, this allows access to the commands contained in the list.
   */
  private void notifyCommandsProcessed() {
    cardCommands.clear();
    manageSecureSessionMap.clear();
    svLastModifyingCommand = null;
  }

  /**
   * Indicates whether an SV Operation has been completed (Reload/Debit/Undebit requested) <br>
   * This method is dedicated to triggering the signature verification after an SV transaction has
   * been executed. It is a single-use method, as the flag is systematically reset to false after it
   * is called.
   *
   * @return True if a "reload" or "debit" command has been requested
   */
  private boolean isSvOperationCompleteOneTime() {
    boolean flag = isSvOperationComplete;
    isSvOperationComplete = false;
    return flag;
  }

  /**
   * Creates a list of {@link ApduRequestSpi} from a list of {@link CardCommand}.
   *
   * @param commands The list of commands.
   * @return An empty list if there is no command.
   * @since 2.2.0
   */
  private static List<ApduRequestSpi> getApduRequests(List<CardCommand> commands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    if (commands != null) {
      for (CardCommand command : commands) {
        apduRequests.add(command.getApduRequest());
      }
    }
    return apduRequests;
  }

  /** Adapter of {@link ApduResponseApi} used to create anticipated card responses. */
  private static final class ApduResponseAdapter implements ApduResponseApi {

    private final byte[] apdu;
    private final int statusWord;

    /** Constructor */
    private ApduResponseAdapter(byte[] apdu) {
      this.apdu = apdu;
      statusWord = ByteArrayUtil.extractInt(apdu, apdu.length - 2, 2, false);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getApdu() {
      return apdu;
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getDataOut() {
      return Arrays.copyOfRange(apdu, 0, apdu.length - 2);
    }

    /** {@inheritDoc} */
    @Override
    public int getStatusWord() {
      return statusWord;
    }

    /**
     * Converts the APDU response into a string where the data is encoded in a json format.
     *
     * @return A not empty String
     * @since 2.0.0
     */
    @Override
    public String toString() {
      return "APDU_RESPONSE = " + JsonUtil.toJson(this);
    }
  }

  private static class ManageSecureSessionDto {
    private int index;
    private boolean isEarlyMutualAuthenticationRequested;
    private boolean isEncryptionRequested;
  }
}
