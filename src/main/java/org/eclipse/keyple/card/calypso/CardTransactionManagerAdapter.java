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
  private static final String MSG_CARD_READER_COMMUNICATION_ERROR =
      "A communication error with the card reader occurred ";
  private static final String MSG_CARD_COMMUNICATION_ERROR =
      "A communication error with the card occurred ";
  private static final String MSG_CARD_COMMAND_ERROR = "A card command error occurred ";
  private static final String MSG_PIN_NOT_AVAILABLE = "PIN is not available for this card.";
  private static final String MSG_CARD_SESSION_MAC_NOT_VERIFIABLE =
      "Unable to verify the card session MAC associated to the successfully closed secure session.";
  private static final String MSG_CARD_SV_MAC_NOT_VERIFIABLE =
      "Unable to verify the card SV MAC associated to the SV operation.";
  public static final String MSG_INVALID_CARD_SESSION_MAC = "Invalid card session MAC";
  public static final String MSG_MANAGE_SECURE_SESSION_NOT_SUPPORTED =
      "The 'Manage Secure Session' command is not available for this context (Card and/or SAM does not support the extended mode).";

  private static final String RECORD_NUMBER = "record number";
  private static final String OFFSET = "offset";

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
  private final boolean isExtendedModeRequired;
  private final int cardPayloadCapacity;

  /* Dynamic fields */
  private boolean isSessionOpen;
  private WriteAccessLevel writeAccessLevel;
  private ChannelControl channelControl = ChannelControl.KEEP_OPEN;
  private int modificationsCounter;
  private SvOperation svOperation;
  private SvAction svAction;
  private CardCommandRef svLastCommandRef;
  private CardCommand svLastModifyingCommand;
  private boolean isSvOperationInsideSession;
  private boolean isSvOperationComplete;
  private int svPostponedDataIndex;
  private int nbPostponedData;
  private boolean isEncryptionActive;
  private boolean isEncryptionRequested;

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
      isExtendedModeRequired =
          card.isExtendedModeSupported()
              && cryptoTransactionManagerFactory.isExtendedModeSupported();
      // Adjust card & SAM payload capacities
      cardPayloadCapacity =
          Math.min(
              card.getPayloadCapacity(),
              cryptoTransactionManagerFactory.getMaxCardApduLengthSupported() - APDU_HEADER_LENGTH);
      // CL-SAM-CSN.1
      symmetricCryptoTransactionManagerSpi =
          cryptoTransactionManagerFactory.createTransactionManager(
              card.getCalypsoSerialNumberFull(), isExtendedModeRequired, getTransactionAuditData());
      cryptoExtension =
          (LegacySamCardTransactionCryptoExtension) symmetricCryptoTransactionManagerSpi;
    } else {
      // Non-secure operations mode
      symmetricCryptoSecuritySetting = null;
      isExtendedModeRequired = card.isExtendedModeSupported();
      cardPayloadCapacity = card.getPayloadCapacity();
      symmetricCryptoTransactionManagerSpi = null;
      cryptoExtension = null;
    }

    this.modificationsCounter = card.getModificationsCounter();
  }

  private SymmetricCryptoSecuritySettingAdapter buildSymmetricCryptoSecuritySetting(
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

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardReader getCardReader() {
    return (CardReader) cardReader;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCard getCalypsoCard() {
    return card;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated Use {@link #getSecuritySetting()} instead.
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
      throw new IllegalStateException("Crypto service is not set.");
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
   * Open a single Secure Session.
   *
   * @param cardCommands the card commands inside session.
   * @throws IllegalStateException if no {@link CardSecuritySetting} is available.
   */
  private void processAtomicOpening(List<CardCommand> cardCommands) {

    if (symmetricCryptoSecuritySetting == null) {
      throw new IllegalStateException("No security settings are available.");
    }

    card.backupFiles();
    nbPostponedData = 0;

    if (cardCommands == null) {
      cardCommands = new ArrayList<CardCommand>();
    }

    // Let's check if we have a read record command at the top of the command list.
    // If so, then the command is withdrawn in favour of its equivalent executed at the same
    // time as the open secure session command.
    // The sfi and record number to be read when the open secure session command is executed.
    // The default value is 0 (no record to read) but we will optimize the exchanges if a read
    // record command has been prepared.
    int offset = 1; // Open Secure Session is inserted at index 0.
    int sfi = 0;
    int recordNumber = 0;
    if (!cardCommands.isEmpty()) {
      CardCommand cardCommand = cardCommands.get(0);
      if (cardCommand.getCommandRef() == CardCommandRef.READ_RECORDS
          && ((CmdCardReadRecords) cardCommand).getReadMode()
              == CmdCardReadRecords.ReadMode.ONE_RECORD) {
        sfi = ((CmdCardReadRecords) cardCommand).getSfi();
        recordNumber = ((CmdCardReadRecords) cardCommand).getFirstRecordNumber();
        cardCommands.remove(0);
        offset = 0;
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
    CmdCardOpenSession cmdCardOpenSession =
        new CmdCardOpenSession(
            card,
            (byte) (writeAccessLevel.ordinal() + 1),
            samChallenge,
            sfi,
            recordNumber,
            isExtendedModeRequired);

    // Add the "Open Secure Session" card command in first position.
    cardCommands.add(0, cmdCardOpenSession);

    isSessionOpen = true;

    // List of APDU requests to hold Open Secure Session and other optional commands
    List<ApduRequestSpi> apduRequests =
        new ArrayList<ApduRequestSpi>(getApduRequests(cardCommands));

    if (manageSecureSessionMap.isEmpty()) {
      executeCardCommandsForOpening(
          cardCommands, apduRequests, apduRequests.size(), cmdCardOpenSession);
    } else {
      // Note: inserting the open session command shifted the indexes.
      // Here we want to exclude the Manage Secure Session command.
      int toIndex = manageSecureSessionMap.get(manageSecureSessionMap.firstKey()).index + offset;
      executeCardCommandsForOpening(cardCommands, apduRequests, toIndex, cmdCardOpenSession);
      int lastIndex =
          executeCardCommandsWithManageSecureSession(
              cardCommands, apduRequests, toIndex, offset, ChannelControl.KEEP_OPEN);
      if (lastIndex < apduRequests.size()) {
        executeCardCommands(
            cardCommands, apduRequests, lastIndex, apduRequests.size(), ChannelControl.KEEP_OPEN);
      }
    }
  }

  /**
   * Executes commands containing at least one "Manage Secure Session" command.
   *
   * @param cardCommands The card commands.
   * @param apduRequests The APDU requests.
   * @param fromIndex Index of the first command to execute.
   * @param indexOffset Offset of the index to use to retrieve "Manage Secure Session" commands in
   *     the whole list.
   * @param channelControl The channel control to use.
   * @return The index of the next command to execute.
   */
  private int executeCardCommandsWithManageSecureSession(
      List<CardCommand> cardCommands,
      List<ApduRequestSpi> apduRequests,
      int fromIndex,
      int indexOffset,
      ChannelControl channelControl) {
    int lastIndex = fromIndex;
    for (ManageSecureSessionDto manageSecureSessionDto : manageSecureSessionMap.values()) {
      fromIndex =
          manageSecureSessionDto.index
              + indexOffset
              + 1; // Include the Manage Secure Session command
      if (manageSecureSessionDto.isEarlyMutualAuthenticationRequested) {
        finalizeManageSecureSessionCommand(
            apduRequests.get(manageSecureSessionDto.index + indexOffset));
        executeCardCommands(
            cardCommands, apduRequests, lastIndex, fromIndex, ChannelControl.KEEP_OPEN);
        checkCardSessionMac(
            (CmdCardManageSession) cardCommands.get(manageSecureSessionDto.index + indexOffset));
      } else {
        executeCardCommands(
            cardCommands, apduRequests, lastIndex, fromIndex, ChannelControl.KEEP_OPEN);
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
      lastIndex = fromIndex;
    }
    return lastIndex;
  }

  /** Aborts the secure session without raising any exception. */
  private void abortSecureSessionSilently() {
    if (isSessionOpen) {
      try {
        processCancel();
      } catch (RuntimeException e) {
        logger.warn(
            "An error occurred while aborting the current secure session: {}", e.getMessage());
      }
      isSessionOpen = false;
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

    if (manageSecureSessionMap.isEmpty()) {
      executeCardCommands(cardCommands, apduRequests, 0, apduRequests.size(), channelControl);
    } else {
      int lastIndex =
          executeCardCommandsWithManageSecureSession(
              cardCommands, apduRequests, 0, 0, ChannelControl.KEEP_OPEN);
      if (lastIndex < apduRequests.size()) {
        executeCardCommands(
            cardCommands, apduRequests, lastIndex, apduRequests.size(), ChannelControl.KEEP_OPEN);
      }
    }
  }

  /**
   * Finalizes the Manage Secure Session card command for mutual authentication request.
   *
   * @param apduRequest The APDU request to complete.
   */
  private void finalizeManageSecureSessionCommand(ApduRequestSpi apduRequest) {
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
   * @param cmdCardOpenSession The "Open Secure Session" card command.
   */
  private void executeCardCommandsForOpening(
      List<CardCommand> cardCommands,
      List<ApduRequestSpi> apduRequests,
      int toIndex,
      CmdCardOpenSession cmdCardOpenSession) {

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
    }

    // Build the "Digest Init" SAM command from card Open Session:

    // The card KIF/KVC (KVC may be null for card Rev 1.0)
    Byte cardKif = cmdCardOpenSession.getSelectedKif();
    Byte cardKvc = cmdCardOpenSession.getSelectedKvc();

    if (logger.isDebugEnabled()) {
      logger.debug(
          "processAtomicOpening => opening: CARD_CHALLENGE={}, CARD_KIF={}, CARD_KVC={}",
          HexUtil.toHex(cmdCardOpenSession.getCardChallenge()),
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

      if (apduRequests.size() == 0) {
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
      if (isSessionOpen) {
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
    CmdCardCloseSession cmdCardCloseSession =
        new CmdCardCloseSession(card, !isRatificationMechanismEnabled, terminalSessionMac);

    apduRequests.add(cmdCardCloseSession.getApduRequest());

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
    List<ApduResponseApi> apduResponses =
        cardResponse.getApduResponses(); // NOSONAR cardResponse is not null

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

    isSessionOpen = false;

    // Check the card's response to Close Secure Session
    try {
      cmdCardCloseSession.parseApduResponse(closeSecureSessionApduResponse);
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
          cmdCardCloseSession.getSignatureLo())) {
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
            cmdCardCloseSession.getPostponedData().get(svPostponedDataIndex))) {
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
          "The number of commands/responses does not match: nb commands = "
              + commands.size()
              + ", nb responses = "
              + apduResponses.size());
    }

    // We go through all the responses (and not the requests) because there may be fewer in the
    // case of an error that occurred in strict mode. In this case the last response will raise an
    // exception.
    for (int i = 0; i < apduResponses.size(); i++) {
      try {
        commands.get(i).parseApduResponse(apduResponses.get(i));
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
          "The number of commands/responses does not match: nb commands = "
              + commands.size()
              + ", nb responses = "
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
    if (isSessionOpen) {
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

    if (manageSecureSessionMap.isEmpty()) {
      executeCardCommandsForClosing(
          cardCommands,
          apduRequests,
          0,
          apduRequests.size(),
          channelControl,
          isRatificationMechanismEnabled);
    } else {
      int lastIndex =
          executeCardCommandsWithManageSecureSession(
              cardCommands, apduRequests, 0, 0, ChannelControl.KEEP_OPEN);
      executeCardCommandsForClosing(
          cardCommands,
          apduRequests,
          lastIndex,
          apduRequests.size(),
          channelControl,
          isRatificationMechanismEnabled);
    }
  }

  /**
   * (private)
   *
   * <p>Gets the value of the all counters of the designated file
   *
   * @param sfi The SFI of the EF containing the counter.
   * @param counters The list of expected counters.
   * @return A map containing the counters.
   * @throws IllegalStateException If one of the expected counter was found.
   */
  private Map<Integer, Integer> getCounterValues(int sfi, Set<Integer> counters) {
    ElementaryFile ef = card.getFileBySfi((byte) sfi);
    if (ef != null) {
      Map<Integer, Integer> allCountersValue = ef.getData().getAllCountersValue();
      if (allCountersValue.keySet().containsAll(counters)) {
        return allCountersValue;
      }
    }
    throw new IllegalStateException(
        "Anticipated response. Unable to determine anticipated value of counters in EF sfi " + sfi);
  }

  /**
   * Builds an anticipated response to an Increase/Decrease command.
   *
   * @param data The expected new counter value.
   * @return An {@link ApduResponseApi} containing the expected bytes.
   */
  private ApduResponseApi buildAnticipatedIncreaseDecreaseResponse(byte[] data) {
    // response = NNNNNN9000
    byte[] response = new byte[5];
    response[0] = data[0];
    response[1] = data[1];
    response[2] = data[2];
    response[3] = (byte) 0x90;
    response[4] = (byte) 0x00;
    return new ApduResponseAdapter(response);
  }

  /**
   * Builds an anticipated response to an Increase/Decrease Multiple command
   *
   * @param isDecreaseCommand True if it is a "Decrease Multiple" command, false if it is an
   *     "Increase Multiple" command.
   * @param counterNumberToCurrentValueMap The values of the counters currently known in the file.
   * @param counterNumberToIncDecValueMap The values to be decremented/incremented.
   * @return An {@link ApduResponseApi} containing the expected bytes.
   */
  private ApduResponseApi buildAnticipatedIncreaseDecreaseMultipleResponse(
      boolean isDecreaseCommand,
      Map<Integer, Integer> counterNumberToCurrentValueMap,
      Map<Integer, Integer> counterNumberToIncDecValueMap) {
    // response = CCVVVVVV..CCVVVVVV9000
    byte[] response = new byte[2 + (counterNumberToIncDecValueMap.size() * 4)];
    int index = 0;
    for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
      response[index] = entry.getKey().byteValue();
      int newCounterValue;
      if (isDecreaseCommand) {
        newCounterValue = counterNumberToCurrentValueMap.get(entry.getKey()) - entry.getValue();
      } else {
        newCounterValue = counterNumberToCurrentValueMap.get(entry.getKey()) + entry.getValue();
      }
      ByteArrayUtil.copyBytes(newCounterValue, response, index + 1, 3);
      index += 4;
    }
    response[index] = (byte) 0x90;
    response[index + 1] = (byte) 0x00;
    return new ApduResponseAdapter(response);
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
                  buildAnticipatedIncreaseDecreaseResponse(
                      ((CmdCardIncreaseOrDecrease) command).computeAnticipatedNewCounterValue()));
            }
            break;
          case INCREASE_MULTIPLE:
          case DECREASE_MULTIPLE:
            CmdCardIncreaseOrDecreaseMultiple cmd = (CmdCardIncreaseOrDecreaseMultiple) command;
            Map<Integer, Integer> counterNumberToIncDecValueMap =
                cmd.getCounterNumberToIncDecValueMap();
            apduResponses.add(
                buildAnticipatedIncreaseDecreaseMultipleResponse(
                    cmd.getCommandRef() == CardCommandRef.DECREASE_MULTIPLE,
                    getCounterValues(cmd.getSfi(), counterNumberToIncDecValueMap.keySet()),
                    counterNumberToIncDecValueMap));
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
   */
  @Override
  public CardTransactionManager processOpening(WriteAccessLevel writeAccessLevel) {
    try {
      checkNoSession();
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
            cardAtomicCommands.clear();
          }
        }
        cardAtomicCommands.add(command);
      }

      processAtomicOpening(cardAtomicCommands);

      // sets the flag indicating that the commands have been executed
      notifyCommandsProcessed();

      // CL-SV-1PCSS.1
      isSvOperationInsideSession = false;

      return this;

    } catch (RuntimeException e) {
      abortSecureSessionSilently();
      throw e;
    }
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
              cardAtomicCommands.clear();
            }
            processAtomicClosing(cardAtomicCommands, false, ChannelControl.KEEP_OPEN);
            processAtomicOpening(null);
            // Reset and update the buffer counter.
            modificationsCounter = card.getModificationsCounter();
            modificationsCounter -= computeCommandSessionBufferSize(command);
            isAtLeastOneReadCommand = false;
            // Clear the list.
            cardAtomicCommands.clear();
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
   */
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
    checkSymmetricCryptoTransactionManager();
    cryptoExtension.prepareComputeSignature(data);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public CardTransactionManager prepareVerifySignature(CommonSignatureVerificationData data) {
    checkSymmetricCryptoTransactionManager();
    cryptoExtension.prepareVerifySignature(data);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public CardTransactionManager processCommands() {
    finalizeSvCommandIfNeeded();
    prepareManageSecureSessionIfNeeded(isSessionOpen);
    if (isSessionOpen) {
      processCommandsInsideSession();
    } else {
      processCommandsOutsideSession();
    }
    return this;
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
   */
  @Override
  public CardTransactionManager processClosing() {
    try {
      checkSession();
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
              cardAtomicCommands.clear();
            }
            processAtomicClosing(cardAtomicCommands, false, ChannelControl.KEEP_OPEN);
            processAtomicOpening(null);
            // Reset and update the buffer counter.
            modificationsCounter = card.getModificationsCounter();
            modificationsCounter -= computeCommandSessionBufferSize(command);
            isAtLeastOneReadCommand = false;
            // Clear the list.
            cardAtomicCommands.clear();
          }
        } else {
          isAtLeastOneReadCommand = true;
        }
        cardAtomicCommands.add(command);
      }

      if (isAtLeastOneReadCommand) {
        processAtomicCardCommands(cardAtomicCommands, ChannelControl.KEEP_OPEN);
        cardAtomicCommands.clear();
        manageSecureSessionMap.clear();
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
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager processCancel() {

    checkSession();
    card.restoreFiles();

    // Build the card Close Session command (in "abort" mode since no signature is provided).
    CmdCardCloseSession cmdCardCloseSession = new CmdCardCloseSession(card);

    // card ApduRequestAdapter List to hold Close Secure Session command
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    apduRequests.add(cmdCardCloseSession.getApduRequest());

    // Transfer card commands
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, false);
    CardResponseApi cardResponse = transmitCardRequest(cardRequest, channelControl);
    try {
      cmdCardCloseSession.parseApduResponse(
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
    isSessionOpen = false;

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager processVerifyPin(byte[] pin) {
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
      prepareManageSecureSessionIfNeeded(isSessionOpen);

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
        byte[] cipheredPin;
        try {
          cipheredPin =
              symmetricCryptoTransactionManagerSpi.cipherPinForPresentation(
                  card.getCardChallenge(),
                  pin,
                  symmetricCryptoSecuritySetting.getPinVerificationCipheringKif(),
                  symmetricCryptoSecuritySetting.getPinVerificationCipheringKvc());
        } catch (SymmetricCryptoException e) {
          throw (RuntimeException) e.getCause();
        } catch (SymmetricCryptoIOException e) {
          throw (RuntimeException) e.getCause();
        }

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
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager processChangePin(byte[] newPin) {
    try {
      Assert.getInstance()
          .notNull(newPin, "newPin")
          .isEqual(newPin.length, CalypsoCardConstant.PIN_LENGTH, "PIN length");

      if (!card.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
      }

      if (isSessionOpen) {
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
        byte[] newPinData;
        try {
          newPinData =
              symmetricCryptoTransactionManagerSpi.cipherPinForModification(
                  card.getCardChallenge(),
                  currentPin,
                  newPin,
                  symmetricCryptoSecuritySetting.getPinModificationCipheringKif(),
                  symmetricCryptoSecuritySetting.getPinModificationCipheringKvc());
        } catch (SymmetricCryptoException e) {
          throw (RuntimeException) e.getCause();
        } catch (SymmetricCryptoIOException e) {
          throw (RuntimeException) e.getCause();
        }

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
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager processChangeKey(
      int keyIndex, byte newKif, byte newKvc, byte issuerKif, byte issuerKvc) {

    if (card.getProductType() == CalypsoCard.ProductType.BASIC) {
      throw new UnsupportedOperationException(
          "The 'Change Key' command is not available for this card.");
    }

    if (isSessionOpen) {
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
              card.getCardChallenge(), issuerKif, issuerKvc, newKif, newKvc);
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
   * Checks if a Secure Session is open, raises an exception if not
   *
   * @throws IllegalStateException if no session is open
   */
  private void checkSession() {
    if (!isSessionOpen) {
      throw new IllegalStateException("No session is open");
    }
  }

  /**
   * Checks if a Secure Session is not open, raises an exception if not
   *
   * @throws IllegalStateException if a session is open
   */
  private void checkNoSession() {
    if (isSessionOpen) {
      throw new IllegalStateException("Session is open");
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
   */
  @Override
  public CardTransactionManager prepareReleaseCardChannel() {
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
    if (!isExtendedModeRequired) {
      throw new UnsupportedOperationException(MSG_MANAGE_SECURE_SESSION_NOT_SUPPORTED);
    }
    ManageSecureSessionDto dto = getOrCreateManageSecureSessionDto();
    dto.isEarlyMutualAuthenticationRequested = true;
    dto.isEncryptionRequested = isEncryptionRequested;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public CardTransactionManager prepareActivateEncryption() {
    if (!isExtendedModeRequired) {
      throw new UnsupportedOperationException(MSG_MANAGE_SECURE_SESSION_NOT_SUPPORTED);
    }
    ManageSecureSessionDto dto = getOrCreateManageSecureSessionDto();
    dto.isEncryptionRequested = true;
    isEncryptionRequested = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public CardTransactionManager prepareDeactivateEncryption() {
    if (!isExtendedModeRequired) {
      throw new UnsupportedOperationException(MSG_MANAGE_SECURE_SESSION_NOT_SUPPORTED);
    }
    ManageSecureSessionDto dto = getOrCreateManageSecureSessionDto();
    dto.isEncryptionRequested = false;
    isEncryptionRequested = false;
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
    cardCommands.add(new CmdCardSelectFile(card, lid));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSelectFile(SelectFileControl selectFileControl) {

    Assert.getInstance().notNull(selectFileControl, "selectFileControl");

    // create the command and add it to the list of commands
    cardCommands.add(new CmdCardSelectFile(card, selectFileControl));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public CardTransactionManager prepareEarlyMutualAuthentication() {
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareGetData(GetDataTag tag) {

    Assert.getInstance().notNull(tag, "tag");

    // create the command and add it to the list of commands
    switch (tag) {
      case FCI_FOR_CURRENT_DF:
        cardCommands.add(new CmdCardGetDataFci(card));
        break;
      case FCP_FOR_CURRENT_FILE:
        cardCommands.add(new CmdCardGetDataFcp(card));
        break;
      case EF_LIST:
        cardCommands.add(new CmdCardGetDataEfList(card));
        break;
      case TRACEABILITY_INFORMATION:
        cardCommands.add(new CmdCardGetDataTraceabilityInformation(card));
        break;
      default:
        throw new UnsupportedOperationException("Unsupported Get Data tag: " + tag.name());
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

    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            recordNumber,
            CalypsoCardConstant.NB_REC_MIN,
            CalypsoCardConstant.NB_REC_MAX,
            RECORD_NUMBER);

    if (isSessionOpen && !((CardReader) cardReader).isContactless()) {
      throw new IllegalStateException(
          "Explicit record size is expected inside a secure session in contact mode.");
    }

    CmdCardReadRecords cmdCardReadRecords =
        new CmdCardReadRecords(card, sfi, recordNumber, CmdCardReadRecords.ReadMode.ONE_RECORD, 0);
    cardCommands.add(cmdCardReadRecords);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareReadRecords(
      byte sfi, int fromRecordNumber, int toRecordNumber, int recordSize) {

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
      // Creates N unitary "Read Records" commands
      for (int i = fromRecordNumber; i <= toRecordNumber; i++) {
        cardCommands.add(
            new CmdCardReadRecords(
                card, sfi, i, CmdCardReadRecords.ReadMode.ONE_RECORD, recordSize));
      }
    } else {
      // Manages the reading of multiple records taking into account the transmission capacity
      // of the card and the response format (2 extra bytes).
      // Multiple APDUs can be generated depending on record size and transmission capacity.
      final int nbBytesPerRecord = recordSize + 2;
      final int nbRecordsPerApdu = cardPayloadCapacity / nbBytesPerRecord;
      final int dataSizeMaxPerApdu = nbRecordsPerApdu * nbBytesPerRecord;

      int currentRecordNumber = fromRecordNumber;
      int nbRecordsRemainingToRead = toRecordNumber - fromRecordNumber + 1;
      int currentLength;

      while (currentRecordNumber < toRecordNumber) {
        currentLength =
            nbRecordsRemainingToRead <= nbRecordsPerApdu
                ? nbRecordsRemainingToRead * nbBytesPerRecord
                : dataSizeMaxPerApdu;

        cardCommands.add(
            new CmdCardReadRecords(
                card,
                sfi,
                currentRecordNumber,
                CmdCardReadRecords.ReadMode.MULTIPLE_RECORD,
                currentLength));

        currentRecordNumber += (currentLength / nbBytesPerRecord);
        nbRecordsRemainingToRead -= (currentLength / nbBytesPerRecord);
      }

      // Optimization: prepare a read "one record" if possible for last iteration.
      if (currentRecordNumber == toRecordNumber) {
        cardCommands.add(
            new CmdCardReadRecords(
                card,
                sfi,
                currentRecordNumber,
                CmdCardReadRecords.ReadMode.ONE_RECORD,
                recordSize));
      }
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

    final int nbRecordsPerApdu = cardPayloadCapacity / nbBytesToRead;

    int currentRecordNumber = fromRecordNumber;

    while (currentRecordNumber <= toRecordNumber) {
      cardCommands.add(
          new CmdCardReadRecordMultiple(
              card, sfi, (byte) currentRecordNumber, (byte) offset, (byte) nbBytesToRead));
      currentRecordNumber += nbRecordsPerApdu;
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
      cardCommands.add(new CmdCardReadBinary(card, sfi, 0, 1));
    }

    int currentLength;
    int currentOffset = offset;
    int nbBytesRemainingToRead = nbBytesToRead;
    do {
      currentLength = Math.min(nbBytesRemainingToRead, cardPayloadCapacity);

      cardCommands.add(new CmdCardReadBinary(card, sfi, currentOffset, currentLength));

      currentOffset += currentLength;
      nbBytesRemainingToRead -= currentLength;
    } while (nbBytesRemainingToRead > 0);

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

    cardCommands.add(new CmdCardSearchRecordMultiple(card, dataAdapter));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareAppendRecord(byte sfi, byte[] recordData) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .notNull(recordData, "recordData")
        .isInRange(recordData.length, 0, cardPayloadCapacity, "recordData.length");

    // create the command and add it to the list of commands
    cardCommands.add(new CmdCardAppendRecord(card, sfi, recordData));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareUpdateRecord(byte sfi, int recordNumber, byte[] recordData) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            recordNumber,
            CalypsoCardConstant.NB_REC_MIN,
            CalypsoCardConstant.NB_REC_MAX,
            RECORD_NUMBER)
        .notNull(recordData, "recordData")
        .isInRange(recordData.length, 0, cardPayloadCapacity, "recordData.length");

    // create the command and add it to the list of commands
    cardCommands.add(new CmdCardUpdateRecord(card, sfi, recordNumber, recordData));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareWriteRecord(byte sfi, int recordNumber, byte[] recordData) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            recordNumber,
            CalypsoCardConstant.NB_REC_MIN,
            CalypsoCardConstant.NB_REC_MAX,
            RECORD_NUMBER)
        .notNull(recordData, "recordData")
        .isInRange(recordData.length, 0, cardPayloadCapacity, "recordData.length");

    // create the command and add it to the list of commands
    cardCommands.add(new CmdCardWriteRecord(card, sfi, recordNumber, recordData));

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
      cardCommands.add(new CmdCardReadBinary(card, sfi, 0, 1));
    }

    final int dataLength = data.length;

    int currentLength;
    int currentOffset = offset;
    int currentIndex = 0;
    do {
      currentLength = Math.min(dataLength - currentIndex, cardPayloadCapacity);

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

    return this;
  }

  /** Factorisation of prepareDecreaseCounter and prepareIncreaseCounter. */
  private CardTransactionManager prepareIncreaseOrDecreaseCounter(
      boolean isDecreaseCommand, byte sfi, int counterNumber, int incDecValue) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            counterNumber, CalypsoCardConstant.NB_CNT_MIN, cardPayloadCapacity / 3, "counterNumber")
        .isInRange(
            incDecValue,
            CalypsoCardConstant.CNT_VALUE_MIN,
            CalypsoCardConstant.CNT_VALUE_MAX,
            "incDecValue");

    // create the command and add it to the list of commands
    cardCommands.add(
        new CmdCardIncreaseOrDecrease(isDecreaseCommand, card, sfi, counterNumber, incDecValue));

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

  /** Factorisation of prepareDecreaseMultipleCounters and prepareIncreaseMultipleCounters. */
  private CardTransactionManager prepareIncreaseOrDecreaseCounters(
      boolean isDecreaseCommand, byte sfi, Map<Integer, Integer> counterNumberToIncDecValueMap) {

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
      final int nbCountersPerApdu = cardPayloadCapacity / 4;
      if (counterNumberToIncDecValueMap.size() <= nbCountersPerApdu) {
        // create the command and add it to the list of commands
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
            cardCommands.add(
                new CmdCardIncreaseOrDecreaseMultiple(
                    isDecreaseCommand, card, sfi, new TreeMap<Integer, Integer>(map)));
            i = 0;
            map.clear();
          }
        }
        if (!map.isEmpty()) {
          cardCommands.add(
              new CmdCardIncreaseOrDecreaseMultiple(isDecreaseCommand, card, sfi, map));
        }
      }
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

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareCheckPinStatus() {
    if (!card.isPinFeatureAvailable()) {
      throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
    }
    // create the command and add it to the list of commands
    cardCommands.add(new CmdCardVerifyPin(card));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSvGet(SvOperation svOperation, SvAction svAction) {

    Assert.getInstance().notNull(svOperation, "svOperation").notNull(svAction, "svAction");

    if (!card.isSvFeatureAvailable()) {
      throw new UnsupportedOperationException("Stored Value is not available for this card.");
    }

    if (symmetricCryptoSecuritySetting.isSvLoadAndDebitLogEnabled() && (!isExtendedModeRequired)) {
      // @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit logs are requested
      // for a non rev3.2 card add two SvGet commands (for RELOAD then for DEBIT).
      // CL-SV-GETNUMBER.1
      SvOperation operation1 =
          SvOperation.RELOAD.equals(svOperation) ? SvOperation.DEBIT : SvOperation.RELOAD;
      addStoredValueCommand(new CmdCardSvGet(card, operation1, false), operation1);
    }
    addStoredValueCommand(new CmdCardSvGet(card, svOperation, isExtendedModeRequired), svOperation);
    this.svAction = svAction;

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSvReload(int amount, byte[] date, byte[] time, byte[] free) {

    checkSvInsideSession();

    // create the initial command with the application data
    CmdCardSvReload svReloadCmdBuild =
        new CmdCardSvReload(card, amount, date, time, free, isExtendedModeRequired);

    // create and keep the CalypsoCardCommand
    addStoredValueCommand(svReloadCmdBuild, SvOperation.RELOAD);

    return this;
  }

  /**
   * Checks if only one modifying SV command is prepared inside the current secure session.
   *
   * @throws IllegalStateException If more than SV command is prepared.
   */
  private void checkSvInsideSession() {
    // CL-SV-1PCSS.1
    if (isSessionOpen) {
      if (!isSvOperationInsideSession) {
        isSvOperationInsideSession = true;
      } else {
        throw new IllegalStateException("Only one SV operation is allowed per Secure Session.");
      }
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSvReload(int amount) {
    final byte[] zero = {0x00, 0x00};
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

    checkSvInsideSession();

    if (svAction == SvAction.DO
        && !symmetricCryptoSecuritySetting.isSvNegativeBalanceAuthorized()
        && (card.getSvBalance() - amount) < 0) {
      throw new IllegalStateException("Negative balances not allowed.");
    }

    // create the initial command with the application data
    CmdCardSvDebitOrUndebit command =
        new CmdCardSvDebitOrUndebit(
            svAction == SvAction.DO, card, amount, date, time, isExtendedModeRequired);

    // create and keep the CalypsoCardCommand
    addStoredValueCommand(command, SvOperation.DEBIT);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareSvDebit(int amount) {
    final byte[] zero = {0x00, 0x00};
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
    if (!card.isSvFeatureAvailable()) {
      throw new UnsupportedOperationException("Stored Value is not available for this card.");
    }
    if (card.getApplicationSubtype() != CalypsoCardConstant.STORED_VALUE_FILE_STRUCTURE_ID) {
      throw new UnsupportedOperationException(
          "The currently selected application is not an SV application.");
    }
    // reset SV data in CalypsoCard if any
    card.setSvData((byte) 0, null, null, 0, 0, null, null);
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

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareInvalidate() {
    if (card.isDfInvalidated()) {
      throw new IllegalStateException("This card is already invalidated.");
    }
    cardCommands.add(new CmdCardInvalidate(card));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager prepareRehabilitate() {
    if (!card.isDfInvalidated()) {
      throw new IllegalStateException("This card is not invalidated.");
    }
    cardCommands.add(new CmdCardRehabilitate(card));

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
        if (!cardCommands.isEmpty()) {
          throw new IllegalStateException(
              "This SV command can only be placed in the first position in the list of prepared commands");
        }
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
  private List<ApduRequestSpi> getApduRequests(List<CardCommand> commands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    if (commands != null) {
      for (CardCommand command : commands) {
        apduRequests.add(command.getApduRequest());
      }
    }
    return apduRequests;
  }

  /** Adapter of {@link ApduResponseApi} used to create anticipated card responses. */
  private static class ApduResponseAdapter implements ApduResponseApi {

    private final byte[] apdu;
    private final int statusWord;

    /** Constructor */
    public ApduResponseAdapter(byte[] apdu) {
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
      return Arrays.copyOfRange(this.apdu, 0, this.apdu.length - 2);
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

  private class ManageSecureSessionDto {
    private int index;
    private boolean isEarlyMutualAuthenticationRequested;
    private boolean isEncryptionRequested;
  }
}
