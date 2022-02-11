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

import java.util.*;
import org.calypsonet.terminal.calypso.GetDataTag;
import org.calypsonet.terminal.calypso.SelectFileControl;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.transaction.*;
import org.calypsonet.terminal.card.*;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.calypsonet.terminal.reader.CardReader;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
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
 * </ul>
 *
 * @since 2.0.0
 */
class CardTransactionManagerAdapter implements CardTransactionManager {

  private static final Logger logger = LoggerFactory.getLogger(CardTransactionManagerAdapter.class);
  private static final String PATTERN_1_BYTE_HEX = "%02Xh";

  /* prefix/suffix used to compose exception messages */
  private static final String CARD_READER_COMMUNICATION_ERROR =
      "A communication error with the card reader occurred while ";
  private static final String CARD_COMMUNICATION_ERROR =
      "A communication error with the card occurred while ";
  private static final String CARD_COMMAND_ERROR = "A card command error occurred while ";
  private static final String SAM_READER_COMMUNICATION_ERROR =
      "A communication error with the SAM reader occurred while ";
  private static final String SAM_COMMUNICATION_ERROR =
      "A communication error with the SAM occurred while ";
  private static final String SAM_COMMAND_ERROR = "A SAM command error occurred while ";
  private static final String PIN_NOT_AVAILABLE_ERROR = "PIN is not available for this card.";
  private static final String GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR =
      "generating of the PIN ciphered data.";
  private static final String GENERATING_OF_THE_KEY_CIPHERED_DATA_ERROR =
      "generating of the key ciphered data.";
  private static final String TRANSMITTING_COMMANDS = "transmitting commands.";
  private static final String CHECKING_THE_SV_OPERATION = "checking the SV operation.";
  private static final String RECORD_NUMBER = "recordNumber";
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
  private final CalypsoCardAdapter calypsoCard;
  private final CardCommandManager cardCommandManager = new CardCommandManager();
  private final CardSecuritySettingAdapter cardSecuritySetting;
  private final SamCommandProcessor samCommandProcessor;
  private final List<byte[]> transactionAuditData = new ArrayList<byte[]>();

  /* Dynamic fields */
  private ChannelControl channelControl;
  private SessionState sessionState;
  private int modificationsCounter;
  private WriteAccessLevel currentWriteAccessLevel;
  private SvAction svAction;
  private boolean isSvOperationInsideSession;

  private enum SessionState {
    /** Initial state of a card transaction. The card must have been previously selected. */
    SESSION_UNINITIALIZED,
    /** The secure session is active. */
    SESSION_OPEN,
    /** The secure session is closed. */
    SESSION_CLOSED
  }

  /**
   * (package-private)<br>
   * Creates an instance of {@link CardTransactionManager} for secure operations.
   *
   * <p>Secure operations are enabled by the presence of {@link CardSecuritySetting}.
   *
   * @param cardReader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @param cardSecuritySetting The security settings.
   * @since 2.0.0
   */
  CardTransactionManagerAdapter(
      CardReader cardReader,
      CalypsoCard calypsoCard,
      CardSecuritySettingAdapter cardSecuritySetting) {

    this.cardReader = (ProxyReaderApi) cardReader;
    this.calypsoCard = (CalypsoCardAdapter) calypsoCard;
    this.cardSecuritySetting = cardSecuritySetting;
    this.samCommandProcessor =
        new SamCommandProcessor(calypsoCard, cardSecuritySetting, transactionAuditData);

    this.modificationsCounter = this.calypsoCard.getModificationsCounter();
    this.channelControl = ChannelControl.KEEP_OPEN;
    this.sessionState = SessionState.SESSION_UNINITIALIZED;
  }

  /**
   * (package-private)<br>
   * Creates an instance of {@link CardTransactionManager} for non-secure operations.
   *
   * @param cardReader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @since 2.0.0
   */
  CardTransactionManagerAdapter(CardReader cardReader, CalypsoCard calypsoCard) {

    this.cardReader = (ProxyReaderApi) cardReader;
    this.calypsoCard = (CalypsoCardAdapter) calypsoCard;
    this.cardSecuritySetting = null;
    this.samCommandProcessor = null;

    this.modificationsCounter = this.calypsoCard.getModificationsCounter();
    this.channelControl = ChannelControl.KEEP_OPEN;
    this.sessionState = SessionState.SESSION_UNINITIALIZED;
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
    return calypsoCard;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSecuritySetting getCardSecuritySetting() {
    return cardSecuritySetting;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.1
   */
  @Override
  public List<byte[]> getTransactionAuditData() {
    // CL-CSS-INFODATA.1
    return transactionAuditData;
  }

  /**
   * (private)<br>
   * Open a single Secure Session.
   *
   * @param writeAccessLevel access level of the session (personalization, load or debit).
   * @param cardCommands the card commands inside session.
   * @throws IllegalStateException if no {@link CardSecuritySetting} is available.
   * @throws CardTransactionException if a functional error occurs (including card and SAM IO
   *     errors).
   */
  private void processAtomicOpening(
      WriteAccessLevel writeAccessLevel, List<AbstractCardCommand> cardCommands) {

    if (cardSecuritySetting == null) {
      throw new IllegalStateException("No security settings are available.");
    }

    calypsoCard.backupFiles();

    if (cardCommands == null) {
      cardCommands = new ArrayList<AbstractCardCommand>();
    }

    // Let's check if we have a read record command at the top of the command list.
    // If so, then the command is withdrawn in favour of its equivalent executed at the same
    // time as the open secure session command.
    // The sfi and record number to be read when the open secure session command is executed.
    // The default value is 0 (no record to read) but we will optimize the exchanges if a read
    // record command has been prepared.
    int sfi = 0;
    int recordNumber = 0;
    if (!cardCommands.isEmpty()) {
      AbstractCardCommand cardCommand = cardCommands.get(0);
      if (cardCommand.getCommandRef() == CalypsoCardCommand.READ_RECORDS
          && ((CmdCardReadRecords) cardCommand).getReadMode()
              == CmdCardReadRecords.ReadMode.ONE_RECORD) {
        sfi = ((CmdCardReadRecords) cardCommand).getSfi();
        recordNumber = ((CmdCardReadRecords) cardCommand).getFirstRecordNumber();
        cardCommands.remove(0);
      }
    }

    // Compute the SAM challenge
    byte[] samChallenge = getSamChallenge();

    // Build the "Open Secure Session" card command.
    CmdCardOpenSession cmdCardOpenSession =
        new CmdCardOpenSession(
            calypsoCard.getProductType(),
            (byte) (writeAccessLevel.ordinal() + 1),
            samChallenge,
            sfi,
            recordNumber,
            isExtendedModeAllowed());

    // Add the "Open Secure Session" card command in first position.
    cardCommands.add(0, cmdCardOpenSession);

    // List of APDU requests to hold Open Secure Session and other optional commands
    List<ApduRequestSpi> apduRequests =
        new ArrayList<ApduRequestSpi>(getApduRequests(cardCommands));

    // Wrap the list of C-APDUs into a card request
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, true);

    sessionState = SessionState.SESSION_OPEN;

    // Open a secure session, transmit the commands to the card and keep channel open
    CardResponseApi cardResponse = transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);

    // Retrieve the list of R-APDUs
    List<ApduResponseApi> apduResponses =
        cardResponse.getApduResponses(); // NOSONAR cardResponse is not null

    // Parse all the responses and fills the CalypsoCard object with the command data.
    try {
      CalypsoCardUtilAdapter.updateCalypsoCard(calypsoCard, cardCommands, apduResponses, true);
    } catch (CardCommandException e) {
      throw new CardAnomalyException(
          CARD_COMMAND_ERROR
              + "processing the response to open session: "
              + e.getCommand()
              + getTransactionAuditDataAsString(),
          e);
    } catch (DesynchronizedExchangesException e) {
      throw new DesynchronizedExchangesException(
          e.getMessage() + getTransactionAuditDataAsString());
    }

    // Build the "Digest Init" SAM command from card Open Session:

    // The card KIF/KVC (KVC may be null for card Rev 1.0)
    Byte cardKif = cmdCardOpenSession.getSelectedKif();
    Byte cardKvc = cmdCardOpenSession.getSelectedKvc();

    if (logger.isDebugEnabled()) {
      logger.debug(
          "processAtomicOpening => opening: CARDCHALLENGE={}, CARDKIF={}, CARDKVC={}",
          ByteArrayUtil.toHex(cmdCardOpenSession.getCardChallenge()),
          cardKif != null ? String.format(PATTERN_1_BYTE_HEX, cardKif) : null,
          cardKvc != null ? String.format(PATTERN_1_BYTE_HEX, cardKvc) : null);
    }

    Byte kvc = samCommandProcessor.computeKvc(writeAccessLevel, cardKvc);
    Byte kif = samCommandProcessor.computeKif(writeAccessLevel, cardKif, kvc);

    if (!cardSecuritySetting.isSessionKeyAuthorized(kif, kvc)) {
      throw new UnauthorizedKeyException(
          String.format(
              "Unauthorized key error: KIF=%s, KVC=%s %s",
              kif != null ? String.format(PATTERN_1_BYTE_HEX, kif) : null,
              kvc != null ? String.format(PATTERN_1_BYTE_HEX, kvc) : null,
              getTransactionAuditDataAsString()));
    }

    // Initialize the digest processor. It will store all digest operations (Digest Init, Digest
    // Update) until the session closing. At this moment, all SAM Apdu will be processed at
    // once.
    samCommandProcessor.initializeDigester(
        false, false, kif, kvc, apduResponses.get(0).getDataOut());

    // Add all commands data to the digest computation. The first command in the list is the
    // open secure session command. This command is not included in the digest computation, so
    // we skip it and start the loop at index 1.
    // Add requests and responses to the digest processor
    samCommandProcessor.pushCardExchangedData(apduRequests, apduResponses, 1);
  }

  /**
   * (private)<br>
   * Aborts the secure session without raising any exception.
   */
  private void abortSecureSessionSilently() {
    if (sessionState == SessionState.SESSION_OPEN) {
      try {
        processCancel();
      } catch (RuntimeException e) {
        logger.error("An error occurred while aborting the current secure session.", e);
      }
      sessionState = SessionState.SESSION_CLOSED;
    }
  }

  /**
   * Create an ApduRequestAdapter List from a AbstractCardCommand List.
   *
   * @param cardCommands a list of card commands.
   * @return An empty list if there is no command.
   */
  private List<ApduRequestSpi> getApduRequests(List<AbstractCardCommand> cardCommands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    if (cardCommands != null) {
      for (AbstractCardCommand command : cardCommands) {
        apduRequests.add(command.getApduRequest());
      }
    }
    return apduRequests;
  }

  /**
   * (private)<br>
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
   * @throws CardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processAtomicCardCommands(
      List<AbstractCardCommand> cardCommands, ChannelControl channelControl) {

    // Get the list of C-APDU to transmit
    List<ApduRequestSpi> apduRequests = getApduRequests(cardCommands);

    // Wrap the list of C-APDUs into a card request
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, true);

    // Transmit the commands to the card
    CardResponseApi cardResponse = transmitCardRequest(cardRequest, channelControl);

    // Retrieve the list of R-APDUs
    List<ApduResponseApi> apduResponses =
        cardResponse.getApduResponses(); // NOSONAR cardResponse is not null

    // If this method is invoked within a secure session, then add all commands data to the digest
    // computation.
    if (sessionState == SessionState.SESSION_OPEN) {
      samCommandProcessor.pushCardExchangedData(apduRequests, apduResponses, 0);
    }

    try {
      CalypsoCardUtilAdapter.updateCalypsoCard(
          calypsoCard, cardCommands, apduResponses, sessionState == SessionState.SESSION_OPEN);
    } catch (CardCommandException e) {
      throw new CardAnomalyException(
          CARD_COMMAND_ERROR
              + "processing responses to card commands: "
              + e.getCommand()
              + getTransactionAuditDataAsString(),
          e);
    } catch (DesynchronizedExchangesException e) {
      throw new DesynchronizedExchangesException(
          e.getMessage() + getTransactionAuditDataAsString());
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
   * @throws CardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processAtomicClosing(
      List<AbstractCardCommand> cardCommands,
      boolean isRatificationMechanismEnabled,
      ChannelControl channelControl) {

    if (cardCommands == null) {
      cardCommands = new ArrayList<AbstractCardCommand>(0);
    }

    // Get the list of C-APDU to transmit
    List<ApduRequestSpi> apduRequests = getApduRequests(cardCommands);

    // Build the expected APDU responses of the card commands
    List<ApduResponseApi> expectedApduResponses = buildAnticipatedResponses(cardCommands);

    // Add all commands data to the digest computation: commands and expected responses.
    samCommandProcessor.pushCardExchangedData(apduRequests, expectedApduResponses, 0);

    // All SAM digest operations will now run at once.
    // Get Terminal Signature from the latest response.
    byte[] sessionTerminalSignature = getSessionTerminalSignature();

    // Build the last "Close Secure Session" card command.
    CmdCardCloseSession cmdCardCloseSession =
        new CmdCardCloseSession(
            calypsoCard, !isRatificationMechanismEnabled, sessionTerminalSignature);

    apduRequests.add(cmdCardCloseSession.getApduRequest());

    // Add the card Ratification command if any
    boolean isRatificationCommandAdded;
    if (isRatificationMechanismEnabled && ((CardReader) cardReader).isContactless()) {
      // CL-RAT-CMD.1
      // CL-RAT-DELAY.1
      // CL-RAT-NXTCLOSE.1
      apduRequests.add(CmdCardRatificationBuilder.getApduRequest(calypsoCard.getCardClass()));
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
      CalypsoCardUtilAdapter.updateCalypsoCard(calypsoCard, cardCommands, apduResponses, true);
    } catch (CardCommandException e) {
      throw new CardAnomalyException(
          CARD_COMMAND_ERROR
              + "processing of responses preceding the close of the session: "
              + e.getCommand()
              + getTransactionAuditDataAsString(),
          e);
    } catch (DesynchronizedExchangesException e) {
      throw new DesynchronizedExchangesException(
          e.getMessage() + getTransactionAuditDataAsString());
    }

    sessionState = SessionState.SESSION_CLOSED;

    // Check the card's response to Close Secure Session
    try {
      CalypsoCardUtilAdapter.updateCalypsoCard(
          calypsoCard, cmdCardCloseSession, closeSecureSessionApduResponse, false);
    } catch (CardSecurityDataException e) {
      throw new CardCloseSecureSessionException(
          "Invalid card session" + getTransactionAuditDataAsString(), e);
    } catch (CardCommandException e) {
      throw new CardAnomalyException(
          CARD_COMMAND_ERROR
              + "processing the response to close session: "
              + e.getCommand()
              + getTransactionAuditDataAsString(),
          e);
    }

    // Check the card signature
    // CL-CSS-MACVERIF.1
    checkCardSignature(cmdCardCloseSession.getSignatureLo());

    // If necessary, we check the status of the SV after the session has been successfully
    // closed.
    // CL-SV-POSTPON.1
    if (cardCommandManager.isSvOperationCompleteOneTime()) {
      checkSvOperationStatus(cmdCardCloseSession.getPostponedData());
    }
  }

  /**
   * (private)
   *
   * <p>Gets the value of the designated counter
   *
   * @param sfi the SFI of the EF containing the counter.
   * @param counter the number of the counter.
   * @return The value of the counter
   * @throws IllegalStateException If the counter is not found.
   */
  private int getCounterValue(int sfi, int counter) {
    ElementaryFile ef = calypsoCard.getFileBySfi((byte) sfi);
    if (ef != null) {
      Integer counterValue = ef.getData().getContentAsCounterValue(counter);
      if (counterValue != null) {
        return counterValue;
      }
    }
    throw new IllegalStateException(
        "Anticipated response. Unable to determine anticipated value of counter "
            + counter
            + " in EF sfi "
            + sfi);
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
    ElementaryFile ef = calypsoCard.getFileBySfi((byte) sfi);
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
   * Builds an anticipated response to an Increase/Decrease command
   *
   * @param isDecreaseCommand True if it is a "Decrease" command, false if it is an * "Increase"
   *     command.
   * @param currentCounterValue The current counter value.
   * @param incDecValue The increment/decrement value.
   * @return An {@link ApduResponseApi} containing the expected bytes
   */
  private ApduResponseApi buildAnticipatedIncreaseDecreaseResponse(
      boolean isDecreaseCommand, int currentCounterValue, int incDecValue) {
    int newValue =
        isDecreaseCommand ? currentCounterValue - incDecValue : currentCounterValue + incDecValue;
    // response = NNNNNN9000
    byte[] response = new byte[5];
    response[0] = (byte) ((newValue & 0x00FF0000) >> 16);
    response[1] = (byte) ((newValue & 0x0000FF00) >> 8);
    response[2] = (byte) (newValue & 0x000000FF);
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
      response[index + 1] = (byte) ((newCounterValue & 0x00FF0000) >> 16);
      response[index + 2] = (byte) ((newCounterValue & 0x0000FF00) >> 8);
      response[index + 3] = (byte) (newCounterValue & 0x000000FF);
      index += 4;
    }
    response[index] = (byte) 0x90;
    response[index + 1] = (byte) 0x00;
    return new ApduResponseAdapter(response);
  }

  /**
   * (private)<br>
   * Builds the anticipated expected responses to the commands sent in processClosing.<br>
   * These commands are supposed to be "modifying commands" only.
   *
   * @param cardCommands the list of card commands sent.
   * @return An empty list if there is no command.
   * @throws IllegalStateException if the anticipation process failed
   */
  private List<ApduResponseApi> buildAnticipatedResponses(List<AbstractCardCommand> cardCommands) {
    List<ApduResponseApi> apduResponses = new ArrayList<ApduResponseApi>();
    if (cardCommands != null) {
      for (AbstractCardCommand command : cardCommands) {
        switch (command.getCommandRef()) {
          case INCREASE:
          case DECREASE:
            CmdCardIncreaseOrDecrease cmdA = (CmdCardIncreaseOrDecrease) command;
            apduResponses.add(
                buildAnticipatedIncreaseDecreaseResponse(
                    cmdA.getCommandRef() == CalypsoCardCommand.DECREASE,
                    getCounterValue(cmdA.getSfi(), cmdA.getCounterNumber()),
                    cmdA.getIncDecValue()));
            break;
          case INCREASE_MULTIPLE:
          case DECREASE_MULTIPLE:
            CmdCardIncreaseOrDecreaseMultiple cmdB = (CmdCardIncreaseOrDecreaseMultiple) command;
            Map<Integer, Integer> counterNumberToIncDecValueMap =
                cmdB.getCounterNumberToIncDecValueMap();
            apduResponses.add(
                buildAnticipatedIncreaseDecreaseMultipleResponse(
                    cmdB.getCommandRef() == CalypsoCardCommand.DECREASE_MULTIPLE,
                    getCounterValues(cmdB.getSfi(), counterNumberToIncDecValueMap.keySet()),
                    counterNumberToIncDecValueMap));
            break;
          case SV_RELOAD:
          case SV_DEBIT:
          case SV_UNDEBIT:
            apduResponses.add(RESPONSE_OK_POSTPONED);
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
  public final CardTransactionManager processOpening(WriteAccessLevel writeAccessLevel) {
    try {
      checkSessionNotOpen();

      // CL-KEY-INDEXPO.1
      currentWriteAccessLevel = writeAccessLevel;

      // Create a sublist of AbstractCardCommand to be sent atomically
      List<AbstractCardCommand> cardAtomicCommands = new ArrayList<AbstractCardCommand>();

      for (AbstractCardCommand command : cardCommandManager.getCardCommands()) {
        // Check if the command is a modifying command.
        if (command.isSessionBufferUsed()) {
          modificationsCounter -= computeCommandSessionBufferSize(command);
          if (modificationsCounter < 0) {
            checkMultipleSessionEnabled(command);
            // Process an intermediate secure session with the current commands.
            processAtomicOpening(currentWriteAccessLevel, cardAtomicCommands);
            processAtomicClosing(null, false, ChannelControl.KEEP_OPEN);
            // Reset and update the buffer counter.
            modificationsCounter = calypsoCard.getModificationsCounter();
            modificationsCounter -= computeCommandSessionBufferSize(command);
            // Clear the list.
            cardAtomicCommands.clear();
          }
        }
        cardAtomicCommands.add(command);
      }

      processAtomicOpening(currentWriteAccessLevel, cardAtomicCommands);

      // sets the flag indicating that the commands have been executed
      cardCommandManager.notifyCommandsProcessed();

      // CL-SV-1PCSS.1
      isSvOperationInsideSession = false;

      return this;

    } catch (RuntimeException e) {
      abortSecureSessionSilently();
      throw e;
    }
  }

  /**
   * (private)<br>
   * Throws an exception if the multiple session is not enabled.
   *
   * @param command The command.
   * @throws AtomicTransactionException If the multiple session is not allowed.
   */
  private void checkMultipleSessionEnabled(AbstractCardCommand command) {
    // CL-CSS-REQUEST.1
    // CL-CSS-SMEXCEED.1
    // CL-CSS-INFOCSS.1
    if (!cardSecuritySetting.isMultipleSessionEnabled()) {
      throw new AtomicTransactionException(
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
   *
   * @param channelControl indicates if the card channel of the card reader must be closed after the
   *     last command.
   * @throws CardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processCardCommandsOutOfSession(ChannelControl channelControl) {

    // card commands sent outside a Secure Session. No modifications buffer limitation.
    processAtomicCardCommands(cardCommandManager.getCardCommands(), channelControl);

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();

    // If an SV transaction was performed, we check the signature returned by the card here
    if (cardCommandManager.isSvOperationCompleteOneTime()) {
      try {
        samCommandProcessor.checkSvStatus(calypsoCard.getSvOperationSignature());
      } catch (CalypsoSamSecurityDataException e) {
        throw new SvAuthenticationException(
            "The checking of the SV operation by the SAM has failed."
                + getTransactionAuditDataAsString(),
            e);
      } catch (CalypsoSamCommandException e) {
        throw new SamAnomalyException(
            SAM_COMMAND_ERROR
                + "checking the SV operation: "
                + e.getCommand().getName()
                + getTransactionAuditDataAsString(),
            e);
      } catch (ReaderBrokenCommunicationException e) {
        throw new SvAuthenticationException(
            SAM_READER_COMMUNICATION_ERROR
                + CHECKING_THE_SV_OPERATION
                + getTransactionAuditDataAsString(),
            e);
      } catch (CardBrokenCommunicationException e) {
        throw new SvAuthenticationException(
            SAM_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION + getTransactionAuditDataAsString(),
            e);
      } catch (DesynchronizedExchangesException e) {
        throw new DesynchronizedExchangesException(
            e.getMessage() + getTransactionAuditDataAsString());
      }
    }
  }

  /**
   * Process all prepared card commands in a Secure Session.
   *
   * <p>The multiple session mode is handled according to the session settings.
   *
   * @throws CardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processCardCommandsInSession() {
    try {
      // A session is open, we have to care about the card modifications buffer
      List<AbstractCardCommand> cardAtomicCommands = new ArrayList<AbstractCardCommand>();
      boolean isAtLeastOneReadCommand = false;

      for (AbstractCardCommand command : cardCommandManager.getCardCommands()) {
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
            processAtomicOpening(currentWriteAccessLevel, null);
            // Reset and update the buffer counter.
            modificationsCounter = calypsoCard.getModificationsCounter();
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
      cardCommandManager.notifyCommandsProcessed();

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
  public final CardTransactionManager processCardCommands() {
    if (sessionState == SessionState.SESSION_OPEN) {
      processCardCommandsInSession();
    } else {
      processCardCommandsOutOfSession(channelControl);
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager processClosing() {
    try {
      checkSessionOpen();

      List<AbstractCardCommand> cardAtomicCommands = new ArrayList<AbstractCardCommand>();
      boolean isAtLeastOneReadCommand = false;

      for (AbstractCardCommand command : cardCommandManager.getCardCommands()) {
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
            processAtomicOpening(currentWriteAccessLevel, null);
            // Reset and update the buffer counter.
            modificationsCounter = calypsoCard.getModificationsCounter();
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
      }

      processAtomicClosing(
          cardAtomicCommands, cardSecuritySetting.isRatificationMechanismEnabled(), channelControl);

      // sets the flag indicating that the commands have been executed
      cardCommandManager.notifyCommandsProcessed();

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
  public final CardTransactionManager processCancel() {

    checkSessionOpen();
    calypsoCard.restoreFiles();

    // Build the card Close Session command (in "abort" mode since no signature is provided).
    CmdCardCloseSession cmdCardCloseSession = new CmdCardCloseSession(calypsoCard);

    // card ApduRequestAdapter List to hold Close Secure Session command
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    apduRequests.add(cmdCardCloseSession.getApduRequest());

    // Transfer card commands
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, false);
    CardResponseApi cardResponse = transmitCardRequest(cardRequest, channelControl);
    try {
      cmdCardCloseSession
          .setApduResponse(
              cardResponse.getApduResponses().get(0)) // NOSONAR cardResponse is not null
          .checkStatus();
    } catch (CardCommandException e) {
      throw new CardAnomalyException(
          CARD_COMMAND_ERROR
              + "processing the response to close session: "
              + e.getCommand()
              + getTransactionAuditDataAsString(),
          e);
    }

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();

    // session is now considered closed regardless the previous state or the result of the abort
    // session command sent to the card.
    sessionState = SessionState.SESSION_CLOSED;

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager processVerifyPin(byte[] pin) {
    try {
      Assert.getInstance()
          .notNull(pin, "pin")
          .isEqual(pin.length, CalypsoCardConstant.PIN_LENGTH, "PIN length");

      if (!calypsoCard.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(PIN_NOT_AVAILABLE_ERROR);
      }

      if (cardCommandManager.hasCommands()) {
        throw new IllegalStateException(
            "No commands should have been prepared prior to a PIN submission.");
      }

      // CL-PIN-PENCRYPT.1
      if (cardSecuritySetting != null && !cardSecuritySetting.isPinPlainTransmissionEnabled()) {

        // CL-PIN-GETCHAL.1
        cardCommandManager.addRegularCommand(new CmdCardGetChallenge(calypsoCard.getCardClass()));

        // transmit and receive data with the card
        processAtomicCardCommands(cardCommandManager.getCardCommands(), ChannelControl.KEEP_OPEN);

        // sets the flag indicating that the commands have been executed
        cardCommandManager.notifyCommandsProcessed();

        // Get the encrypted PIN with the help of the SAM
        byte[] cipheredPin = getSamCipherPinData(pin, null);

        cardCommandManager.addRegularCommand(
            new CmdCardVerifyPin(calypsoCard.getCardClass(), true, cipheredPin));
      } else {
        cardCommandManager.addRegularCommand(
            new CmdCardVerifyPin(calypsoCard.getCardClass(), false, pin));
      }

      // transmit and receive data with the card
      processAtomicCardCommands(cardCommandManager.getCardCommands(), channelControl);

      // sets the flag indicating that the commands have been executed
      cardCommandManager.notifyCommandsProcessed();

      return this;

    } catch (RuntimeException e) {
      abortSecureSessionSilently();
      throw e;
    }
  }

  /**
   * (private)<br>
   * Returns the cipher PIN data from the SAM (ciphered PIN transmission or PIN change).
   *
   * @param currentPin The current PIN.
   * @param newPin The new PIN, or null in case of a PIN presentation.
   * @return A not null array.
   * @throws SamIOException If the communication with the SAM or the SAM reader failed (only for SV
   *     operations).
   * @throws SamAnomalyException If a SAM error occurs (only for SV operations).
   */
  private byte[] getSamCipherPinData(byte[] currentPin, byte[] newPin) {
    try {
      return samCommandProcessor.getCipheredPinData(
          calypsoCard.getCardChallenge(), currentPin, newPin);
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR
              + "generating of the PIN ciphered data: "
              + e.getCommand().getName()
              + getTransactionAuditDataAsString(),
          e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR
              + GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR
              + getTransactionAuditDataAsString(),
          e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_COMMUNICATION_ERROR
              + GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR
              + getTransactionAuditDataAsString(),
          e);
    } catch (DesynchronizedExchangesException e) {
      throw new DesynchronizedExchangesException(
          e.getMessage() + getTransactionAuditDataAsString());
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

      if (!calypsoCard.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(PIN_NOT_AVAILABLE_ERROR);
      }

      if (sessionState == SessionState.SESSION_OPEN) {
        throw new IllegalStateException("'Change PIN' not allowed when a secure session is open.");
      }

      // CL-PIN-MENCRYPT.1
      if (cardSecuritySetting.isPinPlainTransmissionEnabled()) {
        // transmission in plain mode
        if (calypsoCard.getPinAttemptRemaining() >= 0) {
          cardCommandManager.addRegularCommand(
              new CmdCardChangePin(calypsoCard.getCardClass(), newPin));
        }
      } else {
        // CL-PIN-GETCHAL.1
        cardCommandManager.addRegularCommand(new CmdCardGetChallenge(calypsoCard.getCardClass()));

        // transmit and receive data with the card
        processAtomicCardCommands(cardCommandManager.getCardCommands(), ChannelControl.KEEP_OPEN);

        // sets the flag indicating that the commands have been executed
        cardCommandManager.notifyCommandsProcessed();

        // Get the encrypted PIN with the help of the SAM
        byte[] currentPin = new byte[4]; // all zeros as required
        byte[] newPinData = getSamCipherPinData(currentPin, newPin);

        cardCommandManager.addRegularCommand(
            new CmdCardChangePin(calypsoCard.getCardClass(), newPinData));
      }

      // transmit and receive data with the card
      processAtomicCardCommands(cardCommandManager.getCardCommands(), channelControl);

      // sets the flag indicating that the commands have been executed
      cardCommandManager.notifyCommandsProcessed();

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

    if (calypsoCard.getProductType() == CalypsoCard.ProductType.BASIC) {
      throw new UnsupportedOperationException(
          "The 'Change Key' command is not available for this card.");
    }

    if (sessionState == SessionState.SESSION_OPEN) {
      throw new IllegalStateException("'Change Key' not allowed when a secure session is open.");
    }

    Assert.getInstance().isInRange(keyIndex, 1, 3, "keyIndex");

    // CL-KEY-CHANGE.1
    cardCommandManager.addRegularCommand(new CmdCardGetChallenge(calypsoCard.getCardClass()));

    // transmit and receive data with the card
    processAtomicCardCommands(cardCommandManager.getCardCommands(), ChannelControl.KEEP_OPEN);

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();

    // Get the encrypted key with the help of the SAM
    try {
      byte[] encryptedKey =
          samCommandProcessor.getEncryptedKey(
              calypsoCard.getCardChallenge(), issuerKif, issuerKvc, newKif, newKvc);
      cardCommandManager.addRegularCommand(
          new CmdCardChangeKey(calypsoCard.getCardClass(), (byte) keyIndex, encryptedKey));
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR
              + "generating the encrypted key: "
              + e.getCommand().getName()
              + getTransactionAuditDataAsString(),
          e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR
              + GENERATING_OF_THE_KEY_CIPHERED_DATA_ERROR
              + getTransactionAuditDataAsString(),
          e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_COMMUNICATION_ERROR
              + GENERATING_OF_THE_KEY_CIPHERED_DATA_ERROR
              + getTransactionAuditDataAsString(),
          e);
    } catch (DesynchronizedExchangesException e) {
      throw new DesynchronizedExchangesException(
          e.getMessage() + getTransactionAuditDataAsString());
    }

    // transmit and receive data with the card
    processAtomicCardCommands(cardCommandManager.getCardCommands(), channelControl);

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();

    return this;
  }

  /**
   * (private)<br>
   * Transmits a card request, processes and converts any exceptions.
   *
   * @param cardRequest The card request to transmit.
   * @param channelControl The channel control.
   * @return The card response.
   * @throws CardIOException If the communication with the card or the card reader failed.
   * @throws SamIOException If the communication with the SAM or the SAM reader failed (only for SV
   *     operations).
   * @throws SamAnomalyException If a SAM error occurs (only for SV operations).
   */
  private CardResponseApi transmitCardRequest(
      CardRequestSpi cardRequest, ChannelControl channelControl) {

    // Process SAM operations first for SV if needed.
    if (cardCommandManager.getSvLastModifyingCommand() != null) {
      finalizeSvCommand();
    }

    // Process card request.
    CardResponseApi cardResponse;
    try {
      cardResponse = cardReader.transmitCardRequest(cardRequest, channelControl);
    } catch (ReaderBrokenCommunicationException e) {
      storeTransactionAuditData(cardRequest, e.getCardResponse(), transactionAuditData);
      throw new CardIOException(
          CARD_READER_COMMUNICATION_ERROR
              + TRANSMITTING_COMMANDS
              + getTransactionAuditDataAsString(),
          e);
    } catch (CardBrokenCommunicationException e) {
      storeTransactionAuditData(cardRequest, e.getCardResponse(), transactionAuditData);
      throw new CardIOException(
          CARD_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS + getTransactionAuditDataAsString(), e);
    } catch (UnexpectedStatusWordException e) {
      if (logger.isDebugEnabled()) {
        logger.debug("A card command has failed: {}", e.getMessage());
      }
      cardResponse = e.getCardResponse();
    }
    storeTransactionAuditData(cardRequest, cardResponse, transactionAuditData);
    return cardResponse;
  }

  /**
   * (package-private)<br>
   * Stores the provided exchanged APDU commands in the provided list of transaction audit data.
   *
   * @param cardRequest The card request.
   * @param cardResponse The associated card response.
   * @param transactionAuditData The list to complete.
   * @since 2.1.1
   */
  static void storeTransactionAuditData(
      CardRequestSpi cardRequest, CardResponseApi cardResponse, List<byte[]> transactionAuditData) {
    if (cardResponse != null) {
      List<ApduRequestSpi> requests = cardRequest.getApduRequests();
      List<ApduResponseApi> responses = cardResponse.getApduResponses();
      for (int i = 0; i < responses.size(); i++) {
        transactionAuditData.add(requests.get(i).getApdu());
        transactionAuditData.add(responses.get(i).getApdu());
      }
    }
  }

  /**
   * (private)<br>
   * Returns a string representation of the transaction audit data.
   *
   * @return A not empty string.
   */
  private String getTransactionAuditDataAsString() {
    StringBuilder sb = new StringBuilder();
    sb.append("\nTransaction audit data:\n");
    sb.append("CARD: ").append(calypsoCard.toString()).append("\n");
    if (cardSecuritySetting != null && cardSecuritySetting.getCalypsoSam() != null) {
      sb.append("SAM: ").append(cardSecuritySetting.getCalypsoSam().toString()).append("\n");
    }
    sb.append("APDUs:\n[\n");
    for (byte[] apdu : transactionAuditData) {
      sb.append(ByteArrayUtil.toHex(apdu)).append("\n");
    }
    sb.append("]");
    return sb.toString();
  }

  /**
   * (private)<br>
   * Finalizes the last SV modifying command.
   *
   * @throws SamIOException If the communication with the SAM or the SAM reader failed.
   * @throws SamAnomalyException If a SAM error occurs.
   */
  private void finalizeSvCommand() {
    try {
      byte[] svComplementaryData;

      if (cardCommandManager.getSvLastModifyingCommand().getCommandRef()
          == CalypsoCardCommand.SV_RELOAD) {

        // SV RELOAD: get the security data from the SAM
        CmdCardSvReload svCommand =
            (CmdCardSvReload) cardCommandManager.getSvLastModifyingCommand();

        svComplementaryData =
            samCommandProcessor.getSvReloadComplementaryData(
                svCommand, calypsoCard.getSvGetHeader(), calypsoCard.getSvGetData());

        // finalize the SV command with the data provided by the SAM
        svCommand.finalizeCommand(svComplementaryData);

      } else {

        // SV DEBIT/UNDEBIT: get the security data from the SAM
        CmdCardSvDebitOrUndebit svCommand =
            (CmdCardSvDebitOrUndebit) cardCommandManager.getSvLastModifyingCommand();

        svComplementaryData =
            samCommandProcessor.getSvDebitOrUndebitComplementaryData(
                svCommand.getCommandRef() == CalypsoCardCommand.SV_DEBIT,
                svCommand,
                calypsoCard.getSvGetHeader(),
                calypsoCard.getSvGetData());

        // finalize the SV command with the data provided by the SAM
        svCommand.finalizeCommand(svComplementaryData);
      }
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR
              + "preparing the SV command: "
              + e.getCommand().getName()
              + getTransactionAuditDataAsString(),
          e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR
              + "preparing the SV command."
              + getTransactionAuditDataAsString(),
          e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_COMMUNICATION_ERROR + "preparing the SV command." + getTransactionAuditDataAsString(),
          e);
    } catch (DesynchronizedExchangesException e) {
      throw new DesynchronizedExchangesException(
          e.getMessage() + getTransactionAuditDataAsString());
    }
  }

  /**
   * Gets the SAM challenge, and raises exceptions if necessary.
   *
   * @return A not null reference.
   * @throws SamAnomalyException If SAM returned an unexpected response.
   * @throws SamIOException If the communication with the SAM or the SAM reader failed.
   */
  private byte[] getSamChallenge() {
    try {
      return samCommandProcessor.getChallenge();
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR
              + "getting the SAM challenge: "
              + e.getCommand().getName()
              + getTransactionAuditDataAsString(),
          e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR
              + "getting the SAM challenge."
              + getTransactionAuditDataAsString(),
          e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_COMMUNICATION_ERROR + "getting SAM challenge." + getTransactionAuditDataAsString(),
          e);
    } catch (DesynchronizedExchangesException e) {
      throw new DesynchronizedExchangesException(
          e.getMessage() + getTransactionAuditDataAsString());
    }
  }

  /**
   * Gets the terminal signature from the SAM, and raises exceptions if necessary.
   *
   * @return A not null reference.
   * @throws SamAnomalyException If SAM returned an unexpected response.
   * @throws SamIOException If the communication with the SAM or the SAM reader failed.
   * @throws DesynchronizedExchangesException if the APDU SAM exchanges are out of sync.
   */
  private byte[] getSessionTerminalSignature() {
    try {
      return samCommandProcessor.getTerminalSignature();
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR
              + "getting the terminal signature: "
              + e.getCommand().getName()
              + getTransactionAuditDataAsString(),
          e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_COMMUNICATION_ERROR
              + "getting the terminal signature."
              + getTransactionAuditDataAsString(),
          e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR
              + "getting the terminal signature."
              + getTransactionAuditDataAsString(),
          e);
    } catch (DesynchronizedExchangesException e) {
      throw new DesynchronizedExchangesException(
          e.getMessage() + getTransactionAuditDataAsString());
    }
  }

  /**
   * (private)<br>
   * Ask the SAM to verify the signature of the card, and raises exceptions if necessary.
   *
   * @param cardSignature The card signature.
   * @throws SessionAuthenticationException If the card authentication failed.
   * @throws SamAnomalyException If SAM returned an unexpected response.
   * @throws SamIOException If the communication with the SAM or the SAM reader failed.
   */
  private void checkCardSignature(byte[] cardSignature) {
    try {
      samCommandProcessor.authenticateCardSignature(cardSignature);
    } catch (CalypsoSamSecurityDataException e) {
      throw new SessionAuthenticationException(
          "The authentication of the card by the SAM has failed."
              + getTransactionAuditDataAsString(),
          e);
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR
              + "authenticating the card signature: "
              + e.getCommand().getName()
              + getTransactionAuditDataAsString(),
          e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR
              + "authenticating the card signature."
              + getTransactionAuditDataAsString(),
          e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_COMMUNICATION_ERROR
              + "authenticating the card signature."
              + getTransactionAuditDataAsString(),
          e);
    } catch (DesynchronizedExchangesException e) {
      throw new DesynchronizedExchangesException(
          e.getMessage() + getTransactionAuditDataAsString());
    }
  }

  /**
   * Ask the SAM to verify the SV operation status from the card postponed data, raises exceptions
   * if needed.
   *
   * @param cardPostponedData The postponed data from the card.
   * @throws SvAuthenticationException If the SV verification failed.
   * @throws SamAnomalyException If SAM returned an unexpected response.
   * @throws SamIOException If the communication with the SAM or the SAM reader failed.
   */
  private void checkSvOperationStatus(byte[] cardPostponedData) {
    try {
      samCommandProcessor.checkSvStatus(cardPostponedData);
    } catch (CalypsoSamSecurityDataException e) {
      throw new SvAuthenticationException(
          "The checking of the SV operation by the SAM has failed."
              + getTransactionAuditDataAsString(),
          e);
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR
              + "checking the SV operation: "
              + e.getCommand().getName()
              + getTransactionAuditDataAsString(),
          e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR
              + CHECKING_THE_SV_OPERATION
              + getTransactionAuditDataAsString(),
          e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION + getTransactionAuditDataAsString(),
          e);
    } catch (DesynchronizedExchangesException e) {
      throw new DesynchronizedExchangesException(
          e.getMessage() + getTransactionAuditDataAsString());
    }
  }

  /**
   * Checks if a Secure Session is open, raises an exception if not
   *
   * @throws IllegalStateException if no session is open
   */
  private void checkSessionOpen() {
    if (sessionState != SessionState.SESSION_OPEN) {
      throw new IllegalStateException(
          "Bad session state. Current: "
              + sessionState
              + ", expected: "
              + SessionState.SESSION_OPEN);
    }
  }

  /**
   * Checks if a Secure Session is not open, raises an exception if not
   *
   * @throws IllegalStateException if a session is open
   */
  private void checkSessionNotOpen() {
    if (sessionState == SessionState.SESSION_OPEN) {
      throw new IllegalStateException(
          "Bad session state. Current: " + sessionState + ", expected: not open");
    }
  }

  /**
   * (private)<br>
   * Computes the session buffer size of the provided command.<br>
   * The size may be a number of bytes or 1 depending on the card specificities.
   *
   * @param command The command.
   * @return A positive value.
   */
  private int computeCommandSessionBufferSize(AbstractCardCommand command) {
    return calypsoCard.isModificationsCounterInBytes()
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
  public final CardTransactionManager prepareReleaseCardChannel() {
    channelControl = ChannelControl.CLOSE_AFTER;
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
  public final CardTransactionManager prepareSelectFile(byte[] lid) {
    Assert.getInstance().notNull(lid, "lid").isEqual(lid.length, 2, "lid length");
    return prepareSelectFile((short) ByteArrayUtil.twoBytesToInt(lid, 0));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CardTransactionManager prepareSelectFile(short lid) {
    cardCommandManager.addRegularCommand(
        new CmdCardSelectFile(calypsoCard.getCardClass(), calypsoCard.getProductType(), lid));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareSelectFile(SelectFileControl selectFileControl) {

    Assert.getInstance().notNull(selectFileControl, "selectFileControl");

    // create the command and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CmdCardSelectFile(calypsoCard.getCardClass(), selectFileControl));

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
        cardCommandManager.addRegularCommand(new CmdCardGetDataFci(calypsoCard.getCardClass()));
        break;
      case FCP_FOR_CURRENT_FILE:
        cardCommandManager.addRegularCommand(new CmdCardGetDataFcp(calypsoCard.getCardClass()));
        break;
      case EF_LIST:
        cardCommandManager.addRegularCommand(new CmdCardGetDataEfList(calypsoCard.getCardClass()));
        break;
      case TRACEABILITY_INFORMATION:
        cardCommandManager.addRegularCommand(
            new CmdCardGetDataTraceabilityInformation(calypsoCard.getCardClass()));
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
  public final CardTransactionManager prepareReadRecordFile(byte sfi, int recordNumber) {
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
  public final CardTransactionManager prepareReadRecordFile(
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
  public final CardTransactionManager prepareReadCounterFile(byte sfi, int countersNumber) {
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

    if (sessionState == SessionState.SESSION_OPEN && !((CardReader) cardReader).isContactless()) {
      throw new IllegalStateException(
          "Explicit record size is expected inside a secure session in contact mode.");
    }

    CmdCardReadRecords cmdCardReadRecords =
        new CmdCardReadRecords(
            calypsoCard.getCardClass(),
            sfi,
            recordNumber,
            CmdCardReadRecords.ReadMode.ONE_RECORD,
            0);
    cardCommandManager.addRegularCommand(cmdCardReadRecords);

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
            toRecordNumber, fromRecordNumber, CalypsoCardConstant.NB_REC_MAX, "toRecordNumber");

    if (toRecordNumber == fromRecordNumber) {
      // create the command and add it to the list of commands
      cardCommandManager.addRegularCommand(
          new CmdCardReadRecords(
              calypsoCard.getCardClass(),
              sfi,
              fromRecordNumber,
              CmdCardReadRecords.ReadMode.ONE_RECORD,
              recordSize));
    } else {
      // Manages the reading of multiple records taking into account the transmission capacity
      // of the card and the response format (2 extra bytes).
      // Multiple APDUs can be generated depending on record size and transmission capacity.
      final CalypsoCardClass cardClass = calypsoCard.getCardClass();
      final int nbBytesPerRecord = recordSize + 2;
      final int nbRecordsPerApdu = calypsoCard.getPayloadCapacity() / nbBytesPerRecord;
      final int dataSizeMaxPerApdu = nbRecordsPerApdu * nbBytesPerRecord;

      int currentRecordNumber = fromRecordNumber;
      int nbRecordsRemainingToRead = toRecordNumber - fromRecordNumber + 1;
      int currentLength;

      while (currentRecordNumber < toRecordNumber) {
        currentLength =
            nbRecordsRemainingToRead <= nbRecordsPerApdu
                ? nbRecordsRemainingToRead * nbBytesPerRecord
                : dataSizeMaxPerApdu;

        cardCommandManager.addRegularCommand(
            new CmdCardReadRecords(
                cardClass,
                sfi,
                currentRecordNumber,
                CmdCardReadRecords.ReadMode.MULTIPLE_RECORD,
                currentLength));

        currentRecordNumber += (currentLength / nbBytesPerRecord);
        nbRecordsRemainingToRead -= (currentLength / nbBytesPerRecord);
      }

      // Optimization: prepare a read "one record" if possible for last iteration.
      if (currentRecordNumber == toRecordNumber) {
        cardCommandManager.addRegularCommand(
            new CmdCardReadRecords(
                cardClass,
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

    if (calypsoCard.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3
        && calypsoCard.getProductType() != CalypsoCard.ProductType.LIGHT) {
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
            CalypsoCardConstant.DATA_LENGTH_MAX - offset,
            "nbBytesToRead");

    final CalypsoCardClass cardClass = calypsoCard.getCardClass();
    final int nbRecordsPerApdu = calypsoCard.getPayloadCapacity() / nbBytesToRead;

    int currentRecordNumber = fromRecordNumber;

    while (currentRecordNumber <= toRecordNumber) {
      cardCommandManager.addRegularCommand(
          new CmdCardReadRecordMultiple(
              cardClass, sfi, (byte) currentRecordNumber, (byte) offset, (byte) nbBytesToRead));
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

    if (calypsoCard.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3) {
      throw new UnsupportedOperationException(
          "The 'Read Binary' command is not available for this card.");
    }

    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            offset, CalypsoCardConstant.OFFSET_MIN, CalypsoCardConstant.OFFSET_BINARY_MAX, OFFSET)
        .greaterOrEqual(nbBytesToRead, 1, "nbBytesToRead");

    if (sfi > 0 && offset > 255) { // FFh
      // Tips to select the file: add a "Read Binary" command (read one byte at offset 0).
      cardCommandManager.addRegularCommand(
          new CmdCardReadBinary(calypsoCard.getCardClass(), sfi, 0, (byte) 1));
    }

    final int payloadCapacity = calypsoCard.getPayloadCapacity();
    final CalypsoCardClass cardClass = calypsoCard.getCardClass();

    int currentLength;
    int currentOffset = offset;
    int nbBytesRemainingToRead = nbBytesToRead;
    do {
      currentLength = Math.min(nbBytesRemainingToRead, payloadCapacity);

      cardCommandManager.addRegularCommand(
          new CmdCardReadBinary(cardClass, sfi, currentOffset, (byte) currentLength));

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

    if (calypsoCard.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3) {
      throw new UnsupportedOperationException(
          "The 'Search Record Multiple' command is not available for this card.");
    }

    if (!(data instanceof SearchCommandDataAdapter)) {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'SearchCommandDataAdapter' class.");
    }

    SearchCommandDataAdapter dataAdapter = (SearchCommandDataAdapter) data;

    Assert.getInstance()
        .notNull(data, "data")
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
            CalypsoCardConstant.DATA_LENGTH_MAX - dataAdapter.getOffset(),
            "searchData");
    if (dataAdapter.getMask() != null) {
      Assert.getInstance()
          .isInRange(
              dataAdapter.getMask().length,
              CalypsoCardConstant.DATA_LENGTH_MIN,
              dataAdapter.getSearchData().length,
              "mask");
    }

    cardCommandManager.addRegularCommand(
        new CmdCardSearchRecordMultiple(calypsoCard.getCardClass(), dataAdapter));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareAppendRecord(byte sfi, byte[] recordData) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .notNull(recordData, "recordData");

    // create the command and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CmdCardAppendRecord(calypsoCard.getCardClass(), sfi, recordData));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareUpdateRecord(
      byte sfi, int recordNumber, byte[] recordData) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            recordNumber,
            CalypsoCardConstant.NB_REC_MIN,
            CalypsoCardConstant.NB_REC_MAX,
            RECORD_NUMBER)
        .notNull(recordData, "recordData");

    // create the command and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CmdCardUpdateRecord(calypsoCard.getCardClass(), sfi, recordNumber, recordData));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareWriteRecord(
      byte sfi, int recordNumber, byte[] recordData) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            recordNumber,
            CalypsoCardConstant.NB_REC_MIN,
            CalypsoCardConstant.NB_REC_MAX,
            RECORD_NUMBER);

    // create the command and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CmdCardWriteRecord(calypsoCard.getCardClass(), sfi, recordNumber, recordData));

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
   * (private)<br>
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

    if (calypsoCard.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3) {
      throw new UnsupportedOperationException(
          "The 'Update/Write Binary' command is not available for this card.");
    }

    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            offset, CalypsoCardConstant.OFFSET_MIN, CalypsoCardConstant.OFFSET_BINARY_MAX, OFFSET)
        .notEmpty(data, "data");

    if (sfi > 0 && offset > 255) { // FFh
      // Tips to select the file: add a "Read Binary" command (read one byte at offset 0).
      cardCommandManager.addRegularCommand(
          new CmdCardReadBinary(calypsoCard.getCardClass(), sfi, 0, (byte) 1));
    }

    final int dataLength = data.length;
    final int payloadCapacity = calypsoCard.getPayloadCapacity();
    final CalypsoCardClass cardClass = calypsoCard.getCardClass();

    int currentLength;
    int currentOffset = offset;
    int currentIndex = 0;
    do {
      currentLength = Math.min(dataLength - currentIndex, payloadCapacity);

      cardCommandManager.addRegularCommand(
          new CmdCardUpdateOrWriteBinary(
              isUpdateCommand,
              cardClass,
              sfi,
              currentOffset,
              Arrays.copyOfRange(data, currentIndex, currentIndex + currentLength)));

      currentOffset += currentLength;
      currentIndex += currentLength;
    } while (currentIndex < dataLength);

    return this;
  }

  /**
   * (private)
   *
   * <p>Factorisation of prepareDecreaseCounter and prepareIncreaseCounter.
   */
  private CardTransactionManager prepareIncreaseOrDecreaseCounter(
      boolean isDecreaseCommand, byte sfi, int counterNumber, int incDecValue) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            counterNumber,
            CalypsoCardConstant.NB_CNT_MIN,
            CalypsoCardConstant.NB_CNT_MAX,
            "counterNumber")
        .isInRange(
            incDecValue,
            CalypsoCardConstant.CNT_VALUE_MIN,
            CalypsoCardConstant.CNT_VALUE_MAX,
            "incDecValue");

    // create the command and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CmdCardIncreaseOrDecrease(
            isDecreaseCommand, calypsoCard.getCardClass(), sfi, counterNumber, incDecValue));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareIncreaseCounter(
      byte sfi, int counterNumber, int incValue) {
    return prepareIncreaseOrDecreaseCounter(false, sfi, counterNumber, incValue);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareDecreaseCounter(
      byte sfi, int counterNumber, int decValue) {
    return prepareIncreaseOrDecreaseCounter(true, sfi, counterNumber, decValue);
  }

  /**
   * (private)
   *
   * <p>Factorisation of prepareDecreaseMultipleCounters and prepareIncreaseMultipleCounters.
   */
  private CardTransactionManager prepareIncreaseOrDecreaseCounters(
      boolean isDecreaseCommand, byte sfi, Map<Integer, Integer> counterNumberToIncDecValueMap) {

    if (calypsoCard.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3
        && calypsoCard.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_2) {
      throw new UnsupportedOperationException(
          "The 'Increase/Decrease Multiple' commands are not available for this card.");
    }

    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            counterNumberToIncDecValueMap.size(),
            CalypsoCardConstant.NB_CNT_MIN,
            CalypsoCardConstant.NB_CNT_MAX,
            "counterNumberToIncDecValueMap");

    for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
      Assert.getInstance()
          .isInRange(
              entry.getKey(),
              CalypsoCardConstant.NB_CNT_MIN,
              CalypsoCardConstant.NB_CNT_MAX,
              "counterNumberToIncDecValueMapKey")
          .isInRange(
              entry.getValue(),
              CalypsoCardConstant.CNT_VALUE_MIN,
              CalypsoCardConstant.CNT_VALUE_MAX,
              "counterNumberToIncDecValueMapValue");
    }
    final int nbCountersPerApdu = calypsoCard.getPayloadCapacity() / 4;
    if (counterNumberToIncDecValueMap.size() <= nbCountersPerApdu) {
      // create the command and add it to the list of commands
      cardCommandManager.addRegularCommand(
          new CmdCardIncreaseOrDecreaseMultiple(
              isDecreaseCommand,
              calypsoCard.getCardClass(),
              sfi,
              new TreeMap<Integer, Integer>(counterNumberToIncDecValueMap)));
    } else {
      // the number of counters exceeds the payload capacity, let's split into several apdu commands
      int i = 0;
      TreeMap<Integer, Integer> map = new TreeMap<Integer, Integer>();
      for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
        i++;
        map.put(entry.getKey(), entry.getValue());
        if (i == nbCountersPerApdu) {
          cardCommandManager.addRegularCommand(
              new CmdCardIncreaseOrDecreaseMultiple(
                  isDecreaseCommand,
                  calypsoCard.getCardClass(),
                  sfi,
                  new TreeMap<Integer, Integer>(map)));
          i = 0;
          map.clear();
        }
      }
      if (!map.isEmpty()) {
        cardCommandManager.addRegularCommand(
            new CmdCardIncreaseOrDecreaseMultiple(
                isDecreaseCommand, calypsoCard.getCardClass(), sfi, map));
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
  public final CardTransactionManager prepareIncreaseCounters(
      byte sfi, Map<Integer, Integer> counterNumberToIncValueMap) {
    return prepareIncreaseOrDecreaseCounters(false, sfi, counterNumberToIncValueMap);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final CardTransactionManager prepareDecreaseCounters(
      byte sfi, Map<Integer, Integer> counterNumberToDecValueMap) {
    return prepareIncreaseOrDecreaseCounters(true, sfi, counterNumberToDecValueMap);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareSetCounter(byte sfi, int counterNumber, int newValue) {
    Integer oldValue = null;
    ElementaryFile ef = calypsoCard.getFileBySfi(sfi);
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
  public final CardTransactionManager prepareCheckPinStatus() {
    if (!calypsoCard.isPinFeatureAvailable()) {
      throw new UnsupportedOperationException(PIN_NOT_AVAILABLE_ERROR);
    }
    // create the command and add it to the list of commands
    cardCommandManager.addRegularCommand(new CmdCardVerifyPin(calypsoCard.getCardClass()));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareSvGet(SvOperation svOperation, SvAction svAction) {

    Assert.getInstance().notNull(svOperation, "svOperation").notNull(svAction, "svAction");

    if (!calypsoCard.isSvFeatureAvailable()) {
      throw new UnsupportedOperationException("Stored Value is not available for this card.");
    }

    // CL-SV-CMDMODE.1
    CalypsoSam calypsoSam = cardSecuritySetting.getCalypsoSam();
    boolean useExtendedMode =
        calypsoCard.isExtendedModeSupported()
            && (calypsoSam == null || calypsoSam.getProductType() == CalypsoSam.ProductType.SAM_C1);

    if (cardSecuritySetting.isSvLoadAndDebitLogEnabled() && (!useExtendedMode)) {
      // @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit logs are requested
      // for a non rev3.2 card add two SvGet commands (for RELOAD then for DEBIT).
      // CL-SV-GETNUMBER.1
      SvOperation operation1 =
          SvOperation.RELOAD.equals(svOperation) ? SvOperation.DEBIT : SvOperation.RELOAD;
      cardCommandManager.addStoredValueCommand(
          new CmdCardSvGet(calypsoCard.getCardClass(), operation1, false), operation1);
    }
    cardCommandManager.addStoredValueCommand(
        new CmdCardSvGet(calypsoCard.getCardClass(), svOperation, useExtendedMode), svOperation);
    this.svAction = svAction;

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareSvReload(
      int amount, byte[] date, byte[] time, byte[] free) {

    checkSvInsideSession();

    // create the initial command with the application data
    CmdCardSvReload svReloadCmdBuild =
        new CmdCardSvReload(
            calypsoCard.getCardClass(),
            amount,
            calypsoCard.getSvKvc(),
            date,
            time,
            free,
            isExtendedModeAllowed());

    // create and keep the CalypsoCardCommand
    cardCommandManager.addStoredValueCommand(svReloadCmdBuild, SvOperation.RELOAD);

    return this;
  }

  /**
   * (private)<br>
   * Checks if only one modifying SV command is prepared inside the current secure session.
   *
   * @throws IllegalStateException If more than SV command is prepared.
   */
  private void checkSvInsideSession() {
    // CL-SV-1PCSS.1
    if (sessionState == SessionState.SESSION_OPEN) {
      if (!isSvOperationInsideSession) {
        isSvOperationInsideSession = true;
      } else {
        throw new IllegalStateException("Only one SV operation is allowed per Secure Session.");
      }
    }
  }

  /**
   * (private)<br>
   * CL-CSS-OSSMODE.1<br>
   * CL-SV-CMDMODE.1
   *
   * @return True if the card extended mode is allowed.
   */
  private boolean isExtendedModeAllowed() {
    CalypsoSam calypsoSam = cardSecuritySetting.getCalypsoSam();
    return calypsoCard.isExtendedModeSupported()
        && calypsoSam.getProductType() == CalypsoSam.ProductType.SAM_C1;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareSvReload(int amount) {
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
  public final CardTransactionManager prepareSvDebit(int amount, byte[] date, byte[] time) {

    checkSvInsideSession();

    if (svAction == SvAction.DO
        && !cardSecuritySetting.isSvNegativeBalanceAuthorized()
        && (calypsoCard.getSvBalance() - amount) < 0) {
      throw new IllegalStateException("Negative balances not allowed.");
    }

    // create the initial command with the application data
    CmdCardSvDebitOrUndebit command =
        new CmdCardSvDebitOrUndebit(
            svAction == SvAction.DO,
            calypsoCard.getCardClass(),
            amount,
            calypsoCard.getSvKvc(),
            date,
            time,
            isExtendedModeAllowed());

    // create and keep the CalypsoCardCommand
    cardCommandManager.addStoredValueCommand(command, SvOperation.DEBIT);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareSvDebit(int amount) {
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
  public final CardTransactionManager prepareSvReadAllLogs() {
    if (!calypsoCard.isSvFeatureAvailable()) {
      throw new UnsupportedOperationException("Stored Value is not available for this card.");
    }
    if (calypsoCard.getApplicationSubtype() != CalypsoCardConstant.STORED_VALUE_FILE_STRUCTURE_ID) {
      throw new UnsupportedOperationException(
          "The currently selected application is not an SV application.");
    }
    // reset SV data in CalypsoCard if any
    calypsoCard.setSvData((byte) 0, null, null, 0, 0, null, null);
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
  public final CardTransactionManager prepareInvalidate() {
    if (calypsoCard.isDfInvalidated()) {
      throw new IllegalStateException("This card is already invalidated.");
    }
    cardCommandManager.addRegularCommand(new CmdCardInvalidate(calypsoCard.getCardClass()));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareRehabilitate() {
    if (!calypsoCard.isDfInvalidated()) {
      throw new IllegalStateException("This card is not invalidated.");
    }
    cardCommandManager.addRegularCommand(new CmdCardRehabilitate(calypsoCard.getCardClass()));

    return this;
  }

  /**
   * (private)<br>
   * Adapter of {@link ApduResponseApi} used to create anticipated card responses.
   */
  private static class ApduResponseAdapter implements ApduResponseApi {

    private final byte[] apdu;
    private final int statusWord;

    /** Constructor */
    public ApduResponseAdapter(byte[] apdu) {
      this.apdu = apdu;
      statusWord =
          ((apdu[apdu.length - 2] & 0x000000FF) << 8) + (apdu[apdu.length - 1] & 0x000000FF);
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
}
