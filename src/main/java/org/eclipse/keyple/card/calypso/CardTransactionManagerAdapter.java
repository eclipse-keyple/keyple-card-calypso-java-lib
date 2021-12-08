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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.calypsonet.terminal.calypso.GetDataTag;
import org.calypsonet.terminal.calypso.SelectFileControl;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.transaction.*;
import org.calypsonet.terminal.card.*;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.calypsonet.terminal.reader.CardReader;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
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
 * </ul>
 *
 * @since 2.0.0
 */
class CardTransactionManagerAdapter implements CardTransactionManager {

  private static final Logger logger = LoggerFactory.getLogger(CardTransactionManagerAdapter.class);

  // prefix/suffix used to compose exception messages
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
  private static final String TRANSMITTING_COMMANDS = "transmitting commands.";
  private static final String CHECKING_THE_SV_OPERATION = "checking the SV operation.";
  private static final String UNEXPECTED_EXCEPTION = "An unexpected exception was raised.";
  private static final String RECORD_NUMBER = "recordNumber";

  // commands that modify the content of the card in session have a cost on the session buffer equal
  // to the length of the outgoing data plus 6 bytes
  private static final int SESSION_BUFFER_CMD_ADDITIONAL_COST = 6;

  private static final int APDU_HEADER_LENGTH = 5;

  /** The reader for the card. */
  private final ProxyReaderApi cardReader;
  /** The card security settings used to manage the secure session */
  private CardSecuritySetting cardSecuritySettings;
  /** The SAM commands processor */
  private SamCommandProcessor samCommandProcessor;
  /** The current CalypsoCard */
  private final CalypsoCardAdapter calypsoCard;
  /** the type of the notified event. */
  private SessionState sessionState;
  /** The current secure session access level: PERSO, RELOAD, DEBIT */
  private WriteAccessLevel currentWriteAccessLevel;
  /** modifications counter management */
  private int modificationsCounter;
  /** The object for managing card commands */
  private final CardCommandManager cardCommandManager;
  /** The current Store Value action */
  private SvAction svAction;
  /** The {@link ChannelControl} action */
  private ChannelControl channelControl;

  private enum SessionState {
    /** Initial state of a card transaction. The card must have been previously selected. */
    SESSION_UNINITIALIZED,
    /** The secure session is active. */
    SESSION_OPEN,
    /** The secure session is closed. */
    SESSION_CLOSED
  }

  /**
   * Creates an instance of {@link CardTransactionManager} for secure operations.
   *
   * <p>Secure operations are enabled by the presence of {@link CardSecuritySetting}.
   *
   * @param cardReader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @param cardSecuritySetting The security settings.
   * @since 2.0.0
   */
  public CardTransactionManagerAdapter(
      CardReader cardReader, CalypsoCard calypsoCard, CardSecuritySetting cardSecuritySetting) {

    this(cardReader, calypsoCard);

    this.cardSecuritySettings = cardSecuritySetting;

    samCommandProcessor = new SamCommandProcessor(calypsoCard, cardSecuritySetting);
  }

  /**
   * Creates an instance of {@link
   * org.calypsonet.terminal.calypso.transaction.CardTransactionManager} for non-secure operations.
   *
   * @param cardReader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @since 2.0.0
   */
  public CardTransactionManagerAdapter(CardReader cardReader, CalypsoCard calypsoCard) {
    this.cardReader = (ProxyReaderApi) cardReader;

    this.calypsoCard = (CalypsoCardAdapter) calypsoCard;

    modificationsCounter = this.calypsoCard.getModificationsCounter();

    sessionState = SessionState.SESSION_UNINITIALIZED;

    cardCommandManager = new CardCommandManager();

    channelControl = ChannelControl.KEEP_OPEN;
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
    return cardSecuritySettings;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getTransactionAuditData() {
    return null;
  }

  /**
   * Open a single Secure Session.
   *
   * @param writeAccessLevel access level of the session (personalization, load or debit).
   * @param cardCommands the card commands inside session.
   * @throws IllegalStateException if no {@link
   *     org.calypsonet.terminal.calypso.transaction.CardTransactionManager} is available
   * @throws CardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processAtomicOpening(
      WriteAccessLevel writeAccessLevel, List<AbstractCardCommand> cardCommands) {

    // This method should be invoked only if no session was previously open
    checkSessionIsNotOpen();

    if (cardSecuritySettings == null) {
      throw new IllegalStateException("No security settings are available.");
    }

    byte[] sessionTerminalChallenge = getSessionTerminalChallenge();

    // card ApduRequestAdapter List to hold Open Secure Session and other optional commands
    List<ApduRequestSpi> cardApduRequests = new ArrayList<ApduRequestSpi>();

    // The sfi and record number to be read when the open secure session command is executed.
    // The default value is 0 (no record to read) but we will optimize the exchanges if a read
    // record command has been prepared.
    int sfi = 0;
    int recordNumber = 0;

    // Let's check if we have a read record command at the top of the command list.
    //
    // If so, then the command is withdrawn in favour of its equivalent executed at the same
    // time as the open secure session command.
    if (cardCommands != null && !cardCommands.isEmpty()) {
      AbstractCardCommand cardCommand = cardCommands.get(0);
      if (cardCommand.getCommandRef() == CalypsoCardCommand.READ_RECORDS
          && ((CmdCardReadRecords) cardCommand).getReadMode()
              == CmdCardReadRecords.ReadMode.ONE_RECORD) {
        sfi = ((CmdCardReadRecords) cardCommand).getSfi();
        recordNumber = ((CmdCardReadRecords) cardCommand).getFirstRecordNumber();
        cardCommands.remove(0);
      }
    }

    // Build the card Open Secure Session command
    CmdCardOpenSession cmdCardOpenSession =
        new CmdCardOpenSession(
            calypsoCard,
            (byte) (writeAccessLevel.ordinal() + 1),
            sessionTerminalChallenge,
            sfi,
            recordNumber);

    // Add the resulting ApduRequestAdapter to the card ApduRequestAdapter list
    cardApduRequests.add(cmdCardOpenSession.getApduRequest());

    // Add all optional commands to the card ApduRequestAdapter list
    if (cardCommands != null) {
      cardApduRequests.addAll(getApduRequests(cardCommands));
    }

    // Create a CardRequest from the ApduRequestAdapter list, card AID as Selector, keep channel
    // open
    CardRequestSpi cardRequest = new CardRequestAdapter(cardApduRequests, false);

    // Transmit the commands to the card
    CardResponseApi cardResponse = safeTransmit(cardRequest, ChannelControl.KEEP_OPEN);

    // Retrieve and check the ApduResponses
    List<ApduResponseApi> cardApduResponses = cardResponse.getApduResponses();

    // Do some basic checks
    checkCommandsResponsesSynchronization(cardApduRequests.size(), cardApduResponses.size());

    // Parse the response to Open Secure Session (the first item of cardApduResponses)
    // The updateCalypsoCard method fills the CalypsoCard object with the command data.
    try {
      CalypsoCardUtilAdapter.updateCalypsoCard(
          calypsoCard, cmdCardOpenSession, cardApduResponses.get(0));
    } catch (CardCommandException e) {
      throw new CardAnomalyException(
          CARD_COMMAND_ERROR + "processing the response to open session: " + e.getCommand(), e);
    }
    // Build the Digest Init command from card Open Session
    // the session challenge is needed for the SAM digest computation
    byte[] sessionCardChallenge = cmdCardOpenSession.getCardChallenge();

    // The card KIF
    Byte cardKif = cmdCardOpenSession.getSelectedKif();

    // The card KVC, may be null for card Rev 1.0
    Byte cardKvc = cmdCardOpenSession.getSelectedKvc();

    if (logger.isDebugEnabled()) {
      logger.debug(
          "processAtomicOpening => opening: CARDCHALLENGE = {}, CARDKIF = {}, CARDKVC = {}",
          ByteArrayUtil.toHex(sessionCardChallenge),
          cardKif != null ? String.format("%02X", cardKif) : null,
          cardKvc != null ? String.format("%02X", cardKvc) : null);
    }

    Byte kvc = samCommandProcessor.computeKvc(writeAccessLevel, cardKvc);
    Byte kif = samCommandProcessor.computeKif(writeAccessLevel, cardKif, kvc);

    if (!((CardSecuritySettingAdapter) cardSecuritySettings).isSessionKeyAuthorized(kif, kvc)) {
      String logKif = kif != null ? Integer.toHexString(kif).toUpperCase() : "null";
      String logKvc = kvc != null ? Integer.toHexString(kvc).toUpperCase() : "null";
      throw new UnauthorizedKeyException(
          String.format("Unauthorized key error: KIF = %s KVC = %s", logKif, logKvc));
    }

    // Initialize the digest processor. It will store all digest operations (Digest Init, Digest
    // Update) until the session closing. At this moment, all SAM Apdu will be processed at
    // once.
    samCommandProcessor.initializeDigester(
        false, false, kif, kvc, cardApduResponses.get(0).getDataOut());

    // Add all commands data to the digest computation. The first command in the list is the
    // open secure session command. This command is not included in the digest computation, so
    // we skip it and start the loop at index 1.
    if ((cardCommands != null) && !cardCommands.isEmpty()) {
      // Add requests and responses to the digest processor
      samCommandProcessor.pushCardExchangedData(cardApduRequests, cardApduResponses, 1);
    }

    // Remove Open Secure Session response and create a new CardResponse
    cardApduResponses.remove(0);

    // update CalypsoCard with the received data
    try {
      CalypsoCardUtilAdapter.updateCalypsoCard(calypsoCard, cardCommands, cardApduResponses);
    } catch (CardCommandException e) {
      throw new CardAnomalyException(
          CARD_COMMAND_ERROR + "processing the response to open session: " + e.getCommand(), e);
    }

    sessionState = SessionState.SESSION_OPEN;
  }

  /**
   * Create an ApduRequestAdapter List from a AbstractCardCommand List.
   *
   * @param cardCommands a list of card commands.
   * @return The ApduRequestAdapter list
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
   * @param channelControl indicated if the card channel of the card reader must be closed after
   *     the. last command
   * @throws CardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processAtomicCardCommands(
      List<AbstractCardCommand> cardCommands, ChannelControl channelControl) {

    // Get the card ApduRequestAdapter List
    List<ApduRequestSpi> apduRequests = getApduRequests(cardCommands);

    // Create a CardRequest from the ApduRequestAdapter list, card AID as Selector, manage the
    // logical
    // channel according to the channelControl
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, false);

    // Transmit the commands to the card
    CardResponseApi cardResponse = safeTransmit(cardRequest, channelControl);

    // Retrieve and check the ApduResponses
    List<ApduResponseApi> cardApduResponses = cardResponse.getApduResponses();

    // Do some basic checks
    checkCommandsResponsesSynchronization(apduRequests.size(), cardApduResponses.size());

    // Add all commands data to the digest computation if this method is invoked within a Secure
    // Session.
    if (sessionState == SessionState.SESSION_OPEN) {
      samCommandProcessor.pushCardExchangedData(apduRequests, cardApduResponses, 0);
    }

    try {
      CalypsoCardUtilAdapter.updateCalypsoCard(
          calypsoCard, cardCommands, cardResponse.getApduResponses());
    } catch (CardCommandException e) {
      throw new CardAnomalyException(
          CARD_COMMAND_ERROR + "processing responses to card commands: " + e.getCommand(), e);
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
   * @param cardModificationCommands a list of commands that can modify the card memory content.
   * @param cardAnticipatedResponses a list of anticipated card responses to the modification
   *     commands.
   * @param isRatificationMechanismEnabled true if the ratification is closed not ratified and a
   *     ratification command must be sent.
   * @param channelControl indicates if the card channel of the card reader must be closed after
   *     the. last command
   * @throws CardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processAtomicClosing(
      List<AbstractCardCommand> cardModificationCommands,
      List<ApduResponseApi> cardAnticipatedResponses,
      boolean isRatificationMechanismEnabled,
      ChannelControl channelControl) {

    checkSessionIsOpen();

    // Get the card ApduRequestAdapter List - for the first card exchange
    List<ApduRequestSpi> apduRequests = getApduRequests(cardModificationCommands);

    // Compute "anticipated" Digest Update (for optional cardModificationCommands)
    if ((cardModificationCommands != null) && !apduRequests.isEmpty()) {
      checkCommandsResponsesSynchronization(apduRequests.size(), cardAnticipatedResponses.size());
      // Add all commands data to the digest computation: commands and anticipated
      // responses.
      samCommandProcessor.pushCardExchangedData(apduRequests, cardAnticipatedResponses, 0);
    }

    // All SAM digest operations will now run at once.
    // Get Terminal Signature from the latest response
    byte[] sessionTerminalSignature = getSessionTerminalSignature();

    // Build the card Close Session command. The last one for this session
    CmdCardCloseSession cmdCardCloseSession =
        new CmdCardCloseSession(
            calypsoCard, !isRatificationMechanismEnabled, sessionTerminalSignature);

    apduRequests.add(cmdCardCloseSession.getApduRequest());

    // Keep the cardsition of the Close Session command in request list
    int closeCommandIndex = apduRequests.size() - 1;

    // Add the card Ratification command if any
    boolean ratificationCommandAdded;
    if (isRatificationMechanismEnabled && ((CardReader) cardReader).isContactless()) {
      // CL-RAT-CMD.1
      // CL-RAT-DELAY.1
      // CL-RAT-NXTCLOSE.1
      apduRequests.add(CmdCardRatificationBuilder.getApduRequest(calypsoCard.getCardClass()));
      ratificationCommandAdded = true;
    } else {
      ratificationCommandAdded = false;
    }

    // Transfer card commands
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, false);

    CardResponseApi cardResponse;
    try {
      cardResponse = cardReader.transmitCardRequest(cardRequest, channelControl);
    } catch (CardBrokenCommunicationException e) {
      cardResponse = e.getCardResponse();
      // The current exception may have been caused by a communication issue with the card
      // during the ratification command.
      //
      // In this case, we do not stop the process and consider the Secure Session close. We'll
      // check the signature.
      //
      // We should have one response less than requests.
      if (!ratificationCommandAdded
          || cardResponse == null
          || cardResponse.getApduResponses().size() != apduRequests.size() - 1) {
        throw new CardIOException(CARD_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
      }
    } catch (ReaderBrokenCommunicationException e) {
      throw new CardIOException(CARD_READER_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
    } catch (UnexpectedStatusWordException e) {
      throw new IllegalStateException(UNEXPECTED_EXCEPTION, e);
    }

    List<ApduResponseApi> apduResponses = cardResponse.getApduResponses();

    // Check the commands executed before closing the secure session (only responses to these
    // commands will be taken into account)
    try {
      CalypsoCardUtilAdapter.updateCalypsoCard(
          calypsoCard, cardModificationCommands, apduResponses);
    } catch (CardCommandException e) {
      throw new CardAnomalyException(
          CARD_COMMAND_ERROR
              + "processing of responses preceding the close of the session: "
              + e.getCommand(),
          e);
    }

    // Check the card's response to Close Secure Session
    try {
      CalypsoCardUtilAdapter.updateCalypsoCard(
          calypsoCard, cmdCardCloseSession, apduResponses.get(closeCommandIndex));
    } catch (CardSecurityDataException e) {
      throw new CardCloseSecureSessionException("Invalid card session", e);
    } catch (CardCommandException e) {
      throw new CardAnomalyException(
          CARD_COMMAND_ERROR + "processing the response to close session: " + e.getCommand(), e);
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

    sessionState = SessionState.SESSION_CLOSED;
  }

  /**
   * Advanced variant of processAtomicClosing in which the list of expected responses is determined
   * from previous reading operations.
   *
   * @param cardCommands a list of commands that can modify the card memory content.
   * @param isRatificationMechanismEnabled true if the ratification is closed not ratified and a
   *     ratification command must be sent.
   * @param channelControl indicates if the card channel of the card reader must be closed after
   *     the. last command
   * @throws CardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processAtomicClosing(
      List<AbstractCardCommand> cardCommands,
      boolean isRatificationMechanismEnabled,
      ChannelControl channelControl) {
    List<ApduResponseApi> cardAnticipatedResponses = getAnticipatedResponses(cardCommands);
    processAtomicClosing(
        cardCommands, cardAnticipatedResponses, isRatificationMechanismEnabled, channelControl);
  }

  /**
   * Gets the value of the designated counter
   *
   * @param sfi the SFI of the EF containing the counter.
   * @param counter the number of the counter.
   * @return The value of the counter
   */
  private int getCounterValue(int sfi, int counter) {
    try {
      ElementaryFile ef = calypsoCard.getFileBySfi((byte) sfi);
      return ef.getData().getContentAsCounterValue(counter);
    } catch (NoSuchElementException e) {
      throw new IllegalStateException(
          "Anticipated response. Unable to determine anticipated value of counter "
              + counter
              + " in EF sfi "
              + sfi);
    }
  }

  /**
   * Create an anticipated response to an Increase/Decrease command
   *
   * @param newCounterValue the anticipated counter value.
   * @return An {@link ApduResponseApi} containing the expected bytes
   */
  private ApduResponseApi createIncreaseDecreaseResponse(int newCounterValue) {
    // response = NNNNNN9000
    byte[] response = new byte[5];
    response[0] = (byte) ((newCounterValue & 0x00FF0000) >> 16);
    response[1] = (byte) ((newCounterValue & 0x0000FF00) >> 8);
    response[2] = (byte) (newCounterValue & 0x000000FF);
    response[3] = (byte) 0x90;
    response[4] = (byte) 0x00;
    return new ApduResponseAdapter(response);
  }

  static final ApduResponseApi RESPONSE_OK =
      new ApduResponseAdapter(new byte[] {(byte) 0x90, (byte) 0x00});
  static final ApduResponseApi RESPONSE_OK_POSTPONED =
      new ApduResponseAdapter(new byte[] {(byte) 0x62, (byte) 0x00});

  /**
   * Get the anticipated response to the command sent in processClosing.<br>
   * These commands are supposed to be "modifying commands" i.e.
   * Increase/Decrease/UpdateRecord/WriteRecord ou AppendRecord.
   *
   * @param cardCommands the list of card commands sent.
   * @return The list of the anticipated responses.
   * @throws IllegalStateException if the anticipation process failed
   */
  private List<ApduResponseApi> getAnticipatedResponses(List<AbstractCardCommand> cardCommands) {
    List<ApduResponseApi> apduResponses = new ArrayList<ApduResponseApi>();
    if (cardCommands != null) {
      for (AbstractCardCommand command : cardCommands) {
        if (command.getCommandRef() == CalypsoCardCommand.DECREASE) {
          int sfi = ((CmdCardDecrease) command).getSfi();
          int counter = ((CmdCardDecrease) command).getCounterNumber();
          int newCounterValue =
              getCounterValue(sfi, counter) - ((CmdCardDecrease) command).getDecValue();
          apduResponses.add(createIncreaseDecreaseResponse(newCounterValue));
        } else if (command.getCommandRef() == CalypsoCardCommand.INCREASE) {
          int sfi = ((CmdCardIncrease) command).getSfi();
          int counter = ((CmdCardIncrease) command).getCounterNumber();
          int newCounterValue =
              getCounterValue(sfi, counter) + ((CmdCardIncrease) command).getIncValue();
          apduResponses.add(createIncreaseDecreaseResponse(newCounterValue));
        } else if (command.getCommandRef() == CalypsoCardCommand.SV_RELOAD
            || command.getCommandRef() == CalypsoCardCommand.SV_DEBIT
            || command.getCommandRef() == CalypsoCardCommand.SV_UNDEBIT) {
          apduResponses.add(RESPONSE_OK_POSTPONED);
        } else { // Append/Update/Write Record: response = 9000
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

    // CL-KEY-INDEXPO.1
    currentWriteAccessLevel = writeAccessLevel;

    // create a sublist of AbstractCardCommand to be sent atomically
    List<AbstractCardCommand> cardAtomicCommands = new ArrayList<AbstractCardCommand>();

    AtomicInteger neededSessionBufferSpace = new AtomicInteger();
    AtomicBoolean overflow = new AtomicBoolean();

    for (AbstractCardCommand command : cardCommandManager.getCardCommands()) {
      // check if the command is a modifying one and get it status (overflow yes/no,
      // neededSessionBufferSpace)
      // if the command overflows the session buffer in atomic modification mode, an exception
      // is raised.
      if (checkModifyingCommand(command, overflow, neededSessionBufferSpace)) {
        if (overflow.get()) {
          // Open the session with the current commands
          processAtomicOpening(currentWriteAccessLevel, cardAtomicCommands);
          // Closes the session, resets the modifications buffer counters for the next
          // round.
          processAtomicClosing(null, false, ChannelControl.KEEP_OPEN);
          resetModificationsBufferCounter();
          // Clear the list and add the command that did not fit in the card modifications
          // buffer. We also update the usage counter without checking the result.
          cardAtomicCommands.clear();
          cardAtomicCommands.add(command);
          // just update modifications buffer usage counter, ignore result (always false)
          isSessionBufferOverflowed(neededSessionBufferSpace.get());
        } else {
          // The command fits in the card modifications buffer, just add it to the list
          cardAtomicCommands.add(command);
        }
      } else {
        // This command does not affect the card modifications buffer
        cardAtomicCommands.add(command);
      }
    }

    processAtomicOpening(currentWriteAccessLevel, cardAtomicCommands);

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();

    return this;
  }

  /**
   * Process all prepared card commands (outside a Secure Session).
   *
   * <p>Note: commands prepared prior to the invocation of this method shall not require the use of
   * a SAM.
   *
   * @param channelControl indicates if the card channel of the card reader must be closed after
   *     the. last command
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
            "The checking of the SV operation by the SAM has failed.", e);
      } catch (CalypsoSamCommandException e) {
        throw new SamAnomalyException(
            SAM_COMMAND_ERROR + "checking the SV operation: " + e.getCommand().getName(), e);
      } catch (ReaderBrokenCommunicationException e) {
        throw new SvAuthenticationException(
            SAM_READER_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
      } catch (CardBrokenCommunicationException e) {
        throw new SvAuthenticationException(SAM_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
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

    // A session is open, we have to care about the card modifications buffer
    List<AbstractCardCommand> cardAtomicCommands = new ArrayList<AbstractCardCommand>();

    AtomicInteger neededSessionBufferSpace = new AtomicInteger();
    AtomicBoolean overflow = new AtomicBoolean();

    for (AbstractCardCommand command : cardCommandManager.getCardCommands()) {
      // check if the command is a modifying one and get it status (overflow yes/no,
      // neededSessionBufferSpace)
      // if the command overflows the session buffer in atomic modification mode, an exception
      // is raised.
      if (checkModifyingCommand(command, overflow, neededSessionBufferSpace)) {
        if (overflow.get()) {
          // The current command would overflow the modifications buffer in the card. We
          // send the current commands and update the command list. The command Iterator is
          // kept all along the process.
          processAtomicCardCommands(cardAtomicCommands, ChannelControl.KEEP_OPEN);
          // Close the session and reset the modifications buffer counters for the next
          // round
          processAtomicClosing(null, false, ChannelControl.KEEP_OPEN);
          resetModificationsBufferCounter();
          // We reopen a new session for the remaining commands to be sent
          processAtomicOpening(currentWriteAccessLevel, null);
          // Clear the list and add the command that did not fit in the card modifications
          // buffer. We also update the usage counter without checking the result.
          cardAtomicCommands.clear();
          cardAtomicCommands.add(command);
          // just update modifications buffer usage counter, ignore result (always false)
          isSessionBufferOverflowed(neededSessionBufferSpace.get());
        } else {
          // The command fits in the card modifications buffer, just add it to the list
          cardAtomicCommands.add(command);
        }
      } else {
        // This command does not affect the card modifications buffer
        cardAtomicCommands.add(command);
      }
    }

    if (!cardAtomicCommands.isEmpty()) {
      processAtomicCardCommands(cardAtomicCommands, ChannelControl.KEEP_OPEN);
    }

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();
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

    checkSessionIsOpen();

    boolean atLeastOneReadCommand = false;
    boolean sessionPreviouslyClosed = false;

    AtomicInteger neededSessionBufferSpace = new AtomicInteger();
    AtomicBoolean overflow = new AtomicBoolean();

    List<AbstractCardCommand> cardAtomicCommands = new ArrayList<AbstractCardCommand>();
    for (AbstractCardCommand command : cardCommandManager.getCardCommands()) {
      // check if the command is a modifying one and get it status (overflow yes/no,
      // neededSessionBufferSpace)
      // if the command overflows the session buffer in atomic modification mode, an exception
      // is raised.
      if (checkModifyingCommand(command, overflow, neededSessionBufferSpace)) {
        if (overflow.get()) {
          // Reopen a session with the same access level if it was previously closed in
          // this current processClosing
          if (sessionPreviouslyClosed) {
            processAtomicOpening(currentWriteAccessLevel, null);
          }

          // If at least one non-modifying was prepared, we use processAtomicCardCommands
          // instead of processAtomicClosing to send the list
          if (atLeastOneReadCommand) {
            processAtomicCardCommands(cardAtomicCommands, ChannelControl.KEEP_OPEN);
            // Clear the list of commands sent
            cardAtomicCommands.clear();
            processAtomicClosing(cardAtomicCommands, false, ChannelControl.KEEP_OPEN);
            resetModificationsBufferCounter();
            sessionPreviouslyClosed = true;
            atLeastOneReadCommand = false;
          } else {
            // All commands in the list are 'modifying the card'
            processAtomicClosing(cardAtomicCommands, false, ChannelControl.KEEP_OPEN);
            // Clear the list of commands sent
            cardAtomicCommands.clear();
            resetModificationsBufferCounter();
            sessionPreviouslyClosed = true;
          }

          // Add the command that did not fit in the card modifications
          // buffer. We also update the usage counter without checking the result.
          cardAtomicCommands.add(command);
          // just update modifications buffer usage counter, ignore result (always false)
          isSessionBufferOverflowed(neededSessionBufferSpace.get());
        } else {
          // The command fits in the card modifications buffer, just add it to the list
          cardAtomicCommands.add(command);
        }
      } else {
        // This command does not affect the card modifications buffer
        cardAtomicCommands.add(command);
        atLeastOneReadCommand = true;
      }
    }
    if (sessionPreviouslyClosed) {
      // Reopen a session if necessary
      processAtomicOpening(currentWriteAccessLevel, null);
    }

    // Finally, close the session as requested
    processAtomicClosing(
        cardAtomicCommands,
        ((CardSecuritySettingAdapter) cardSecuritySettings).isRatificationMechanismEnabled(),
        channelControl);

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager processCancel() {

    checkSessionIsOpen();

    // card ApduRequestAdapter List to hold Close Secure Session command
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();

    // Build the card Close Session command (in "abort" mode since no signature is provided).
    CmdCardCloseSession cmdCardCloseSession = new CmdCardCloseSession(calypsoCard);

    apduRequests.add(cmdCardCloseSession.getApduRequest());

    // Transfer card commands
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, false);

    CardResponseApi cardResponse = safeTransmit(cardRequest, channelControl);

    try {
      cmdCardCloseSession.setApduResponse(cardResponse.getApduResponses().get(0)).checkStatus();
    } catch (CardCommandException e) {
      throw new CardAnomalyException(
          CARD_COMMAND_ERROR + "processing the response to close session: " + e.getCommand(), e);
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
    if (cardSecuritySettings != null
        && !((CardSecuritySettingAdapter) cardSecuritySettings).isPinPlainTransmissionEnabled()) {

      // CL-PIN-GETCHAL.1
      cardCommandManager.addRegularCommand(new CmdCardGetChallenge(calypsoCard.getCardClass()));

      // transmit and receive data with the card
      processAtomicCardCommands(cardCommandManager.getCardCommands(), ChannelControl.KEEP_OPEN);

      // sets the flag indicating that the commands have been executed
      cardCommandManager.notifyCommandsProcessed();

      // Get the encrypted PIN with the help of the SAM
      byte[] cipheredPin;
      try {
        cipheredPin =
            samCommandProcessor.getCipheredPinData(calypsoCard.getCardChallenge(), pin, null);
      } catch (CalypsoSamCommandException e) {
        throw new SamAnomalyException(
            SAM_COMMAND_ERROR + "generating of the PIN ciphered data: " + e.getCommand().getName(),
            e);
      } catch (ReaderBrokenCommunicationException e) {
        throw new SamIOException(
            SAM_READER_COMMUNICATION_ERROR + GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR, e);
      } catch (CardBrokenCommunicationException e) {
        throw new SamIOException(
            SAM_COMMUNICATION_ERROR + GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR, e);
      }
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
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardTransactionManager processChangePin(byte[] newPin) {

    Assert.getInstance()
        .notNull(newPin, "newPin")
        .isEqual(newPin.length, CalypsoCardConstant.PIN_LENGTH, "PIN length");

    if (!calypsoCard.isPinFeatureAvailable()) {
      throw new UnsupportedOperationException(PIN_NOT_AVAILABLE_ERROR);
    }

    if (sessionState == SessionState.SESSION_OPEN) {
      throw new IllegalStateException("Change PIN not allowed when a secure session is open.");
    }

    // CL-PIN-MENCRYPT.1
    if (((CardSecuritySettingAdapter) cardSecuritySettings).isPinPlainTransmissionEnabled()) {
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
      byte[] newPinData;
      byte[] currentPin = new byte[4]; // all zeros as required
      try {
        newPinData =
            samCommandProcessor.getCipheredPinData(
                calypsoCard.getCardChallenge(), currentPin, newPin);
      } catch (CalypsoSamCommandException e) {
        throw new SamAnomalyException(
            SAM_COMMAND_ERROR + "generating of the PIN ciphered data: " + e.getCommand().getName(),
            e);
      } catch (ReaderBrokenCommunicationException e) {
        throw new SamIOException(
            SAM_READER_COMMUNICATION_ERROR + GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR, e);
      } catch (CardBrokenCommunicationException e) {
        throw new SamIOException(
            SAM_COMMUNICATION_ERROR + GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR, e);
      }
      cardCommandManager.addRegularCommand(
          new CmdCardChangePin(calypsoCard.getCardClass(), newPinData));
    }

    // transmit and receive data with the card
    processAtomicCardCommands(cardCommandManager.getCardCommands(), channelControl);

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();

    return this;
  }

  private CardResponseApi safeTransmit(CardRequestSpi cardRequest, ChannelControl channelControl) {
    try {
      return cardReader.transmitCardRequest(cardRequest, channelControl);
    } catch (ReaderBrokenCommunicationException e) {
      throw new CardIOException(CARD_READER_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
    } catch (CardBrokenCommunicationException e) {
      throw new CardIOException(CARD_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
    } catch (UnexpectedStatusWordException e) {
      throw new IllegalStateException(UNEXPECTED_EXCEPTION, e);
    }
  }

  /**
   * Gets the terminal challenge from the SAM, and raises exceptions if necessary.
   *
   * @return A not null reference.
   * @throws SamAnomalyException If SAM returned an unexpected response.
   * @throws SamIOException If the communication with the SAM or the SAM reader failed.
   */
  private byte[] getSessionTerminalChallenge() {
    byte[] sessionTerminalChallenge;
    try {
      sessionTerminalChallenge = samCommandProcessor.getSessionTerminalChallenge();
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR + "getting the terminal challenge: " + e.getCommand().getName(), e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR + "getting the terminal challenge.", e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(SAM_COMMUNICATION_ERROR + "getting terminal challenge.", e);
    }
    return sessionTerminalChallenge;
  }

  /**
   * Gets the terminal signature from the SAM, and raises exceptions if necessary.
   *
   * @return A not null reference.
   * @throws SamAnomalyException If SAM returned an unexpected response.
   * @throws SamIOException If the communication with the SAM or the SAM reader failed.
   */
  private byte[] getSessionTerminalSignature() {
    byte[] sessionTerminalSignature;
    try {
      sessionTerminalSignature = samCommandProcessor.getTerminalSignature();
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR + "getting the terminal signature: " + e.getCommand().getName(), e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(SAM_COMMUNICATION_ERROR + "getting the terminal signature.", e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR + "getting the terminal signature.", e);
    }
    return sessionTerminalSignature;
  }

  /**
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
          "The authentication of the card by the SAM has failed.", e);
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR + "authenticating the card signature: " + e.getCommand().getName(), e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR + "authenticating the card signature.", e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(SAM_COMMUNICATION_ERROR + "authenticating the card signature.", e);
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
          "The checking of the SV operation by the SAM has failed.", e);
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR + "checking the SV operation: " + e.getCommand().getName(), e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(SAM_READER_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(SAM_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
    }
  }

  /**
   * Checks if a Secure Session is open, raises an exception if not
   *
   * @throws IllegalStateException if no session is open
   */
  private void checkSessionIsOpen() {
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
  private void checkSessionIsNotOpen() {
    if (sessionState == SessionState.SESSION_OPEN) {
      throw new IllegalStateException(
          "Bad session state. Current: " + sessionState + ", expected: not open");
    }
  }

  /**
   * Checks if the number of responses matches the number of commands.<br>
   * Throw a {@link DesynchronizedExchangesException} if not.
   *
   * @param commandsNumber the number of commands.
   * @param responsesNumber the number of responses.
   * @throws DesynchronizedExchangesException if the test failed
   */
  private void checkCommandsResponsesSynchronization(int commandsNumber, int responsesNumber) {
    if (commandsNumber != responsesNumber) {
      throw new DesynchronizedExchangesException(
          "The number of commands/responses does not match: cmd="
              + commandsNumber
              + ", resp="
              + responsesNumber);
    }
  }

  /**
   * Checks the provided command from the session buffer overflow management perspective<br>
   * A exception is raised if the session buffer is overflowed in ATOMIC modification mode.<br>
   * Returns false if the command does not affect the session buffer.<br>
   * Sets the overflow flag and the neededSessionBufferSpace value according to the characteristics
   * of the command in other cases.
   *
   * @param command the command.
   * @param overflow flag set to true if the command overflowed the buffer.
   * @param neededSessionBufferSpace updated with the size of the buffer consumed by the command.
   * @return True if the command modifies the content of the card, false if not
   * @throws AtomicTransactionException if the command overflows the buffer in ATOMIC modification
   *     mode
   */
  private boolean checkModifyingCommand(
      AbstractCardCommand command, AtomicBoolean overflow, AtomicInteger neededSessionBufferSpace) {
    if (command.isSessionBufferUsed()) {
      // This command affects the card modifications buffer
      neededSessionBufferSpace.set(
          command.getApduRequest().getApdu().length
              + SESSION_BUFFER_CMD_ADDITIONAL_COST
              - APDU_HEADER_LENGTH);
      if (isSessionBufferOverflowed(neededSessionBufferSpace.get())) {
        // raise an exception if in atomic mode
        // CL-CSS-REQUEST.1
        // CL-CSS-SMEXCEED.1
        // CL-CSS-INFOCSS.1
        if (!((CardSecuritySettingAdapter) cardSecuritySettings).isMultipleSessionEnabled()) {
          throw new AtomicTransactionException(
              "ATOMIC mode error! This command would overflow the card modifications buffer: "
                  + command.getName());
        }
        overflow.set(true);
      } else {
        overflow.set(false);
      }
      return true;
    } else return false;
  }

  /**
   * Checks whether the requirement for the modifications buffer of the command provided in argument
   * is compatible with the current usage level of the buffer.
   *
   * <p>If it is compatible, the requirement is subtracted from the current level and the method
   * returns false. If this is not the case, the method returns true and the current level is left
   * unchanged.
   *
   * @param sessionBufferSizeConsumed session buffer requirement.
   * @return True or false
   */
  private boolean isSessionBufferOverflowed(int sessionBufferSizeConsumed) {
    boolean isSessionBufferFull = false;
    if (calypsoCard.isModificationsCounterInBytes()) {
      if (modificationsCounter - sessionBufferSizeConsumed >= 0) {
        modificationsCounter = modificationsCounter - sessionBufferSizeConsumed;
      } else {
        if (logger.isDebugEnabled()) {
          logger.debug(
              "Modifications buffer overflow! BYTESMODE, CURRENTCOUNTER = {}, REQUIREMENT = {}",
              modificationsCounter,
              sessionBufferSizeConsumed);
        }
        isSessionBufferFull = true;
      }
    } else {
      if (modificationsCounter > 0) {
        modificationsCounter--;
      } else {
        if (logger.isDebugEnabled()) {
          logger.debug(
              "Modifications buffer overflow! COMMANDSMODE, CURRENTCOUNTER = {}, REQUIREMENT = {}",
              modificationsCounter,
              1);
        }
        isSessionBufferFull = true;
      }
    }
    return isSessionBufferFull;
  }

  /** Initialized the modifications buffer counter to its maximum value for the current card */
  private void resetModificationsBufferCounter() {
    if (logger.isTraceEnabled()) {
      logger.trace(
          "Modifications buffer counter reset: PREVIOUSVALUE = {}, NEWVALUE = {}",
          modificationsCounter,
          calypsoCard.getModificationsCounter());
    }
    modificationsCounter = calypsoCard.getModificationsCounter();
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
   */
  @Override
  public final CardTransactionManager prepareSelectFile(byte[] lid) {

    Assert.getInstance().notNull(lid, "lid").isEqual(lid.length, 2, "lid length");

    // create the command and add it to the list of commands
    cardCommandManager.addRegularCommand(new CmdCardSelectFile(calypsoCard.getCardClass(), lid));

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
      default:
        throw new UnsupportedOperationException("Unsupported Get Data tag: " + tag.name());
    }

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareReadRecordFile(byte sfi, int recordNumber) {

    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            recordNumber,
            CalypsoCardConstant.NB_REC_MIN,
            CalypsoCardConstant.NB_REC_MAX,
            RECORD_NUMBER);

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
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareReadRecordFile(
      byte sfi, int firstRecordNumber, int numberOfRecords, int recordSize) {

    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi") //
        .isInRange(
            firstRecordNumber,
            CalypsoCardConstant.NB_REC_MIN,
            CalypsoCardConstant.NB_REC_MAX,
            "firstRecordNumber") //
        .isInRange(
            numberOfRecords,
            CalypsoCardConstant.NB_REC_MIN,
            CalypsoCardConstant.NB_REC_MAX - firstRecordNumber,
            "numberOfRecords");

    if (numberOfRecords == 1) {
      // create the command and add it to the list of commands
      cardCommandManager.addRegularCommand(
          new CmdCardReadRecords(
              calypsoCard.getCardClass(),
              sfi,
              firstRecordNumber,
              CmdCardReadRecords.ReadMode.ONE_RECORD,
              recordSize));
    } else {
      // Manages the reading of multiple records taking into account the transmission capacity
      // of the card and the response format (2 extra bytes)
      // Multiple APDUs can be generated depending on record size and transmission capacity.
      int recordsPerApdu = calypsoCard.getPayloadCapacity() / (recordSize + 2);
      int maxSizeDataPerApdu = recordsPerApdu * (recordSize + 2);
      int remainingRecords = numberOfRecords;
      int startRecordNumber = firstRecordNumber;
      while (remainingRecords > 0) {
        int expectedLength;
        if (remainingRecords > recordsPerApdu) {
          expectedLength = maxSizeDataPerApdu;
          remainingRecords = remainingRecords - recordsPerApdu;
          startRecordNumber = startRecordNumber + recordsPerApdu;
        } else {
          expectedLength = remainingRecords * (recordSize + 2);
          remainingRecords = 0;
        }
        // create the command and add it to the list of commands
        cardCommandManager.addRegularCommand(
            new CmdCardReadRecords(
                calypsoCard.getCardClass(),
                sfi,
                startRecordNumber,
                CmdCardReadRecords.ReadMode.MULTIPLE_RECORD,
                expectedLength));
      }
    }

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareReadCounterFile(byte sfi, int countersNumber) {
    prepareReadRecordFile(sfi, 1, 1, countersNumber * 3);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareAppendRecord(byte sfi, byte[] recordData) {
    Assert.getInstance() //
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
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi") //
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
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi") //
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
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareIncreaseCounter(
      byte sfi, int counterNumber, int incValue) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi") //
        .isInRange(
            counterNumber,
            CalypsoCardConstant.NB_CNT_MIN,
            CalypsoCardConstant.NB_CNT_MAX,
            "counterNumber") //
        .isInRange(
            incValue,
            CalypsoCardConstant.CNT_VALUE_MIN,
            CalypsoCardConstant.CNT_VALUE_MAX,
            "incValue");

    // create the command and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CmdCardIncrease(calypsoCard.getCardClass(), sfi, counterNumber, incValue));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareDecreaseCounter(
      byte sfi, int counterNumber, int decValue) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi") //
        .isInRange(
            counterNumber,
            CalypsoCardConstant.NB_CNT_MIN,
            CalypsoCardConstant.NB_CNT_MAX,
            "counterNumber") //
        .isInRange(
            decValue,
            CalypsoCardConstant.CNT_VALUE_MIN,
            CalypsoCardConstant.CNT_VALUE_MAX,
            "decValue");

    // create the command and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CmdCardDecrease(calypsoCard.getCardClass(), sfi, counterNumber, decValue));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareSetCounter(byte sfi, int counterNumber, int newValue) {
    int delta;
    try {
      delta =
          newValue
              - calypsoCard.getFileBySfi(sfi).getData().getContentAsCounterValue(counterNumber);
    } catch (NoSuchElementException ex) {
      throw new IllegalStateException(
          "The value for counter " + counterNumber + " in file " + sfi + " is not available");
    }
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
    if (((CardSecuritySettingAdapter) cardSecuritySettings).isSvLoadAndDebitLogEnabled()
        && (!calypsoCard.isExtendedModeSupported())) {
      // @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit logs are requested
      // for a non rev3.2 card add two SvGet commands (for RELOAD then for DEBIT).
      // CL-SV-GETNUMBER.1
      SvOperation operation1 =
          SvOperation.RELOAD.equals(svOperation) ? SvOperation.DEBIT : SvOperation.RELOAD;
      cardCommandManager.addStoredValueCommand(
          new CmdCardSvGet(calypsoCard.getCardClass(), calypsoCard, operation1), operation1);
    }
    cardCommandManager.addStoredValueCommand(
        new CmdCardSvGet(calypsoCard.getCardClass(), calypsoCard, svOperation), svOperation);
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
    // create the initial command with the application data
    CmdCardSvReload svReloadCmdBuild =
        new CmdCardSvReload(calypsoCard, amount, calypsoCard.getSvKvc(), date, time, free);

    // get the security data from the SAM
    byte[] svReloadComplementaryData;
    try {
      svReloadComplementaryData =
          samCommandProcessor.getSvReloadComplementaryData(
              svReloadCmdBuild, calypsoCard.getSvGetHeader(), calypsoCard.getSvGetData());
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR + "preparing the SV reload command: " + e.getCommand().getName(), e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR + "preparing the SV reload command.", e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(SAM_COMMUNICATION_ERROR + "preparing the SV reload command.", e);
    }

    // finalize the SvReload command with the data provided by the SAM
    svReloadCmdBuild.finalizeCommand(svReloadComplementaryData);

    // create and keep the CalypsoCardCommand
    cardCommandManager.addStoredValueCommand(svReloadCmdBuild, SvOperation.RELOAD);

    return this;
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
   * Schedules the execution of a <b>SV Debit</b> command to decrease the current SV balance.
   *
   * <p>It consists in decreasing the current balance of the SV by a certain amount.
   *
   * <p>Note: the key used is the debit key
   *
   * @param amount the amount to be subtracted, positive integer in the range 0..32767
   * @param date 2-byte free value.
   * @param time 2-byte free value.
   */
  private void prepareSvDebitPriv(int amount, byte[] date, byte[] time)
      throws CardBrokenCommunicationException, ReaderBrokenCommunicationException,
          CalypsoSamCommandException {

    if (!((CardSecuritySettingAdapter) cardSecuritySettings).isSvNegativeBalanceAuthorized()
        && (calypsoCard.getSvBalance() - amount) < 0) {
      throw new IllegalStateException("Negative balances not allowed.");
    }

    // create the initial command with the application data
    CmdCardSvDebit svDebitCmdBuild =
        new CmdCardSvDebit(calypsoCard, amount, calypsoCard.getSvKvc(), date, time);

    // get the security data from the SAM
    byte[] svDebitComplementaryData;
    svDebitComplementaryData =
        samCommandProcessor.getSvDebitComplementaryData(
            svDebitCmdBuild, calypsoCard.getSvGetHeader(), calypsoCard.getSvGetData());

    // finalize the SvDebit command with the data provided by the SAM
    svDebitCmdBuild.finalizeCommand(svDebitComplementaryData);

    // create and keep the CalypsoCardCommand
    cardCommandManager.addStoredValueCommand(svDebitCmdBuild, SvOperation.DEBIT);
  }

  /**
   * Prepares an SV Undebit (partially or totally cancels the last SV debit command).
   *
   * <p>It consists in canceling a previous debit. <br>
   * Note: the key used is the debit key
   *
   * @param amount the amount to be subtracted, positive integer in the range 0..32767
   * @param date 2-byte free value.
   * @param time 2-byte free value.
   */
  private void prepareSvUndebitPriv(int amount, byte[] date, byte[] time)
      throws CardBrokenCommunicationException, ReaderBrokenCommunicationException,
          CalypsoSamCommandException {

    // create the initial command with the application data
    CmdCardSvUndebit svUndebitCmdBuild =
        new CmdCardSvUndebit(calypsoCard, amount, calypsoCard.getSvKvc(), date, time);

    // get the security data from the SAM
    byte[] svDebitComplementaryData;
    svDebitComplementaryData =
        samCommandProcessor.getSvUndebitComplementaryData(
            svUndebitCmdBuild, calypsoCard.getSvGetHeader(), calypsoCard.getSvGetData());

    // finalize the SvUndebit command with the data provided by the SAM
    svUndebitCmdBuild.finalizeCommand(svDebitComplementaryData);

    // create and keep the CalypsoCardCommand
    cardCommandManager.addStoredValueCommand(svUndebitCmdBuild, SvOperation.DEBIT);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final CardTransactionManager prepareSvDebit(int amount, byte[] date, byte[] time) {
    try {
      if (SvAction.DO.equals(svAction)) {
        prepareSvDebitPriv(amount, date, time);
      } else {
        prepareSvUndebitPriv(amount, date, time);
      }
    } catch (CalypsoSamCommandException e) {
      throw new SamAnomalyException(
          SAM_COMMAND_ERROR + "preparing the SV debit/undebit command: " + e.getCommand().getName(),
          e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_READER_COMMUNICATION_ERROR + "preparing the SV debit/undebit command.", e);
    } catch (CardBrokenCommunicationException e) {
      throw new SamIOException(
          SAM_COMMUNICATION_ERROR + "preparing the SV debit/undebit command.", e);
    }

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
    prepareReadRecordFile(
        CalypsoCardConstant.SV_RELOAD_LOG_FILE_SFI, CalypsoCardConstant.SV_RELOAD_LOG_FILE_NB_REC);
    prepareReadRecordFile(
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
  }
}
