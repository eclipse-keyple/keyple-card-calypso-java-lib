/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://www.calypsonet-asso.org/
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
import org.calypsonet.terminal.card.*;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.calypsonet.terminal.reader.CardReader;
import org.eclipse.keyple.card.calypso.card.CalypsoCard;
import org.eclipse.keyple.card.calypso.card.CardRevision;
import org.eclipse.keyple.card.calypso.card.ElementaryFile;
import org.eclipse.keyple.card.calypso.card.SelectFileControl;
import org.eclipse.keyple.card.calypso.transaction.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Implementation of {@link CardTransactionService}.
 *
 * @since 2.0
 */
class CardTransactionServiceAdapter implements CardTransactionService {

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
  private static final String TRANSMITTING_COMMANDS = "transmitting commands.";
  private static final String CHECKING_THE_SV_OPERATION = "checking the SV operation.";
  private static final String UNEXPECTED_EXCEPTION = "An unexpected exception was raised.";

  // commands that modify the content of the card in session have a cost on the session buffer equal
  // to the length of the outgoing data plus 6 bytes
  private static final int SESSION_BUFFER_CMD_ADDITIONAL_COST = 6;

  private static final int APDU_HEADER_LENGTH = 5;

  private static final Logger logger = LoggerFactory.getLogger(CardTransactionServiceAdapter.class);

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
  private SessionAccessLevel currentSessionAccessLevel;
  /** modifications counter management */
  private int modificationsCounter;
  /** The object for managing card commands */
  private final CardCommandManager cardCommandManager;
  /** The current Store Value action */
  private SvSettings.Action svAction;
  /** The {@link ChannelControl} action */
  private ChannelControl channelControl;

  /**
   * The card Transaction State defined with the elements: ‘IOError’, ‘SEInserted’ and ‘SERemoval’.
   */
  private enum SessionState {
    /** Initial state of a card transaction. The card must have been previously selected. */
    SESSION_UNINITIALIZED,
    /** The secure session is active. */
    SESSION_OPEN,
    /** The secure session is closed. */
    SESSION_CLOSED
  }

  /**
   * Creates an instance of {@link CardTransactionService} for secure operations.
   *
   * <p>Secure operations are enabled by the presence of {@link CardSecuritySetting}.
   *
   * @param cardReader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @param cardSecuritySetting The security settings.
   * @since 2.0
   */
  public CardTransactionServiceAdapter(
      CardReader cardReader, CalypsoCard calypsoCard, CardSecuritySetting cardSecuritySetting) {

    this(cardReader, calypsoCard);

    this.cardSecuritySettings = cardSecuritySetting;

    samCommandProcessor = new SamCommandProcessor(calypsoCard, cardSecuritySetting);
  }

  /**
   * Creates an instance of {@link CardTransactionService} for non-secure operations.
   *
   * @param cardReader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @since 2.0
   */
  public CardTransactionServiceAdapter(CardReader cardReader, CalypsoCard calypsoCard) {
    this.cardReader = (ProxyReaderApi) cardReader;

    this.calypsoCard = (CalypsoCardAdapter) calypsoCard;

    modificationsCounter = this.calypsoCard.getModificationsCounter();

    sessionState = SessionState.SESSION_UNINITIALIZED;

    cardCommandManager = new CardCommandManager();

    channelControl = ChannelControl.KEEP_OPEN;
  }

  /**
   * Open a single Secure Session.
   *
   * @param sessionAccessLevel access level of the session (personalization, load or debit).
   * @param cardCommands the card commands inside session.
   * @throws CalypsoCardTransactionIllegalStateException if no {@link CardSecuritySetting} is
   *     available
   * @throws CalypsoCardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processAtomicOpening(
      SessionAccessLevel sessionAccessLevel,
      List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>> cardCommands) {

    // This method should be invoked only if no session was previously open
    checkSessionIsNotOpen();

    if (cardSecuritySettings == null) {
      throw new CalypsoCardTransactionIllegalStateException("No security settings are available.");
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
      AbstractCardCommandBuilder<? extends AbstractCardResponseParser> cardCommand =
          cardCommands.get(0);
      if (cardCommand.getCommandRef() == CalypsoCardCommand.READ_RECORDS
          && ((CardReadRecordsBuilder) cardCommand).getReadMode()
              == CardReadRecordsBuilder.ReadMode.ONE_RECORD) {
        sfi = ((CardReadRecordsBuilder) cardCommand).getSfi();
        recordNumber = ((CardReadRecordsBuilder) cardCommand).getFirstRecordNumber();
        cardCommands.remove(0);
      }
    }

    // Build the card Open Secure Session command
    AbstractCardCommandBuilder<AbstractCardOpenSessionParser> openSessionCmdBuild =
        AbstractCardOpenSessionBuilder.create(
            calypsoCard.getRevision(),
            sessionAccessLevel.getSessionKey(),
            sessionTerminalChallenge,
            sfi,
            recordNumber);

    // Add the resulting ApduRequestAdapter to the card ApduRequestAdapter list
    cardApduRequests.add(openSessionCmdBuild.getApduRequest());

    // Add all optional commands to the card ApduRequestAdapter list
    if (cardCommands != null) {
      cardApduRequests.addAll(getApduRequests(cardCommands));
    }

    // Create a CardRequest from the ApduRequestAdapter list, card AID as Selector, keep channel
    // open
    CardRequestSpi cardRequest = new CardRequestAdapter(cardApduRequests, false);

    // Transmit the commands to the card
    CardResponseApi poCardResponse = safeTransmit(cardRequest, ChannelControl.KEEP_OPEN);

    // Retrieve and check the ApduResponses
    List<ApduResponseApi> poApduResponses = poCardResponse.getApduResponses();

    // Do some basic checks
    checkCommandsResponsesSynchronization(cardApduRequests.size(), poApduResponses.size());

    // Parse the response to Open Secure Session (the first item of poApduResponses)
    // The updateCalypsoCard method fills the CalypsoCard object with the command data and
    // return
    // the parser used for an internal usage here.
    AbstractCardOpenSessionParser poOpenSessionPars;
    try {
      poOpenSessionPars =
          (AbstractCardOpenSessionParser)
              CalypsoCardUtils.updateCalypsoCard(
                  calypsoCard, openSessionCmdBuild, poApduResponses.get(0));
    } catch (CalypsoCardCommandException e) {
      throw new CalypsoCardAnomalyException(
          CARD_COMMAND_ERROR + "processing the response to open session: " + e.getCommand(), e);
    }
    // Build the Digest Init command from card Open Session
    // the session challenge is needed for the SAM digest computation
    byte[] sessionCardChallenge = poOpenSessionPars.getCardChallenge();

    // The card KIF
    byte cardKif = poOpenSessionPars.getSelectedKif();

    // The card KVC, may be null for card Rev 1.0
    byte cardKvc = poOpenSessionPars.getSelectedKvc();

    if (logger.isDebugEnabled()) {
      logger.debug(
          "processAtomicOpening => opening: CARDCHALLENGE = {}, CARDKIF = {}, CARDKVC = {}",
          ByteArrayUtil.toHex(sessionCardChallenge),
          String.format("%02X", cardKif),
          String.format("%02X", cardKvc));
    }

    if (!cardSecuritySettings.isKvcAuthorized(cardKvc)) {
      throw new CalypsoUnauthorizedKvcException(
          String.format("Unauthorized KVC error: card KVC = %02X", cardKvc));
    }

    // Initialize the digest processor. It will store all digest operations (Digest Init, Digest
    // Update) until the session closing. At this moment, all SAM Apdu will be processed at
    // once.
    samCommandProcessor.initializeDigester(
        sessionAccessLevel, false, false, cardKif, cardKvc, poApduResponses.get(0).getDataOut());

    // Add all commands data to the digest computation. The first command in the list is the
    // open secure session command. This command is not included in the digest computation, so
    // we skip it and start the loop at index 1.
    if ((cardCommands != null) && !cardCommands.isEmpty()) {
      // Add requests and responses to the digest processor
      samCommandProcessor.pushCardExchangedData(cardApduRequests, poApduResponses, 1);
    }

    // Remove Open Secure Session response and create a new CardResponse
    poApduResponses.remove(0);

    // update CalypsoCard with the received data
    // TODO check if this is not redundant with what is done 40 lines above
    try {
      CalypsoCardUtils.updateCalypsoCard(calypsoCard, cardCommands, poApduResponses);
    } catch (CalypsoCardCommandException e) {
      throw new CalypsoCardAnomalyException(
          CARD_COMMAND_ERROR + "processing the response to open session: " + e.getCommand(), e);
    }

    sessionState = SessionState.SESSION_OPEN;
  }

  /**
   * Create an ApduRequestAdapter List from a AbstractCardCommandBuilder List.
   *
   * @param cardCommands a list of card commands.
   * @return The ApduRequestAdapter list
   */
  private List<ApduRequestSpi> getApduRequests(
      List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>> cardCommands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    if (cardCommands != null) {
      for (AbstractCardCommandBuilder<? extends AbstractCardResponseParser> commandBuilder :
          cardCommands) {
        apduRequests.add(commandBuilder.getApduRequest());
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
   * @throws CalypsoCardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processAtomicCardCommands(
      List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>> cardCommands,
      ChannelControl channelControl) {

    // Get the card ApduRequestAdapter List
    List<ApduRequestSpi> apduRequests = getApduRequests(cardCommands);

    // Create a CardRequest from the ApduRequestAdapter list, card AID as Selector, manage the
    // logical
    // channel according to the channelControl
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, false);

    // Transmit the commands to the card
    CardResponseApi poCardResponse = safeTransmit(cardRequest, channelControl);

    // Retrieve and check the ApduResponses
    List<ApduResponseApi> poApduResponses = poCardResponse.getApduResponses();

    // Do some basic checks
    checkCommandsResponsesSynchronization(apduRequests.size(), poApduResponses.size());

    // Add all commands data to the digest computation if this method is invoked within a Secure
    // Session.
    if (sessionState == SessionState.SESSION_OPEN) {
      samCommandProcessor.pushCardExchangedData(apduRequests, poApduResponses, 0);
    }

    try {
      CalypsoCardUtils.updateCalypsoCard(
          calypsoCard, cardCommands, poCardResponse.getApduResponses());
    } catch (CalypsoCardCommandException e) {
      throw new CalypsoCardAnomalyException(
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
   *   <li>The card responses of the poModificationCommands are compared with the
   *       poAnticipatedResponses. The card signature is identified from the card Close Session
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
   * @param poAnticipatedResponses a list of anticipated card responses to the modification
   *     commands.
   * @param isRatificationMechanismEnabled true if the ratification is closed not ratified and a
   *     ratification command must be sent.
   * @param channelControl indicates if the card channel of the card reader must be closed after
   *     the. last command
   * @throws CalypsoCardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processAtomicClosing(
      List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>>
          cardModificationCommands,
      List<ApduResponseApi> poAnticipatedResponses,
      boolean isRatificationMechanismEnabled,
      ChannelControl channelControl) {

    checkSessionIsOpen();

    // Get the card ApduRequestAdapter List - for the first card exchange
    List<ApduRequestSpi> apduRequests = getApduRequests(cardModificationCommands);

    // Compute "anticipated" Digest Update (for optional poModificationCommands)
    if ((cardModificationCommands != null) && !apduRequests.isEmpty()) {
      checkCommandsResponsesSynchronization(apduRequests.size(), poAnticipatedResponses.size());
      // Add all commands data to the digest computation: commands and anticipated
      // responses.
      samCommandProcessor.pushCardExchangedData(apduRequests, poAnticipatedResponses, 0);
    }

    // All SAM digest operations will now run at once.
    // Get Terminal Signature from the latest response
    byte[] sessionTerminalSignature = getSessionTerminalSignature();

    boolean ratificationCommandResponseReceived;

    // Build the card Close Session command. The last one for this session
    CardCloseSessionBuilder closeSessionCmdBuild =
        new CardCloseSessionBuilder(
            calypsoCard.getCardClass(), !isRatificationMechanismEnabled, sessionTerminalSignature);

    apduRequests.add(closeSessionCmdBuild.getApduRequest());

    // Keep the position of the Close Session command in request list
    int closeCommandIndex = apduRequests.size() - 1;

    // Add the card Ratification command if any
    boolean ratificationCommandAdded;
    if (isRatificationMechanismEnabled && ((CardReader) cardReader).isContactless()) {
      apduRequests.add(CardRatificationBuilder.getApduRequest(calypsoCard.getCardClass()));
      ratificationCommandAdded = true;
    } else {
      ratificationCommandAdded = false;
    }

    // Transfer card commands
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, false);

    CardResponseApi poCardResponse;
    try {
      poCardResponse = cardReader.transmitCardRequest(cardRequest, channelControl);
      // if the ratification command was added and no error occurred then the response has been
      // received
      ratificationCommandResponseReceived = ratificationCommandAdded;
    } catch (CardBrokenCommunicationException e) {
      poCardResponse = e.getCardResponse();
      // The current exception may have been caused by a communication issue with the card
      // during the ratification command.
      //
      // In this case, we do not stop the process and consider the Secure Session close. We'll
      // check the signature.
      //
      // We should have one response less than requests.
      if (!ratificationCommandAdded
          || poCardResponse == null
          || poCardResponse.getApduResponses().size() != apduRequests.size() - 1) {
        throw new CalypsoCardIOException(CARD_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
      }
      // we received all responses except the response to the ratification command
      ratificationCommandResponseReceived = false;
    } catch (ReaderBrokenCommunicationException e) {
      throw new CalypsoCardIOException(CARD_READER_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
    } catch (UnexpectedStatusWordException e) {
      throw new IllegalStateException(UNEXPECTED_EXCEPTION, e);
    }

    List<ApduResponseApi> apduResponses = poCardResponse.getApduResponses();

    // Check the commands executed before closing the secure session (only responses to these
    // commands will be taken into account)
    try {
      CalypsoCardUtils.updateCalypsoCard(calypsoCard, cardModificationCommands, apduResponses);
    } catch (CalypsoCardCommandException e) {
      throw new CalypsoCardAnomalyException(
          CARD_COMMAND_ERROR
              + "processing of responses preceding the close of the session: "
              + e.getCommand(),
          e);
    }

    // Check the card's response to Close Secure Session
    CardCloseSessionParser cardCloseSessionPars =
        getCardCloseSessionParser(apduResponses, closeSessionCmdBuild, closeCommandIndex);

    // Check the card signature
    checkCardSignature(cardCloseSessionPars.getSignatureLo());

    // If necessary, we check the status of the SV after the session has been successfully
    // closed.
    if (cardCommandManager.isSvOperationCompleteOneTime()) {
      checkSvOperationStatus(cardCloseSessionPars.getPostponedData());
    }

    sessionState = SessionState.SESSION_CLOSED;

    if (ratificationCommandResponseReceived) { // NOSONAR: boolean change in catch
      // is not taken into account by
      // Sonar
      // Remove the ratification response
      apduResponses.remove(apduResponses.size() - 1);
    }

    // Remove Close Secure Session response and create a new CardResponse
    apduResponses.remove(apduResponses.size() - 1);
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
   * @throws CalypsoCardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processAtomicClosing(
      List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>> cardCommands,
      boolean isRatificationMechanismEnabled,
      ChannelControl channelControl) {
    List<ApduResponseApi> poAnticipatedResponses = getAnticipatedResponses(cardCommands);
    processAtomicClosing(
        cardCommands, poAnticipatedResponses, isRatificationMechanismEnabled, channelControl);
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
      throw new CalypsoCardTransactionIllegalStateException(
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
   * @throws CalypsoCardTransactionIllegalStateException if the anticipation process failed
   */
  private List<ApduResponseApi> getAnticipatedResponses(
      List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>> cardCommands) {
    List<ApduResponseApi> apduResponses = new ArrayList<ApduResponseApi>();
    if (cardCommands != null) {
      for (AbstractCardCommandBuilder<? extends AbstractCardResponseParser> commandBuilder :
          cardCommands) {
        if (commandBuilder.getCommandRef() == CalypsoCardCommand.DECREASE) {
          int sfi = ((CardDecreaseBuilder) commandBuilder).getSfi();
          int counter = ((CardDecreaseBuilder) commandBuilder).getCounterNumber();
          int newCounterValue =
              getCounterValue(sfi, counter) - ((CardDecreaseBuilder) commandBuilder).getDecValue();
          apduResponses.add(createIncreaseDecreaseResponse(newCounterValue));
        } else if (commandBuilder.getCommandRef() == CalypsoCardCommand.INCREASE) {
          int sfi = ((CardIncreaseBuilder) commandBuilder).getSfi();
          int counter = ((CardIncreaseBuilder) commandBuilder).getCounterNumber();
          int newCounterValue =
              getCounterValue(sfi, counter) + ((CardIncreaseBuilder) commandBuilder).getIncValue();
          apduResponses.add(createIncreaseDecreaseResponse(newCounterValue));
        } else if (commandBuilder.getCommandRef() == CalypsoCardCommand.SV_RELOAD
            || commandBuilder.getCommandRef() == CalypsoCardCommand.SV_DEBIT
            || commandBuilder.getCommandRef() == CalypsoCardCommand.SV_UNDEBIT) {
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
   * @since 2.0
   */
  @Override
  public final CardTransactionService processOpening(SessionAccessLevel sessionAccessLevel) {
    try {
      currentSessionAccessLevel = sessionAccessLevel;

      // create a sublist of AbstractCardCommandBuilder to be sent atomically
      List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>> poAtomicCommands =
          new ArrayList<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>>();

      AtomicInteger neededSessionBufferSpace = new AtomicInteger();
      AtomicBoolean overflow = new AtomicBoolean();

      for (AbstractCardCommandBuilder<? extends AbstractCardResponseParser> commandBuilder :
          cardCommandManager.getCardCommandBuilders()) {
        // check if the command is a modifying one and get it status (overflow yes/no,
        // neededSessionBufferSpace)
        // if the command overflows the session buffer in atomic modification mode, an exception
        // is raised.
        if (checkModifyingCommand(commandBuilder, overflow, neededSessionBufferSpace)) {
          if (overflow.get()) {
            // Open the session with the current commands
            processAtomicOpening(currentSessionAccessLevel, poAtomicCommands);
            // Closes the session, resets the modifications buffer counters for the next
            // round.
            processAtomicClosing(null, false, ChannelControl.KEEP_OPEN);
            resetModificationsBufferCounter();
            // Clear the list and add the command that did not fit in the card modifications
            // buffer. We also update the usage counter without checking the result.
            poAtomicCommands.clear();
            poAtomicCommands.add(commandBuilder);
            // just update modifications buffer usage counter, ignore result (always false)
            isSessionBufferOverflowed(neededSessionBufferSpace.get());
          } else {
            // The command fits in the card modifications buffer, just add it to the list
            poAtomicCommands.add(commandBuilder);
          }
        } else {
          // This command does not affect the card modifications buffer
          poAtomicCommands.add(commandBuilder);
        }
      }

      processAtomicOpening(currentSessionAccessLevel, poAtomicCommands);

      // sets the flag indicating that the commands have been executed
      cardCommandManager.notifyCommandsProcessed();

      return this;
    } catch (RuntimeException e) {
      releaseSamResourceSilently();
      throw e;
    }
  }

  /**
   * Process all prepared card commands (outside a Secure Session).
   *
   * <p>Note: commands prepared prior to the invocation of this method shall not require the use of
   * a SAM.
   *
   * @param channelControl indicates if the card channel of the card reader must be closed after
   *     the. last command
   * @throws CalypsoCardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processCardCommandsOutOfSession(ChannelControl channelControl) {

    // card commands sent outside a Secure Session. No modifications buffer limitation.
    processAtomicCardCommands(cardCommandManager.getCardCommandBuilders(), channelControl);

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();

    // If an SV transaction was performed, we check the signature returned by the card here
    if (cardCommandManager.isSvOperationCompleteOneTime()) {
      try {
        samCommandProcessor.checkSvStatus(CalypsoCardUtils.getSvOperationSignature());
      } catch (CalypsoSamSecurityDataException e) {
        throw new CalypsoSvAuthenticationException(
            "The checking of the SV operation by the SAM has failed.", e);
      } catch (CalypsoSamCommandException e) {
        throw new CalypsoSamAnomalyException(
            SAM_COMMAND_ERROR + "checking the SV operation: " + e.getCommand().getName(), e);
      } catch (ReaderBrokenCommunicationException e) {
        throw new CalypsoSvAuthenticationException(
            SAM_READER_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
      } catch (CardBrokenCommunicationException e) {
        throw new CalypsoSvAuthenticationException(
            SAM_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
      }
    }
  }

  /**
   * Process all prepared card commands in a Secure Session.
   *
   * <p>The multiple session mode is handled according to the session settings.
   *
   * @throws CalypsoCardTransactionException if a functional error occurs (including card and SAM IO
   *     errors)
   */
  private void processCardCommandsInSession() {

    // A session is open, we have to care about the card modifications buffer
    List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>> cardAtomicBuilders =
        new ArrayList<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>>();

    AtomicInteger neededSessionBufferSpace = new AtomicInteger();
    AtomicBoolean overflow = new AtomicBoolean();

    for (AbstractCardCommandBuilder<? extends AbstractCardResponseParser> commandBuilder :
        cardCommandManager.getCardCommandBuilders()) {
      // check if the command is a modifying one and get it status (overflow yes/no,
      // neededSessionBufferSpace)
      // if the command overflows the session buffer in atomic modification mode, an exception
      // is raised.
      if (checkModifyingCommand(commandBuilder, overflow, neededSessionBufferSpace)) {
        if (overflow.get()) {
          // The current command would overflow the modifications buffer in the card. We
          // send the current commands and update the parsers. The parsers Iterator is
          // kept all along the process.
          processAtomicCardCommands(cardAtomicBuilders, ChannelControl.KEEP_OPEN);
          // Close the session and reset the modifications buffer counters for the next
          // round
          processAtomicClosing(null, false, ChannelControl.KEEP_OPEN);
          resetModificationsBufferCounter();
          // We reopen a new session for the remaining commands to be sent
          processAtomicOpening(currentSessionAccessLevel, null);
          // Clear the list and add the command that did not fit in the card modifications
          // buffer. We also update the usage counter without checking the result.
          cardAtomicBuilders.clear();
          cardAtomicBuilders.add(commandBuilder);
          // just update modifications buffer usage counter, ignore result (always false)
          isSessionBufferOverflowed(neededSessionBufferSpace.get());
        } else {
          // The command fits in the card modifications buffer, just add it to the list
          cardAtomicBuilders.add(commandBuilder);
        }
      } else {
        // This command does not affect the card modifications buffer
        cardAtomicBuilders.add(commandBuilder);
      }
    }

    if (!cardAtomicBuilders.isEmpty()) {
      processAtomicCardCommands(cardAtomicBuilders, ChannelControl.KEEP_OPEN);
    }

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService processCardCommands() {
    try {
      if (sessionState == SessionState.SESSION_OPEN) {
        processCardCommandsInSession();
      } else {
        processCardCommandsOutOfSession(channelControl);
      }
      return this;
    } catch (RuntimeException e) {
      releaseSamResourceSilently();
      throw e;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final void processClosing() {
    try {
      checkSessionIsOpen();

      boolean atLeastOneReadCommand = false;
      boolean sessionPreviouslyClosed = false;

      AtomicInteger neededSessionBufferSpace = new AtomicInteger();
      AtomicBoolean overflow = new AtomicBoolean();

      List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>> cardAtomicCommands =
          new ArrayList<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>>();
      for (AbstractCardCommandBuilder<? extends AbstractCardResponseParser> commandBuilder :
          cardCommandManager.getCardCommandBuilders()) {
        // check if the command is a modifying one and get it status (overflow yes/no,
        // neededSessionBufferSpace)
        // if the command overflows the session buffer in atomic modification mode, an exception
        // is raised.
        if (checkModifyingCommand(commandBuilder, overflow, neededSessionBufferSpace)) {
          if (overflow.get()) {
            // Reopen a session with the same access level if it was previously closed in
            // this current processClosing
            if (sessionPreviouslyClosed) {
              processAtomicOpening(currentSessionAccessLevel, null);
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
            cardAtomicCommands.add(commandBuilder);
            // just update modifications buffer usage counter, ignore result (always false)
            isSessionBufferOverflowed(neededSessionBufferSpace.get());
          } else {
            // The command fits in the card modifications buffer, just add it to the list
            cardAtomicCommands.add(commandBuilder);
          }
        } else {
          // This command does not affect the card modifications buffer
          cardAtomicCommands.add(commandBuilder);
          atLeastOneReadCommand = true;
        }
      }
      if (sessionPreviouslyClosed) {
        // Reopen a session if necessary
        processAtomicOpening(currentSessionAccessLevel, null);
      }

      // Finally, close the session as requested
      processAtomicClosing(
          cardAtomicCommands,
          cardSecuritySettings.isRatificationMechanismEnabled(),
          channelControl);

      // sets the flag indicating that the commands have been executed
      cardCommandManager.notifyCommandsProcessed();
    } finally {
      releaseSamResourceSilently();
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final void processCancel() {
    // card ApduRequestAdapter List to hold Close Secure Session command
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();

    // Build the card Close Session command (in "abort" mode since no signature is provided).
    CardCloseSessionBuilder closeSessionCmdBuild =
        new CardCloseSessionBuilder(calypsoCard.getCardClass());

    apduRequests.add(closeSessionCmdBuild.getApduRequest());

    // Transfer card commands
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, false);

    CardResponseApi cardResponse = safeTransmit(cardRequest, channelControl);

    try {
      closeSessionCmdBuild
          .createResponseParser(cardResponse.getApduResponses().get(0))
          .checkStatus();
    } catch (CalypsoCardCommandException e) {
      throw new CalypsoCardAnomalyException(
          CARD_COMMAND_ERROR + "processing the response to close session: " + e.getCommand(), e);
    }

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();

    // session is now considered closed regardless the previous state or the result of the abort
    // session command sent to the card.
    sessionState = SessionState.SESSION_CLOSED;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService processVerifyPin(byte[] pin) {
    Assert.getInstance()
        .notNull(pin, "pin")
        .isEqual(pin.length, CalypsoCardUtils.PIN_LENGTH, "PIN length");

    if (!calypsoCard.isPinFeatureAvailable()) {
      throw new CalypsoCardTransactionIllegalStateException("PIN is not available for this card.");
    }

    if (cardCommandManager.hasCommands()) {
      throw new CalypsoCardTransactionIllegalStateException(
          "No commands should have been prepared prior to a PIN submission.");
    }

    if (cardSecuritySettings != null
        && !cardSecuritySettings.isPinTransmissionEncryptionDisabled()) {
      cardCommandManager.addRegularCommand(new CardGetChallengeBuilder(calypsoCard.getCardClass()));

      // transmit and receive data with the card
      processAtomicCardCommands(
          cardCommandManager.getCardCommandBuilders(), ChannelControl.KEEP_OPEN);

      // sets the flag indicating that the commands have been executed
      cardCommandManager.notifyCommandsProcessed();

      // Get the encrypted PIN with the help of the SAM
      byte[] cipheredPin;
      try {
        cipheredPin =
            samCommandProcessor.getCipheredPinData(CalypsoCardUtils.getCardChallenge(), pin, null);
      } catch (CalypsoSamCommandException e) {
        throw new CalypsoSamAnomalyException(
            SAM_COMMAND_ERROR + "generating of the PIN ciphered data: " + e.getCommand().getName(),
            e);
      } catch (ReaderBrokenCommunicationException e) {
        throw new CalypsoSamIOException(
            SAM_READER_COMMUNICATION_ERROR + "generating of the PIN ciphered data.", e);
      } catch (CardBrokenCommunicationException e) {
        throw new CalypsoSamIOException(
            SAM_COMMUNICATION_ERROR + "generating of the PIN ciphered data.", e);
      }
      cardCommandManager.addRegularCommand(
          new CardVerifyPinBuilder(calypsoCard.getCardClass(), true, cipheredPin));
    } else {
      cardCommandManager.addRegularCommand(
          new CardVerifyPinBuilder(calypsoCard.getCardClass(), false, pin));
    }

    // transmit and receive data with the card
    processAtomicCardCommands(cardCommandManager.getCardCommandBuilders(), channelControl);

    // sets the flag indicating that the commands have been executed
    cardCommandManager.notifyCommandsProcessed();

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService processVerifyPin(String pin) {
    processVerifyPin(pin.getBytes());

    return this;
  }

  private CardResponseApi safeTransmit(CardRequestSpi cardRequest, ChannelControl channelControl) {
    try {
      return cardReader.transmitCardRequest(cardRequest, channelControl);
    } catch (ReaderBrokenCommunicationException e) {
      throw new CalypsoCardIOException(CARD_READER_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
    } catch (CardBrokenCommunicationException e) {
      throw new CalypsoCardIOException(CARD_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
    } catch (UnexpectedStatusWordException e) {
      throw new IllegalStateException(UNEXPECTED_EXCEPTION, e);
    }
  }

  /**
   * Gets the terminal challenge from the SAM, and raises exceptions if necessary.
   *
   * @return A not null reference.
   * @throws CalypsoSamAnomalyException If SAM returned an unexpected response.
   * @throws CalypsoSamIOException If the communication with the SAM or the SAM reader failed.
   */
  private byte[] getSessionTerminalChallenge() {
    byte[] sessionTerminalChallenge;
    try {
      sessionTerminalChallenge = samCommandProcessor.getSessionTerminalChallenge();
    } catch (CalypsoSamCommandException e) {
      throw new CalypsoSamAnomalyException(
          SAM_COMMAND_ERROR + "getting the terminal challenge: " + e.getCommand().getName(), e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + "getting the terminal challenge.", e);
    } catch (CardBrokenCommunicationException e) {
      throw new CalypsoSamIOException(SAM_COMMUNICATION_ERROR + "getting terminal challenge.", e);
    }
    return sessionTerminalChallenge;
  }

  /**
   * Gets the terminal signature from the SAM, and raises exceptions if necessary.
   *
   * @return A not null reference.
   * @throws CalypsoSamAnomalyException If SAM returned an unexpected response.
   * @throws CalypsoSamIOException If the communication with the SAM or the SAM reader failed.
   */
  private byte[] getSessionTerminalSignature() {
    byte[] sessionTerminalSignature;
    try {
      sessionTerminalSignature = samCommandProcessor.getTerminalSignature();
    } catch (CalypsoSamCommandException e) {
      throw new CalypsoSamAnomalyException(
          SAM_COMMAND_ERROR + "getting the terminal signature: " + e.getCommand().getName(), e);
    } catch (CardBrokenCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_COMMUNICATION_ERROR + "getting the terminal signature.", e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + "getting the terminal signature.", e);
    }
    return sessionTerminalSignature;
  }

  /**
   * Ask the SAM to verify the signature of the card, and raises exceptions if necessary.
   *
   * @param cardSignature The card signature.
   * @throws CalypsoSessionAuthenticationException If the card authentication failed.
   * @throws CalypsoSamAnomalyException If SAM returned an unexpected response.
   * @throws CalypsoSamIOException If the communication with the SAM or the SAM reader failed.
   */
  private void checkCardSignature(byte[] cardSignature) {
    try {
      samCommandProcessor.authenticateCardSignature(cardSignature);
    } catch (CalypsoSamSecurityDataException e) {
      throw new CalypsoSessionAuthenticationException(
          "The authentication of the card by the SAM has failed.", e);
    } catch (CalypsoSamCommandException e) {
      throw new CalypsoSamAnomalyException(
          SAM_COMMAND_ERROR + "authenticating the card signature: " + e.getCommand().getName(), e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + "authenticating the card signature.", e);
    } catch (CardBrokenCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_COMMUNICATION_ERROR + "authenticating the card signature.", e);
    }
  }

  /**
   * Ask the SAM to verify the SV operation status from the card postponed data, raises exceptions
   * if needed.
   *
   * @param cardPostponedData The postponed data from the card.
   * @throws CalypsoSvAuthenticationException If the SV verification failed.
   * @throws CalypsoSamAnomalyException If SAM returned an unexpected response.
   * @throws CalypsoSamIOException If the communication with the SAM or the SAM reader failed.
   */
  private void checkSvOperationStatus(byte[] cardPostponedData) {
    try {
      samCommandProcessor.checkSvStatus(cardPostponedData);
    } catch (CalypsoSamSecurityDataException e) {
      throw new CalypsoSvAuthenticationException(
          "The checking of the SV operation by the SAM has failed.", e);
    } catch (CalypsoSamCommandException e) {
      throw new CalypsoSamAnomalyException(
          SAM_COMMAND_ERROR + "checking the SV operation: " + e.getCommand().getName(), e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
    } catch (CardBrokenCommunicationException e) {
      throw new CalypsoSamIOException(SAM_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
    }
  }

  /**
   * Get the close session parser.
   *
   * @param poApduResponses The responses received from the card.
   * @param closeSessionCmdBuild The command builder.
   * @param closeCommandIndex The index of the close command within the request.
   * @throws CalypsoCardCloseSecureSessionException If a security error occurs.
   * @throws CalypsoCardAnomalyException If card returned an unexpected response.
   */
  private CardCloseSessionParser getCardCloseSessionParser(
      List<ApduResponseApi> poApduResponses,
      CardCloseSessionBuilder closeSessionCmdBuild,
      int closeCommandIndex) {
    CardCloseSessionParser poCloseSessionPars;
    try {
      poCloseSessionPars =
          (CardCloseSessionParser)
              CalypsoCardUtils.updateCalypsoCard(
                  calypsoCard, closeSessionCmdBuild, poApduResponses.get(closeCommandIndex));
    } catch (CalypsoCardSecurityDataException e) {
      throw new CalypsoCardCloseSecureSessionException("Invalid card session", e);
    } catch (CalypsoCardCommandException e) {
      throw new CalypsoCardAnomalyException(
          CARD_COMMAND_ERROR + "processing the response to close session: " + e.getCommand(), e);
    }
    return poCloseSessionPars;
  }

  /**
   * Checks if a Secure Session is open, raises an exception if not
   *
   * @throws CalypsoCardTransactionIllegalStateException if no session is open
   */
  private void checkSessionIsOpen() {
    if (sessionState != SessionState.SESSION_OPEN) {
      throw new CalypsoCardTransactionIllegalStateException(
          "Bad session state. Current: "
              + sessionState
              + ", expected: "
              + SessionState.SESSION_OPEN);
    }
  }

  /**
   * Checks if a Secure Session is not open, raises an exception if not
   *
   * @throws CalypsoCardTransactionIllegalStateException if a session is open
   */
  private void checkSessionIsNotOpen() {
    if (sessionState == SessionState.SESSION_OPEN) {
      throw new CalypsoCardTransactionIllegalStateException(
          "Bad session state. Current: " + sessionState + ", expected: not open");
    }
  }

  /**
   * Checks if the number of responses matches the number of commands.<br>
   * Throw a {@link CalypsoDesynchronizedExchangesException} if not.
   *
   * @param commandsNumber the number of commands.
   * @param responsesNumber the number of responses.
   * @throws CalypsoDesynchronizedExchangesException if the test failed
   */
  private void checkCommandsResponsesSynchronization(int commandsNumber, int responsesNumber) {
    if (commandsNumber != responsesNumber) {
      throw new CalypsoDesynchronizedExchangesException(
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
   * @param builder the command builder.
   * @param overflow flag set to true if the command overflowed the buffer.
   * @param neededSessionBufferSpace updated with the size of the buffer consumed by the command.
   * @return True if the command modifies the content of the card, false if not
   * @throws CalypsoAtomicTransactionException if the command overflows the buffer in ATOMIC
   *     modification mode
   */
  private boolean checkModifyingCommand(
      AbstractCardCommandBuilder<? extends AbstractCardResponseParser> builder,
      AtomicBoolean overflow,
      AtomicInteger neededSessionBufferSpace) {
    if (builder.isSessionBufferUsed()) {
      // This command affects the card modifications buffer
      neededSessionBufferSpace.set(
          builder.getApduRequest().getBytes().length
              + SESSION_BUFFER_CMD_ADDITIONAL_COST
              - APDU_HEADER_LENGTH);
      if (isSessionBufferOverflowed(neededSessionBufferSpace.get())) {
        // raise an exception if in atomic mode
        if (!cardSecuritySettings.isMultipleSessionEnabled()) {
          throw new CalypsoAtomicTransactionException(
              "ATOMIC mode error! This command would overflow the card modifications buffer: "
                  + builder.getName());
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
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareReleaseCardChannel() {
    channelControl = ChannelControl.CLOSE_AFTER;

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareSelectFile(byte[] lid) {
    // create the builder and add it to the list of commands
    cardCommandManager.addRegularCommand(
        CalypsoCardUtils.prepareSelectFile(calypsoCard.getCardClass(), lid));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareSelectFile(SelectFileControl control) {
    // create the builder and add it to the list of commands
    cardCommandManager.addRegularCommand(
        CalypsoCardUtils.prepareSelectFile(calypsoCard.getCardClass(), control));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareReadRecordFile(byte sfi, int recordNumber) {
    try {
      // create the builder and add it to the list of commands
      cardCommandManager.addRegularCommand(
          CalypsoCardUtils.prepareReadRecordFile(calypsoCard.getCardClass(), sfi, recordNumber));

      return this;
    } catch (RuntimeException e) {
      releaseSamResourceSilently();
      throw e;
    }
  }

  /**
   * (private)<br>
   * Try to release the current SAM card resource.
   */
  private void releaseSamResourceSilently() {
    try {
      if (samCommandProcessor != null) {
        samCommandProcessor.releaseResource();
      }
    } catch (RuntimeException e) {
      logger.error("Unexpected error during release card resource: {}", e.getMessage(), e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareReadRecordFile(
      byte sfi, int firstRecordNumber, int numberOfRecords, int recordSize) {

    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoCardUtils.SFI_MIN, CalypsoCardUtils.SFI_MAX, "sfi") //
        .isInRange(
            firstRecordNumber,
            CalypsoCardUtils.NB_REC_MIN,
            CalypsoCardUtils.NB_REC_MAX,
            "firstRecordNumber") //
        .isInRange(
            numberOfRecords,
            CalypsoCardUtils.NB_REC_MIN,
            CalypsoCardUtils.NB_REC_MAX - firstRecordNumber,
            "numberOfRecords");

    if (numberOfRecords == 1) {
      // create the builder and add it to the list of commands
      cardCommandManager.addRegularCommand(
          new CardReadRecordsBuilder(
              calypsoCard.getCardClass(),
              sfi,
              firstRecordNumber,
              CardReadRecordsBuilder.ReadMode.ONE_RECORD,
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
        // create the builder and add it to the list of commands
        cardCommandManager.addRegularCommand(
            new CardReadRecordsBuilder(
                calypsoCard.getCardClass(),
                sfi,
                startRecordNumber,
                CardReadRecordsBuilder.ReadMode.MULTIPLE_RECORD,
                expectedLength));
      }
    }

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareReadCounterFile(byte sfi, int countersNumber) {
    prepareReadRecordFile(sfi, 1, 1, countersNumber * 3);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareAppendRecord(byte sfi, byte[] recordData) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoCardUtils.SFI_MIN, CalypsoCardUtils.SFI_MAX, "sfi");

    // create the builder and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CardAppendRecordBuilder(calypsoCard.getCardClass(), sfi, recordData));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareUpdateRecord(
      byte sfi, int recordNumber, byte[] recordData) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoCardUtils.SFI_MIN, CalypsoCardUtils.SFI_MAX, "sfi") //
        .isInRange(
            recordNumber, CalypsoCardUtils.NB_REC_MIN, CalypsoCardUtils.NB_REC_MAX, "recordNumber");

    // create the builder and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CardUpdateRecordBuilder(calypsoCard.getCardClass(), sfi, recordNumber, recordData));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareWriteRecord(
      byte sfi, int recordNumber, byte[] recordData) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoCardUtils.SFI_MIN, CalypsoCardUtils.SFI_MAX, "sfi") //
        .isInRange(
            recordNumber, CalypsoCardUtils.NB_REC_MIN, CalypsoCardUtils.NB_REC_MAX, "recordNumber");

    // create the builder and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CardWriteRecordBuilder(calypsoCard.getCardClass(), sfi, recordNumber, recordData));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareIncreaseCounter(
      byte sfi, int counterNumber, int incValue) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoCardUtils.SFI_MIN, CalypsoCardUtils.SFI_MAX, "sfi") //
        .isInRange(
            counterNumber,
            CalypsoCardUtils.NB_CNT_MIN,
            CalypsoCardUtils.NB_CNT_MAX,
            "counterNumber") //
        .isInRange(
            incValue, CalypsoCardUtils.CNT_VALUE_MIN, CalypsoCardUtils.CNT_VALUE_MAX, "incValue");

    // create the builder and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CardIncreaseBuilder(calypsoCard.getCardClass(), sfi, counterNumber, incValue));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareDecreaseCounter(
      byte sfi, int counterNumber, int decValue) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoCardUtils.SFI_MIN, CalypsoCardUtils.SFI_MAX, "sfi") //
        .isInRange(
            counterNumber,
            CalypsoCardUtils.NB_CNT_MIN,
            CalypsoCardUtils.NB_CNT_MAX,
            "counterNumber") //
        .isInRange(
            decValue, CalypsoCardUtils.CNT_VALUE_MIN, CalypsoCardUtils.CNT_VALUE_MAX, "decValue");

    // create the builder and add it to the list of commands
    cardCommandManager.addRegularCommand(
        new CardDecreaseBuilder(calypsoCard.getCardClass(), sfi, counterNumber, decValue));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareSetCounter(byte sfi, int counterNumber, int newValue) {
    int delta;
    try {
      delta =
          newValue
              - calypsoCard.getFileBySfi(sfi).getData().getContentAsCounterValue(counterNumber);
    } catch (NoSuchElementException ex) {
      throw new CalypsoCardTransactionIllegalStateException(
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
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareCheckPinStatus() {
    if (!calypsoCard.isPinFeatureAvailable()) {
      throw new CalypsoCardTransactionIllegalStateException("PIN is not available for this card.");
    }
    // create the builder and add it to the list of commands
    cardCommandManager.addRegularCommand(new CardVerifyPinBuilder(calypsoCard.getCardClass()));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareSvGet(
      SvSettings.Operation svOperation, SvSettings.Action svAction) {
    if (!calypsoCard.isSvFeatureAvailable()) {
      throw new CalypsoCardTransactionIllegalStateException(
          "Stored Value is not available for this card.");
    }
    if (cardSecuritySettings.isLoadAndDebitSvLogRequired()
        && (calypsoCard.getRevision() != CardRevision.REV3_2)) {
      // @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit logs are requested
      // for a non rev3.2 card add two SvGet commands (for RELOAD then for DEBIT).
      SvSettings.Operation operation1 =
          SvSettings.Operation.RELOAD.equals(svOperation)
              ? SvSettings.Operation.DEBIT
              : SvSettings.Operation.RELOAD;
      cardCommandManager.addStoredValueCommand(
          new CardSvGetBuilder(calypsoCard.getCardClass(), calypsoCard.getRevision(), operation1),
          operation1);
    }
    cardCommandManager.addStoredValueCommand(
        new CardSvGetBuilder(calypsoCard.getCardClass(), calypsoCard.getRevision(), svOperation),
        svOperation);
    this.svAction = svAction;

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareSvReload(
      int amount, byte[] date, byte[] time, byte[] free) {
    // create the initial builder with the application data
    CardSvReloadBuilder svReloadCmdBuild =
        new CardSvReloadBuilder(
            calypsoCard.getCardClass(),
            calypsoCard.getRevision(),
            amount,
            CalypsoCardUtils.getSvKvc(),
            date,
            time,
            free);

    // get the security data from the SAM
    byte[] svReloadComplementaryData;
    try {
      svReloadComplementaryData =
          samCommandProcessor.getSvReloadComplementaryData(
              svReloadCmdBuild, CalypsoCardUtils.getSvGetHeader(), CalypsoCardUtils.getSvGetData());
    } catch (CalypsoSamCommandException e) {
      throw new CalypsoSamAnomalyException(
          SAM_COMMAND_ERROR + "preparing the SV reload command: " + e.getCommand().getName(), e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + "preparing the SV reload command.", e);
    } catch (CardBrokenCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_COMMUNICATION_ERROR + "preparing the SV reload command.", e);
    }

    // finalize the SvReload command builder with the data provided by the SAM
    svReloadCmdBuild.finalizeBuilder(svReloadComplementaryData);

    // create and keep the CalypsoCardCommand
    cardCommandManager.addStoredValueCommand(svReloadCmdBuild, SvSettings.Operation.RELOAD);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareSvReload(int amount) {
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

    if (!cardSecuritySettings.isSvNegativeBalanceAllowed()
        && (calypsoCard.getSvBalance() - amount) < 0) {
      throw new CalypsoCardTransactionIllegalStateException("Negative balances not allowed.");
    }

    // create the initial builder with the application data
    CardSvDebitBuilder svDebitCmdBuild =
        new CardSvDebitBuilder(
            calypsoCard.getCardClass(),
            calypsoCard.getRevision(),
            amount,
            CalypsoCardUtils.getSvKvc(),
            date,
            time);

    // get the security data from the SAM
    byte[] svDebitComplementaryData;
    svDebitComplementaryData =
        samCommandProcessor.getSvDebitComplementaryData(
            svDebitCmdBuild, CalypsoCardUtils.getSvGetHeader(), CalypsoCardUtils.getSvGetData());

    // finalize the SvDebit command builder with the data provided by the SAM
    svDebitCmdBuild.finalizeBuilder(svDebitComplementaryData);

    // create and keep the CalypsoCardCommand
    cardCommandManager.addStoredValueCommand(svDebitCmdBuild, SvSettings.Operation.DEBIT);
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

    // create the initial builder with the application data
    CardSvUndebitBuilder svUndebitCmdBuild =
        new CardSvUndebitBuilder(
            calypsoCard.getCardClass(),
            calypsoCard.getRevision(),
            amount,
            CalypsoCardUtils.getSvKvc(),
            date,
            time);

    // get the security data from the SAM
    byte[] svDebitComplementaryData;
    svDebitComplementaryData =
        samCommandProcessor.getSvUndebitComplementaryData(
            svUndebitCmdBuild, CalypsoCardUtils.getSvGetHeader(), CalypsoCardUtils.getSvGetData());

    // finalize the SvUndebit command builder with the data provided by the SAM
    svUndebitCmdBuild.finalizeBuilder(svDebitComplementaryData);

    // create and keep the CalypsoCardCommand
    cardCommandManager.addStoredValueCommand(svUndebitCmdBuild, SvSettings.Operation.DEBIT);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareSvDebit(int amount, byte[] date, byte[] time) {
    try {
      if (SvSettings.Action.DO.equals(svAction)) {
        prepareSvDebitPriv(amount, date, time);
      } else {
        prepareSvUndebitPriv(amount, date, time);
      }
    } catch (CalypsoSamCommandException e) {
      throw new CalypsoSamAnomalyException(
          SAM_COMMAND_ERROR + "preparing the SV debit/undebit command: " + e.getCommand().getName(),
          e);
    } catch (ReaderBrokenCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + "preparing the SV debit/undebit command.", e);
    } catch (CardBrokenCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_COMMUNICATION_ERROR + "preparing the SV debit/undebit command.", e);
    }

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareSvDebit(int amount) {
    final byte[] zero = {0x00, 0x00};
    prepareSvDebit(amount, zero, zero);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareSvReadAllLogs() {
    if (calypsoCard.getApplicationSubtype() != CalypsoCardUtils.STORED_VALUE_FILE_STRUCTURE_ID) {
      throw new CalypsoCardTransactionIllegalStateException(
          "The currently selected application is not an SV application.");
    }
    // reset SV data in CalypsoCard if any
    calypsoCard.setSvData(0, 0, null, null);
    prepareReadRecordFile(
        CalypsoCardUtils.SV_RELOAD_LOG_FILE_SFI, CalypsoCardUtils.SV_RELOAD_LOG_FILE_NB_REC);
    prepareReadRecordFile(
        CalypsoCardUtils.SV_DEBIT_LOG_FILE_SFI,
        1,
        CalypsoCardUtils.SV_DEBIT_LOG_FILE_NB_REC,
        CalypsoCardUtils.SV_LOG_FILE_REC_LENGTH);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareInvalidate() {
    if (calypsoCard.isDfInvalidated()) {
      throw new CalypsoCardTransactionIllegalStateException("This card is already invalidated.");
    }
    cardCommandManager.addRegularCommand(new CardInvalidateBuilder(calypsoCard.getCardClass()));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final CardTransactionService prepareRehabilitate() {
    if (!calypsoCard.isDfInvalidated()) {
      throw new CalypsoCardTransactionIllegalStateException("This card is not invalidated.");
    }
    cardCommandManager.addRegularCommand(new CardRehabilitateBuilder(calypsoCard.getCardClass()));

    return this;
  }

  /**
   * (private)<br>
   * Adapter of {@link ApduResponseApi} used to create anticipated card responses.
   */
  private static class ApduResponseAdapter implements ApduResponseApi {

    private final byte[] bytes;
    private final int statusWord;

    /** Constructor */
    public ApduResponseAdapter(byte[] bytes) {
      this.bytes = bytes;
      statusWord =
          ((bytes[bytes.length - 2] & 0x000000FF) << 8) + (bytes[bytes.length - 1] & 0x000000FF);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getBytes() {
      return bytes;
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getDataOut() {
      return Arrays.copyOfRange(this.bytes, 0, this.bytes.length - 2);
    }

    /** {@inheritDoc} */
    @Override
    public int getStatusWord() {
      return statusWord;
    }
  }
}
