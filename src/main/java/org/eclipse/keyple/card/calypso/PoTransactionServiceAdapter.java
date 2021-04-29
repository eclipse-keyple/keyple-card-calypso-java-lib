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
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.eclipse.keyple.card.calypso.po.ElementaryFile;
import org.eclipse.keyple.card.calypso.po.PoRevision;
import org.eclipse.keyple.card.calypso.po.PoSmartCard;
import org.eclipse.keyple.card.calypso.po.SelectFileControl;
import org.eclipse.keyple.card.calypso.transaction.*;
import org.eclipse.keyple.core.card.*;
import org.eclipse.keyple.core.service.Reader;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Implementation of {@link PoTransactionService}.
 *
 * @since 2.0
 */
class PoTransactionServiceAdapter implements PoTransactionService {

  // prefix/suffix used to compose exception messages
  private static final String PO_READER_COMMUNICATION_ERROR =
      "A communication error with the PO reader occurred while ";
  private static final String PO_COMMUNICATION_ERROR =
      "A communication error with the PO occurred while ";
  private static final String PO_COMMAND_ERROR = "A PO command error occurred while ";
  private static final String SAM_READER_COMMUNICATION_ERROR =
      "A communication error with the SAM reader occurred while ";
  private static final String SAM_COMMUNICATION_ERROR =
      "A communication error with the SAM occurred while ";
  private static final String SAM_COMMAND_ERROR = "A SAM command error occurred while ";
  private static final String TRANSMITTING_COMMANDS = "transmitting commands.";
  private static final String CHECKING_THE_SV_OPERATION = "checking the SV operation.";
  private static final String UNEXPECTED_EXCEPTION = "An unexpected exception was raised.";

  // commands that modify the content of the PO in session have a cost on the session buffer equal
  // to the length of the outgoing data plus 6 bytes
  private static final int SESSION_BUFFER_CMD_ADDITIONAL_COST = 6;

  private static final int APDU_HEADER_LENGTH = 5;

  private static final Logger logger = LoggerFactory.getLogger(PoTransactionServiceAdapter.class);

  /** The reader for PO. */
  private final ProxyReader poReader;
  /** The PO security settings used to manage the secure session */
  private PoSecuritySetting poSecuritySettings;
  /** The SAM commands processor */
  private SamCommandProcessor samCommandProcessor;
  /** The current PoSmartCard */
  private final PoSmartCardAdapter calypsoPoSmartCard;
  /** the type of the notified event. */
  private SessionState sessionState;
  /** The current secure session access level: PERSO, RELOAD, DEBIT */
  private SessionAccessLevel currentSessionAccessLevel;
  /** modifications counter management */
  private int modificationsCounter;
  /** The object for managing PO commands */
  private final PoCommandManager poCommandManager;
  /** The current Store Value action */
  private SvSettings.Action svAction;
  /** The {@link ChannelControl} action */
  private ChannelControl channelControl;

  /**
   * The PO Transaction State defined with the elements: ‘IOError’, ‘SEInserted’ and ‘SERemoval’.
   */
  private enum SessionState {
    /** Initial state of a PO transaction. The PO must have been previously selected. */
    SESSION_UNINITIALIZED,
    /** The secure session is active. */
    SESSION_OPEN,
    /** The secure session is closed. */
    SESSION_CLOSED
  }

  /**
   * Creates an instance of {@link PoTransactionService} for secure operations.
   *
   * <p>Secure operations are enabled by the presence of {@link PoSecuritySetting}.
   *
   * @param poReader The reader through which the card communicates.
   * @param poSmartCard The initial PO data provided by the selection process.
   * @param poSecuritySetting The security settings.
   * @since 2.0
   */
  public PoTransactionServiceAdapter(
      Reader poReader, PoSmartCard poSmartCard, PoSecuritySetting poSecuritySetting) {

    this(poReader, poSmartCard);

    this.poSecuritySettings = poSecuritySetting;

    samCommandProcessor = new SamCommandProcessor(poSmartCard, poSecuritySetting);
  }

  /**
   * Creates an instance of {@link PoTransactionService} for non-secure operations.
   *
   * @param poReader The reader through which the card communicates.
   * @param poSmartCard The initial PO data provided by the selection process.
   * @since 2.0
   */
  public PoTransactionServiceAdapter(Reader poReader, PoSmartCard poSmartCard) {
    this.poReader = (ProxyReader) poReader;

    this.calypsoPoSmartCard = (PoSmartCardAdapter) poSmartCard;

    modificationsCounter = this.calypsoPoSmartCard.getModificationsCounter();

    sessionState = SessionState.SESSION_UNINITIALIZED;

    poCommandManager = new PoCommandManager();

    channelControl = ChannelControl.KEEP_OPEN;
  }

  /**
   * Open a single Secure Session.
   *
   * @param sessionAccessLevel access level of the session (personalization, load or debit).
   * @param poCommands the po commands inside session.
   * @throws CalypsoPoTransactionIllegalStateException if no {@link PoSecuritySetting} is available
   * @throws CalypsoPoTransactionException if a functional error occurs (including PO and SAM IO
   *     errors)
   */
  private void processAtomicOpening(
      SessionAccessLevel sessionAccessLevel,
      List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> poCommands) {

    // This method should be invoked only if no session was previously open
    checkSessionIsNotOpen();

    if (poSecuritySettings == null) {
      throw new CalypsoPoTransactionIllegalStateException("No security settings are available.");
    }

    byte[] sessionTerminalChallenge = getSessionTerminalChallenge();

    // PO ApduRequest List to hold Open Secure Session and other optional commands
    List<ApduRequest> poApduRequests = new ArrayList<ApduRequest>();

    // The sfi and record number to be read when the open secure session command is executed.
    // The default value is 0 (no record to read) but we will optimize the exchanges if a read
    // record command has been prepared.
    int sfi = 0;
    int recordNumber = 0;

    // Let's check if we have a read record command at the top of the command list.
    //
    // If so, then the command is withdrawn in favour of its equivalent executed at the same
    // time as the open secure session command.
    if (poCommands != null && !poCommands.isEmpty()) {
      AbstractPoCommandBuilder<? extends AbstractPoResponseParser> poCommand = poCommands.get(0);
      if (poCommand.getCommandRef() == PoCommand.READ_RECORDS
          && ((PoReadRecordsBuilder) poCommand).getReadMode()
              == PoReadRecordsBuilder.ReadMode.ONE_RECORD) {
        sfi = ((PoReadRecordsBuilder) poCommand).getSfi();
        recordNumber = ((PoReadRecordsBuilder) poCommand).getFirstRecordNumber();
        poCommands.remove(0);
      }
    }

    // Build the PO Open Secure Session command
    AbstractPoCommandBuilder<AbstractPoOpenSessionParser> openSessionCmdBuild =
        AbstractPoOpenSessionBuilder.create(
            calypsoPoSmartCard.getRevision(),
            sessionAccessLevel.getSessionKey(),
            sessionTerminalChallenge,
            sfi,
            recordNumber);

    // Add the resulting ApduRequest to the PO ApduRequest list
    poApduRequests.add(openSessionCmdBuild.getApduRequest());

    // Add all optional commands to the PO ApduRequest list
    if (poCommands != null) {
      poApduRequests.addAll(getApduRequests(poCommands));
    }

    // Create a CardRequest from the ApduRequest list, PO AID as Selector, keep channel open
    CardRequest poCardRequest = new CardRequest(poApduRequests, false);

    // Transmit the commands to the PO
    CardResponse poCardResponse = safePoTransmit(poCardRequest, ChannelControl.KEEP_OPEN);

    // Retrieve and check the ApduResponses
    List<ApduResponse> poApduResponses = poCardResponse.getApduResponses();

    // Do some basic checks
    checkCommandsResponsesSynchronization(poApduRequests.size(), poApduResponses.size());

    // Parse the response to Open Secure Session (the first item of poApduResponses)
    // The updateCalypsoPo method fills the PoSmartCard object with the command data and
    // return
    // the parser used for an internal usage here.
    AbstractPoOpenSessionParser poOpenSessionPars;
    try {
      poOpenSessionPars =
          (AbstractPoOpenSessionParser)
              CalypsoPoUtils.updateCalypsoPo(
                  calypsoPoSmartCard, openSessionCmdBuild, poApduResponses.get(0));
    } catch (CalypsoPoCommandException e) {
      throw new CalypsoPoAnomalyException(
          PO_COMMAND_ERROR + "processing the response to open session: " + e.getCommand(), e);
    }
    // Build the Digest Init command from PO Open Session
    // the session challenge is needed for the SAM digest computation
    byte[] sessionCardChallenge = poOpenSessionPars.getPoChallenge();

    // The PO KIF
    byte poKif = poOpenSessionPars.getSelectedKif();

    // The PO KVC, may be null for PO Rev 1.0
    byte poKvc = poOpenSessionPars.getSelectedKvc();

    if (logger.isDebugEnabled()) {
      logger.debug(
          "processAtomicOpening => opening: CARDCHALLENGE = {}, POKIF = {}, POKVC = {}",
          ByteArrayUtil.toHex(sessionCardChallenge),
          String.format("%02X", poKif),
          String.format("%02X", poKvc));
    }

    if (!poSecuritySettings.isKvcAuthorized(poKvc)) {
      throw new CalypsoUnauthorizedKvcException(
          String.format("Unauthorized KVC error: PO KVC = %02X", poKvc));
    }

    // Initialize the digest processor. It will store all digest operations (Digest Init, Digest
    // Update) until the session closing. At this moment, all SAM Apdu will be processed at
    // once.
    samCommandProcessor.initializeDigester(
        sessionAccessLevel, false, false, poKif, poKvc, poApduResponses.get(0).getDataOut());

    // Add all commands data to the digest computation. The first command in the list is the
    // open secure session command. This command is not included in the digest computation, so
    // we skip it and start the loop at index 1.
    if ((poCommands != null) && !poCommands.isEmpty()) {
      // Add requests and responses to the digest processor
      samCommandProcessor.pushPoExchangeDataList(poApduRequests, poApduResponses, 1);
    }

    // Remove Open Secure Session response and create a new CardResponse
    poApduResponses.remove(0);

    // update PoSmartCard with the received data
    // TODO check if this is not redundant with what is done 40 lines above
    try {
      CalypsoPoUtils.updateCalypsoPo(calypsoPoSmartCard, poCommands, poApduResponses);
    } catch (CalypsoPoCommandException e) {
      throw new CalypsoPoAnomalyException(
          PO_COMMAND_ERROR + "processing the response to open session: " + e.getCommand(), e);
    }

    sessionState = SessionState.SESSION_OPEN;
  }

  /**
   * Create an ApduRequest List from a AbstractPoCommandBuilder List.
   *
   * @param poCommands a list of PO commands.
   * @return the ApduRequest list
   */
  private List<ApduRequest> getApduRequests(
      List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> poCommands) {
    List<ApduRequest> apduRequests = new ArrayList<ApduRequest>();
    if (poCommands != null) {
      for (AbstractPoCommandBuilder<? extends AbstractPoResponseParser> commandBuilder :
          poCommands) {
        apduRequests.add(commandBuilder.getApduRequest());
      }
    }
    return apduRequests;
  }

  /**
   * Process PO commands in a Secure Session.
   *
   * <ul>
   *   <li>On the PO reader, generates a CardRequest with channelControl set to KEEP_OPEN, and
   *       ApduRequests with the PO commands.
   *   <li>In case the secure session is active, the "cache" of SAM commands is completed with the
   *       corresponding Digest Update commands.
   *   <li>If a session is open and channelControl is set to CLOSE_AFTER, the current PO session is
   *       aborted
   *   <li>Returns the corresponding PO CardResponse.
   * </ul>
   *
   * @param poCommands the po commands inside session.
   * @param channelControl indicated if the card channel of the PO reader must be closed after the.
   *     last command
   * @throws CalypsoPoTransactionException if a functional error occurs (including PO and SAM IO
   *     errors)
   */
  private void processAtomicPoCommands(
      List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> poCommands,
      ChannelControl channelControl) {

    // Get the PO ApduRequest List
    List<ApduRequest> poApduRequests = getApduRequests(poCommands);

    // Create a CardRequest from the ApduRequest list, PO AID as Selector, manage the logical
    // channel according to the channelControl
    CardRequest poCardRequest = new CardRequest(poApduRequests, false);

    // Transmit the commands to the PO
    CardResponse poCardResponse = safePoTransmit(poCardRequest, channelControl);

    // Retrieve and check the ApduResponses
    List<ApduResponse> poApduResponses = poCardResponse.getApduResponses();

    // Do some basic checks
    checkCommandsResponsesSynchronization(poApduRequests.size(), poApduResponses.size());

    // Add all commands data to the digest computation if this method is invoked within a Secure
    // Session.
    if (sessionState == SessionState.SESSION_OPEN) {
      samCommandProcessor.pushPoExchangeDataList(poApduRequests, poApduResponses, 0);
    }

    try {
      CalypsoPoUtils.updateCalypsoPo(
          calypsoPoSmartCard, poCommands, poCardResponse.getApduResponses());
    } catch (CalypsoPoCommandException e) {
      throw new CalypsoPoAnomalyException(
          PO_COMMAND_ERROR + "processing responses to PO commands: " + e.getCommand(), e);
    }
  }

  /**
   * Close the Secure Session.
   *
   * <ul>
   *   <li>The SAM cache is completed with the Digest Update commands related to the new PO commands
   *       to be sent and their anticipated responses. A Digest Close command is also added to the
   *       SAM command cache.
   *   <li>On the SAM session reader side, a CardRequest is transmitted with SAM commands from the
   *       command cache. The SAM command cache is emptied.
   *   <li>The SAM certificate is retrieved from the Digest Close response. The terminal signature
   *       is identified.
   *   <li>Then, on the PO reader, a CardRequest is transmitted with a {@link ChannelControl} set to
   *       CLOSE_AFTER or KEEP_OPEN depending on whether or not prepareReleasePoChannel was invoked,
   *       and apduRequests including the new PO commands to send in the session, a Close Session
   *       command (defined with the SAM certificate), and optionally a ratificationCommand.
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
   *         <li>Otherwise, the PO Close Secure Session command is defined to directly set the PO as
   *             ratified.
   *       </ul>
   *   <li>The PO responses of the poModificationCommands are compared with the
   *       poAnticipatedResponses. The PO signature is identified from the PO Close Session
   *       response.
   *   <li>The PO certificate is recovered from the Close Session response. The card signature is
   *       identified.
   *   <li>Finally, on the SAM session reader, a Digest Authenticate is automatically operated in
   *       order to verify the PO signature.
   *   <li>Returns the corresponding PO CardResponse.
   * </ul>
   *
   * The method is marked as deprecated because the advanced variant defined below must be used at
   * the application level.
   *
   * @param poModificationCommands a list of commands that can modify the PO memory content.
   * @param poAnticipatedResponses a list of anticipated PO responses to the modification commands.
   * @param isRatificationMechanismEnabled true if the ratification is closed not ratified and a
   *     ratification command must be sent.
   * @param channelControl indicates if the card channel of the PO reader must be closed after the.
   *     last command
   * @throws CalypsoPoTransactionException if a functional error occurs (including PO and SAM IO
   *     errors)
   */
  private void processAtomicClosing(
      List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> poModificationCommands,
      List<ApduResponse> poAnticipatedResponses,
      boolean isRatificationMechanismEnabled,
      ChannelControl channelControl) {

    checkSessionIsOpen();

    // Get the PO ApduRequest List - for the first PO exchange
    List<ApduRequest> poApduRequests = getApduRequests(poModificationCommands);

    // Compute "anticipated" Digest Update (for optional poModificationCommands)
    if ((poModificationCommands != null) && !poApduRequests.isEmpty()) {
      checkCommandsResponsesSynchronization(poApduRequests.size(), poAnticipatedResponses.size());
      // Add all commands data to the digest computation: commands and anticipated
      // responses.
      samCommandProcessor.pushPoExchangeDataList(poApduRequests, poAnticipatedResponses, 0);
    }

    // All SAM digest operations will now run at once.
    // Get Terminal Signature from the latest response
    byte[] sessionTerminalSignature = getSessionTerminalSignature();

    boolean ratificationCommandResponseReceived;

    // Build the PO Close Session command. The last one for this session
    PoCloseSessionBuilder closeSessionCmdBuild =
        new PoCloseSessionBuilder(
            calypsoPoSmartCard.getPoClass(),
            !isRatificationMechanismEnabled,
            sessionTerminalSignature);

    poApduRequests.add(closeSessionCmdBuild.getApduRequest());

    // Keep the position of the Close Session command in request list
    int closeCommandIndex = poApduRequests.size() - 1;

    // Add the PO Ratification command if any
    boolean ratificationCommandAdded;
    if (isRatificationMechanismEnabled && ((Reader) poReader).isContactless()) {
      poApduRequests.add(PoRatificationBuilder.getApduRequest(calypsoPoSmartCard.getPoClass()));
      ratificationCommandAdded = true;
    } else {
      ratificationCommandAdded = false;
    }

    // Transfer PO commands
    CardRequest poCardRequest = new CardRequest(poApduRequests, false);

    CardResponse poCardResponse;
    try {
      poCardResponse = poReader.transmitCardRequest(poCardRequest, channelControl);
      // if the ratification command was added and no error occurred then the response has been
      // received
      ratificationCommandResponseReceived = ratificationCommandAdded;
    } catch (CardCommunicationException e) {
      poCardResponse = e.getCardResponse();
      // The current exception may have been caused by a communication issue with the PO
      // during the ratification command.
      //
      // In this case, we do not stop the process and consider the Secure Session close. We'll
      // check the signature.
      //
      // We should have one response less than requests.
      if (!ratificationCommandAdded
          || poCardResponse == null
          || poCardResponse.getApduResponses().size() != poApduRequests.size() - 1) {
        throw new CalypsoPoIOException(PO_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
      }
      // we received all responses except the response to the ratification command
      ratificationCommandResponseReceived = false;
    } catch (ReaderCommunicationException e) {
      throw new CalypsoPoIOException(PO_READER_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
    } catch (UnexpectedStatusCodeException e) {
      throw new IllegalStateException(UNEXPECTED_EXCEPTION, e);
    }

    List<ApduResponse> poApduResponses = poCardResponse.getApduResponses();

    // Check the commands executed before closing the secure session (only responses to these
    // commands will be taken into account)
    try {
      CalypsoPoUtils.updateCalypsoPo(calypsoPoSmartCard, poModificationCommands, poApduResponses);
    } catch (CalypsoPoCommandException e) {
      throw new CalypsoPoAnomalyException(
          PO_COMMAND_ERROR
              + "processing of responses preceding the close of the session: "
              + e.getCommand(),
          e);
    }

    // Check the PO's response to Close Secure Session
    PoCloseSessionParser poCloseSessionPars =
        getPoCloseSessionParser(poApduResponses, closeSessionCmdBuild, closeCommandIndex);

    // Check the PO signature
    checkPoSignature(poCloseSessionPars.getSignatureLo());

    // If necessary, we check the status of the SV after the session has been successfully
    // closed.
    if (poCommandManager.isSvOperationCompleteOneTime()) {
      checkSvOperationStatus(poCloseSessionPars.getPostponedData());
    }

    sessionState = SessionState.SESSION_CLOSED;

    if (ratificationCommandResponseReceived) { // NOSONAR: boolean change in catch
      // is not taken into account by
      // Sonar
      // Remove the ratification response
      poApduResponses.remove(poApduResponses.size() - 1);
    }

    // Remove Close Secure Session response and create a new CardResponse
    poApduResponses.remove(poApduResponses.size() - 1);
  }

  /**
   * Advanced variant of processAtomicClosing in which the list of expected responses is determined
   * from previous reading operations.
   *
   * @param poCommands a list of commands that can modify the PO memory content.
   * @param isRatificationMechanismEnabled true if the ratification is closed not ratified and a
   *     ratification command must be sent.
   * @param channelControl indicates if the card channel of the PO reader must be closed after the.
   *     last command
   * @throws CalypsoPoTransactionException if a functional error occurs (including PO and SAM IO
   *     errors)
   */
  private void processAtomicClosing(
      List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> poCommands,
      boolean isRatificationMechanismEnabled,
      ChannelControl channelControl) {
    List<ApduResponse> poAnticipatedResponses = getAnticipatedResponses(poCommands);
    processAtomicClosing(
        poCommands, poAnticipatedResponses, isRatificationMechanismEnabled, channelControl);
  }

  /**
   * Gets the value of the designated counter
   *
   * @param sfi the SFI of the EF containing the counter.
   * @param counter the number of the counter.
   * @return the value of the counter
   */
  private int getCounterValue(int sfi, int counter) {
    try {
      ElementaryFile ef = calypsoPoSmartCard.getFileBySfi((byte) sfi);
      return ef.getData().getContentAsCounterValue(counter);
    } catch (NoSuchElementException e) {
      throw new CalypsoPoTransactionIllegalStateException(
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
   * @return an {@link ApduResponse} containing the expected bytes
   */
  private ApduResponse createIncreaseDecreaseResponse(int newCounterValue) {
    // response = NNNNNN9000
    byte[] response = new byte[5];
    response[0] = (byte) ((newCounterValue & 0x00FF0000) >> 16);
    response[1] = (byte) ((newCounterValue & 0x0000FF00) >> 8);
    response[2] = (byte) (newCounterValue & 0x000000FF);
    response[3] = (byte) 0x90;
    response[4] = (byte) 0x00;
    return new ApduResponse(response);
  }

  static final ApduResponse RESPONSE_OK = new ApduResponse(new byte[] {(byte) 0x90, (byte) 0x00});
  static final ApduResponse RESPONSE_OK_POSTPONED =
      new ApduResponse(new byte[] {(byte) 0x62, (byte) 0x00});

  /**
   * Get the anticipated response to the command sent in processClosing.<br>
   * These commands are supposed to be "modifying commands" i.e.
   * Increase/Decrease/UpdateRecord/WriteRecord ou AppendRecord.
   *
   * @param poCommands the list of PO commands sent.
   * @return the list of the anticipated responses.
   * @throws CalypsoPoTransactionIllegalStateException if the anticipation process failed
   */
  private List<ApduResponse> getAnticipatedResponses(
      List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> poCommands) {
    List<ApduResponse> apduResponses = new ArrayList<ApduResponse>();
    if (poCommands != null) {
      for (AbstractPoCommandBuilder<? extends AbstractPoResponseParser> commandBuilder :
          poCommands) {
        if (commandBuilder.getCommandRef() == PoCommand.DECREASE) {
          int sfi = ((PoDecreaseBuilder) commandBuilder).getSfi();
          int counter = ((PoDecreaseBuilder) commandBuilder).getCounterNumber();
          int newCounterValue =
              getCounterValue(sfi, counter) - ((PoDecreaseBuilder) commandBuilder).getDecValue();
          apduResponses.add(createIncreaseDecreaseResponse(newCounterValue));
        } else if (commandBuilder.getCommandRef() == PoCommand.INCREASE) {
          int sfi = ((PoIncreaseBuilder) commandBuilder).getSfi();
          int counter = ((PoIncreaseBuilder) commandBuilder).getCounterNumber();
          int newCounterValue =
              getCounterValue(sfi, counter) + ((PoIncreaseBuilder) commandBuilder).getIncValue();
          apduResponses.add(createIncreaseDecreaseResponse(newCounterValue));
        } else if (commandBuilder.getCommandRef() == PoCommand.SV_RELOAD
            || commandBuilder.getCommandRef() == PoCommand.SV_DEBIT
            || commandBuilder.getCommandRef() == PoCommand.SV_UNDEBIT) {
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
  public final PoTransactionService processOpening(SessionAccessLevel sessionAccessLevel) {
    try {
      currentSessionAccessLevel = sessionAccessLevel;

      // create a sublist of AbstractPoCommandBuilder to be sent atomically
      List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> poAtomicCommands =
          new ArrayList<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>>();

      AtomicInteger neededSessionBufferSpace = new AtomicInteger();
      AtomicBoolean overflow = new AtomicBoolean();

      for (AbstractPoCommandBuilder<? extends AbstractPoResponseParser> commandBuilder :
          poCommandManager.getPoCommandBuilders()) {
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
            // Clear the list and add the command that did not fit in the PO modifications
            // buffer. We also update the usage counter without checking the result.
            poAtomicCommands.clear();
            poAtomicCommands.add(commandBuilder);
            // just update modifications buffer usage counter, ignore result (always false)
            isSessionBufferOverflowed(neededSessionBufferSpace.get());
          } else {
            // The command fits in the PO modifications buffer, just add it to the list
            poAtomicCommands.add(commandBuilder);
          }
        } else {
          // This command does not affect the PO modifications buffer
          poAtomicCommands.add(commandBuilder);
        }
      }

      processAtomicOpening(currentSessionAccessLevel, poAtomicCommands);

      // sets the flag indicating that the commands have been executed
      poCommandManager.notifyCommandsProcessed();

      return this;
    } catch (RuntimeException e) {
      releaseSamResourceSilently();
      throw e;
    }
  }

  /**
   * Process all prepared PO commands (outside a Secure Session).
   *
   * <p>Note: commands prepared prior to the invocation of this method shall not require the use of
   * a SAM.
   *
   * @param channelControl indicates if the card channel of the PO reader must be closed after the.
   *     last command
   * @throws CalypsoPoTransactionException if a functional error occurs (including PO and SAM IO
   *     errors)
   */
  private void processPoCommandsOutOfSession(ChannelControl channelControl) {

    // PO commands sent outside a Secure Session. No modifications buffer limitation.
    processAtomicPoCommands(poCommandManager.getPoCommandBuilders(), channelControl);

    // sets the flag indicating that the commands have been executed
    poCommandManager.notifyCommandsProcessed();

    // If an SV transaction was performed, we check the signature returned by the PO here
    if (poCommandManager.isSvOperationCompleteOneTime()) {
      try {
        samCommandProcessor.checkSvStatus(CalypsoPoUtils.getSvOperationSignature());
      } catch (CalypsoSamSecurityDataException e) {
        throw new CalypsoSvAuthenticationException(
            "The checking of the SV operation by the SAM has failed.", e);
      } catch (CalypsoSamCommandException e) {
        throw new CalypsoSamAnomalyException(
            SAM_COMMAND_ERROR + "checking the SV operation: " + e.getCommand().getName(), e);
      } catch (ReaderCommunicationException e) {
        throw new CalypsoSvAuthenticationException(
            SAM_READER_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
      } catch (CardCommunicationException e) {
        throw new CalypsoSvAuthenticationException(
            SAM_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
      }
    }
  }

  /**
   * Process all prepared PO commands in a Secure Session.
   *
   * <p>The multiple session mode is handled according to the session settings.
   *
   * @throws CalypsoPoTransactionException if a functional error occurs (including PO and SAM IO
   *     errors)
   */
  private void processPoCommandsInSession() {

    // A session is open, we have to care about the PO modifications buffer
    List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> poAtomicBuilders =
        new ArrayList<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>>();

    AtomicInteger neededSessionBufferSpace = new AtomicInteger();
    AtomicBoolean overflow = new AtomicBoolean();

    for (AbstractPoCommandBuilder<? extends AbstractPoResponseParser> commandBuilder :
        poCommandManager.getPoCommandBuilders()) {
      // check if the command is a modifying one and get it status (overflow yes/no,
      // neededSessionBufferSpace)
      // if the command overflows the session buffer in atomic modification mode, an exception
      // is raised.
      if (checkModifyingCommand(commandBuilder, overflow, neededSessionBufferSpace)) {
        if (overflow.get()) {
          // The current command would overflow the modifications buffer in the PO. We
          // send the current commands and update the parsers. The parsers Iterator is
          // kept all along the process.
          processAtomicPoCommands(poAtomicBuilders, ChannelControl.KEEP_OPEN);
          // Close the session and reset the modifications buffer counters for the next
          // round
          processAtomicClosing(null, false, ChannelControl.KEEP_OPEN);
          resetModificationsBufferCounter();
          // We reopen a new session for the remaining commands to be sent
          processAtomicOpening(currentSessionAccessLevel, null);
          // Clear the list and add the command that did not fit in the PO modifications
          // buffer. We also update the usage counter without checking the result.
          poAtomicBuilders.clear();
          poAtomicBuilders.add(commandBuilder);
          // just update modifications buffer usage counter, ignore result (always false)
          isSessionBufferOverflowed(neededSessionBufferSpace.get());
        } else {
          // The command fits in the PO modifications buffer, just add it to the list
          poAtomicBuilders.add(commandBuilder);
        }
      } else {
        // This command does not affect the PO modifications buffer
        poAtomicBuilders.add(commandBuilder);
      }
    }

    if (!poAtomicBuilders.isEmpty()) {
      processAtomicPoCommands(poAtomicBuilders, ChannelControl.KEEP_OPEN);
    }

    // sets the flag indicating that the commands have been executed
    poCommandManager.notifyCommandsProcessed();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService processPoCommands() {
    try {
      if (sessionState == SessionState.SESSION_OPEN) {
        processPoCommandsInSession();
      } else {
        processPoCommandsOutOfSession(channelControl);
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

      List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> poAtomicCommands =
          new ArrayList<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>>();
      for (AbstractPoCommandBuilder<? extends AbstractPoResponseParser> commandBuilder :
          poCommandManager.getPoCommandBuilders()) {
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

            // If at least one non-modifying was prepared, we use processAtomicPoCommands
            // instead of processAtomicClosing to send the list
            if (atLeastOneReadCommand) {
              processAtomicPoCommands(poAtomicCommands, ChannelControl.KEEP_OPEN);
              // Clear the list of commands sent
              poAtomicCommands.clear();
              processAtomicClosing(poAtomicCommands, false, ChannelControl.KEEP_OPEN);
              resetModificationsBufferCounter();
              sessionPreviouslyClosed = true;
              atLeastOneReadCommand = false;
            } else {
              // All commands in the list are 'modifying the PO'
              processAtomicClosing(poAtomicCommands, false, ChannelControl.KEEP_OPEN);
              // Clear the list of commands sent
              poAtomicCommands.clear();
              resetModificationsBufferCounter();
              sessionPreviouslyClosed = true;
            }

            // Add the command that did not fit in the PO modifications
            // buffer. We also update the usage counter without checking the result.
            poAtomicCommands.add(commandBuilder);
            // just update modifications buffer usage counter, ignore result (always false)
            isSessionBufferOverflowed(neededSessionBufferSpace.get());
          } else {
            // The command fits in the PO modifications buffer, just add it to the list
            poAtomicCommands.add(commandBuilder);
          }
        } else {
          // This command does not affect the PO modifications buffer
          poAtomicCommands.add(commandBuilder);
          atLeastOneReadCommand = true;
        }
      }
      if (sessionPreviouslyClosed) {
        // Reopen a session if necessary
        processAtomicOpening(currentSessionAccessLevel, null);
      }

      // Finally, close the session as requested
      processAtomicClosing(
          poAtomicCommands, poSecuritySettings.isRatificationMechanismEnabled(), channelControl);

      // sets the flag indicating that the commands have been executed
      poCommandManager.notifyCommandsProcessed();
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
    // PO ApduRequest List to hold Close Secure Session command
    List<ApduRequest> poApduRequests = new ArrayList<ApduRequest>();

    // Build the PO Close Session command (in "abort" mode since no signature is provided).
    PoCloseSessionBuilder closeSessionCmdBuild =
        new PoCloseSessionBuilder(calypsoPoSmartCard.getPoClass());

    poApduRequests.add(closeSessionCmdBuild.getApduRequest());

    // Transfer PO commands
    CardRequest poCardRequest = new CardRequest(poApduRequests, false);

    CardResponse poCardResponse = safePoTransmit(poCardRequest, channelControl);

    try {
      closeSessionCmdBuild
          .createResponseParser(poCardResponse.getApduResponses().get(0))
          .checkStatus();
    } catch (CalypsoPoCommandException e) {
      throw new CalypsoPoAnomalyException(
          PO_COMMAND_ERROR + "processing the response to close session: " + e.getCommand(), e);
    }

    // sets the flag indicating that the commands have been executed
    poCommandManager.notifyCommandsProcessed();

    // session is now considered closed regardless the previous state or the result of the abort
    // session command sent to the PO.
    sessionState = SessionState.SESSION_CLOSED;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService processVerifyPin(byte[] pin) {
    Assert.getInstance()
        .notNull(pin, "pin")
        .isEqual(pin.length, CalypsoPoUtils.PIN_LENGTH, "PIN length");

    if (!calypsoPoSmartCard.isPinFeatureAvailable()) {
      throw new CalypsoPoTransactionIllegalStateException("PIN is not available for this PO.");
    }

    if (poCommandManager.hasCommands()) {
      throw new CalypsoPoTransactionIllegalStateException(
          "No commands should have been prepared prior to a PIN submission.");
    }

    if (poSecuritySettings != null && !poSecuritySettings.isPinTransmissionEncryptionDisabled()) {
      poCommandManager.addRegularCommand(
          new PoGetChallengeBuilder(calypsoPoSmartCard.getPoClass()));

      // transmit and receive data with the PO
      processAtomicPoCommands(poCommandManager.getPoCommandBuilders(), ChannelControl.KEEP_OPEN);

      // sets the flag indicating that the commands have been executed
      poCommandManager.notifyCommandsProcessed();

      // Get the encrypted PIN with the help of the SAM
      byte[] cipheredPin;
      try {
        cipheredPin =
            samCommandProcessor.getCipheredPinData(CalypsoPoUtils.getPoChallenge(), pin, null);
      } catch (CalypsoSamCommandException e) {
        throw new CalypsoSamAnomalyException(
            SAM_COMMAND_ERROR + "generating of the PIN ciphered data: " + e.getCommand().getName(),
            e);
      } catch (ReaderCommunicationException e) {
        throw new CalypsoSamIOException(
            SAM_READER_COMMUNICATION_ERROR + "generating of the PIN ciphered data.", e);
      } catch (CardCommunicationException e) {
        throw new CalypsoSamIOException(
            SAM_COMMUNICATION_ERROR + "generating of the PIN ciphered data.", e);
      }
      poCommandManager.addRegularCommand(
          new PoVerifyPinBuilder(calypsoPoSmartCard.getPoClass(), true, cipheredPin));
    } else {
      poCommandManager.addRegularCommand(
          new PoVerifyPinBuilder(calypsoPoSmartCard.getPoClass(), false, pin));
    }

    // transmit and receive data with the PO
    processAtomicPoCommands(poCommandManager.getPoCommandBuilders(), channelControl);

    // sets the flag indicating that the commands have been executed
    poCommandManager.notifyCommandsProcessed();

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService processVerifyPin(String pin) {
    processVerifyPin(pin.getBytes());

    return this;
  }

  private CardResponse safePoTransmit(CardRequest poCardRequest, ChannelControl channelControl) {
    try {
      return poReader.transmitCardRequest(poCardRequest, channelControl);
    } catch (ReaderCommunicationException e) {
      throw new CalypsoPoIOException(PO_READER_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
    } catch (CardCommunicationException e) {
      throw new CalypsoPoIOException(PO_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS, e);
    } catch (UnexpectedStatusCodeException e) {
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
    } catch (ReaderCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + "getting the terminal challenge.", e);
    } catch (CardCommunicationException e) {
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
    } catch (CardCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_COMMUNICATION_ERROR + "getting the terminal signature.", e);
    } catch (ReaderCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + "getting the terminal signature.", e);
    }
    return sessionTerminalSignature;
  }

  /**
   * Ask the SAM to verify the signature of the PO, and raises exceptions if necessary.
   *
   * @param poSignature The PO signature.
   * @throws CalypsoSessionAuthenticationException If the PO authentication failed.
   * @throws CalypsoSamAnomalyException If SAM returned an unexpected response.
   * @throws CalypsoSamIOException If the communication with the SAM or the SAM reader failed.
   */
  private void checkPoSignature(byte[] poSignature) {
    try {
      samCommandProcessor.authenticatePoSignature(poSignature);
    } catch (CalypsoSamSecurityDataException e) {
      throw new CalypsoSessionAuthenticationException(
          "The authentication of the PO by the SAM has failed.", e);
    } catch (CalypsoSamCommandException e) {
      throw new CalypsoSamAnomalyException(
          SAM_COMMAND_ERROR + "authenticating the PO signature: " + e.getCommand().getName(), e);
    } catch (ReaderCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + "authenticating the PO signature.", e);
    } catch (CardCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_COMMUNICATION_ERROR + "authenticating the PO signature.", e);
    }
  }

  /**
   * Ask the SAM to verify the SV operation status from the PO postponed data, raises exceptions if
   * needed.
   *
   * @param poPostponedData The postponed data from the pO.
   * @throws CalypsoSvAuthenticationException If the SV verification failed.
   * @throws CalypsoSamAnomalyException If SAM returned an unexpected response.
   * @throws CalypsoSamIOException If the communication with the SAM or the SAM reader failed.
   */
  private void checkSvOperationStatus(byte[] poPostponedData) {
    try {
      samCommandProcessor.checkSvStatus(poPostponedData);
    } catch (CalypsoSamSecurityDataException e) {
      throw new CalypsoSvAuthenticationException(
          "The checking of the SV operation by the SAM has failed.", e);
    } catch (CalypsoSamCommandException e) {
      throw new CalypsoSamAnomalyException(
          SAM_COMMAND_ERROR + "checking the SV operation: " + e.getCommand().getName(), e);
    } catch (ReaderCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
    } catch (CardCommunicationException e) {
      throw new CalypsoSamIOException(SAM_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION, e);
    }
  }

  /**
   * Get the close session parser.
   *
   * @param poApduResponses The responses received from the PO.
   * @param closeSessionCmdBuild The command builder.
   * @param closeCommandIndex The index of the close command within the request.
   * @throws CalypsoPoCloseSecureSessionException If a security error occurs.
   * @throws CalypsoPoAnomalyException If PO returned an unexpected response.
   */
  private PoCloseSessionParser getPoCloseSessionParser(
      List<ApduResponse> poApduResponses,
      PoCloseSessionBuilder closeSessionCmdBuild,
      int closeCommandIndex) {
    PoCloseSessionParser poCloseSessionPars;
    try {
      poCloseSessionPars =
          (PoCloseSessionParser)
              CalypsoPoUtils.updateCalypsoPo(
                  calypsoPoSmartCard, closeSessionCmdBuild, poApduResponses.get(closeCommandIndex));
    } catch (CalypsoPoSecurityDataException e) {
      throw new CalypsoPoCloseSecureSessionException("Invalid PO session", e);
    } catch (CalypsoPoCommandException e) {
      throw new CalypsoPoAnomalyException(
          PO_COMMAND_ERROR + "processing the response to close session: " + e.getCommand(), e);
    }
    return poCloseSessionPars;
  }

  /**
   * Checks if a Secure Session is open, raises an exception if not
   *
   * @throws CalypsoPoTransactionIllegalStateException if no session is open
   */
  private void checkSessionIsOpen() {
    if (sessionState != SessionState.SESSION_OPEN) {
      throw new CalypsoPoTransactionIllegalStateException(
          "Bad session state. Current: "
              + sessionState
              + ", expected: "
              + SessionState.SESSION_OPEN);
    }
  }

  /**
   * Checks if a Secure Session is not open, raises an exception if not
   *
   * @throws CalypsoPoTransactionIllegalStateException if a session is open
   */
  private void checkSessionIsNotOpen() {
    if (sessionState == SessionState.SESSION_OPEN) {
      throw new CalypsoPoTransactionIllegalStateException(
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
   * @return true if the command modifies the content of the PO, false if not
   * @throws CalypsoAtomicTransactionException if the command overflows the buffer in ATOMIC
   *     modification mode
   */
  private boolean checkModifyingCommand(
      AbstractPoCommandBuilder<? extends AbstractPoResponseParser> builder,
      AtomicBoolean overflow,
      AtomicInteger neededSessionBufferSpace) {
    if (builder.isSessionBufferUsed()) {
      // This command affects the PO modifications buffer
      neededSessionBufferSpace.set(
          builder.getApduRequest().getBytes().length
              + SESSION_BUFFER_CMD_ADDITIONAL_COST
              - APDU_HEADER_LENGTH);
      if (isSessionBufferOverflowed(neededSessionBufferSpace.get())) {
        // raise an exception if in atomic mode
        if (!poSecuritySettings.isMultipleSessionEnabled()) {
          throw new CalypsoAtomicTransactionException(
              "ATOMIC mode error! This command would overflow the PO modifications buffer: "
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
   * @return true or false
   */
  private boolean isSessionBufferOverflowed(int sessionBufferSizeConsumed) {
    boolean isSessionBufferFull = false;
    if (calypsoPoSmartCard.isModificationsCounterInBytes()) {
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

  /** Initialized the modifications buffer counter to its maximum value for the current PO */
  private void resetModificationsBufferCounter() {
    if (logger.isTraceEnabled()) {
      logger.trace(
          "Modifications buffer counter reset: PREVIOUSVALUE = {}, NEWVALUE = {}",
          modificationsCounter,
          calypsoPoSmartCard.getModificationsCounter());
    }
    modificationsCounter = calypsoPoSmartCard.getModificationsCounter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareReleasePoChannel() {
    channelControl = ChannelControl.CLOSE_AFTER;

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareSelectFile(byte[] lid) {
    // create the builder and add it to the list of commands
    poCommandManager.addRegularCommand(
        CalypsoPoUtils.prepareSelectFile(calypsoPoSmartCard.getPoClass(), lid));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareSelectFile(SelectFileControl control) {
    // create the builder and add it to the list of commands
    poCommandManager.addRegularCommand(
        CalypsoPoUtils.prepareSelectFile(calypsoPoSmartCard.getPoClass(), control));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareReadRecordFile(byte sfi, int recordNumber) {
    try {
      // create the builder and add it to the list of commands
      poCommandManager.addRegularCommand(
          CalypsoPoUtils.prepareReadRecordFile(calypsoPoSmartCard.getPoClass(), sfi, recordNumber));

      return this;
    } catch (RuntimeException e) {
      releaseSamResourceSilently();
      throw e;
    }
  }

  /** */
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
  public final PoTransactionService prepareReadRecordFile(
      byte sfi, int firstRecordNumber, int numberOfRecords, int recordSize) {

    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoPoUtils.SFI_MIN, CalypsoPoUtils.SFI_MAX, "sfi") //
        .isInRange(
            firstRecordNumber,
            CalypsoPoUtils.NB_REC_MIN,
            CalypsoPoUtils.NB_REC_MAX,
            "firstRecordNumber") //
        .isInRange(
            numberOfRecords,
            CalypsoPoUtils.NB_REC_MIN,
            CalypsoPoUtils.NB_REC_MAX - firstRecordNumber,
            "numberOfRecords");

    if (numberOfRecords == 1) {
      // create the builder and add it to the list of commands
      poCommandManager.addRegularCommand(
          new PoReadRecordsBuilder(
              calypsoPoSmartCard.getPoClass(),
              sfi,
              firstRecordNumber,
              PoReadRecordsBuilder.ReadMode.ONE_RECORD,
              recordSize));
    } else {
      // Manages the reading of multiple records taking into account the transmission capacity
      // of the PO and the response format (2 extra bytes)
      // Multiple APDUs can be generated depending on record size and transmission capacity.
      int recordsPerApdu = calypsoPoSmartCard.getPayloadCapacity() / (recordSize + 2);
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
        poCommandManager.addRegularCommand(
            new PoReadRecordsBuilder(
                calypsoPoSmartCard.getPoClass(),
                sfi,
                startRecordNumber,
                PoReadRecordsBuilder.ReadMode.MULTIPLE_RECORD,
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
  public final PoTransactionService prepareReadCounterFile(byte sfi, int countersNumber) {
    prepareReadRecordFile(sfi, 1, 1, countersNumber * 3);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareAppendRecord(byte sfi, byte[] recordData) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoPoUtils.SFI_MIN, CalypsoPoUtils.SFI_MAX, "sfi");

    // create the builder and add it to the list of commands
    poCommandManager.addRegularCommand(
        new PoAppendRecordBuilder(calypsoPoSmartCard.getPoClass(), sfi, recordData));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareUpdateRecord(
      byte sfi, int recordNumber, byte[] recordData) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoPoUtils.SFI_MIN, CalypsoPoUtils.SFI_MAX, "sfi") //
        .isInRange(
            recordNumber, CalypsoPoUtils.NB_REC_MIN, CalypsoPoUtils.NB_REC_MAX, "recordNumber");

    // create the builder and add it to the list of commands
    poCommandManager.addRegularCommand(
        new PoUpdateRecordBuilder(calypsoPoSmartCard.getPoClass(), sfi, recordNumber, recordData));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareWriteRecord(
      byte sfi, int recordNumber, byte[] recordData) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoPoUtils.SFI_MIN, CalypsoPoUtils.SFI_MAX, "sfi") //
        .isInRange(
            recordNumber, CalypsoPoUtils.NB_REC_MIN, CalypsoPoUtils.NB_REC_MAX, "recordNumber");

    // create the builder and add it to the list of commands
    poCommandManager.addRegularCommand(
        new PoWriteRecordBuilder(calypsoPoSmartCard.getPoClass(), sfi, recordNumber, recordData));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareIncreaseCounter(
      byte sfi, int counterNumber, int incValue) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoPoUtils.SFI_MIN, CalypsoPoUtils.SFI_MAX, "sfi") //
        .isInRange(
            counterNumber,
            CalypsoPoUtils.NB_CNT_MIN,
            CalypsoPoUtils.NB_CNT_MAX,
            "counterNumber") //
        .isInRange(
            incValue, CalypsoPoUtils.CNT_VALUE_MIN, CalypsoPoUtils.CNT_VALUE_MAX, "incValue");

    // create the builder and add it to the list of commands
    poCommandManager.addRegularCommand(
        new PoIncreaseBuilder(calypsoPoSmartCard.getPoClass(), sfi, counterNumber, incValue));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareDecreaseCounter(
      byte sfi, int counterNumber, int decValue) {
    Assert.getInstance() //
        .isInRange((int) sfi, CalypsoPoUtils.SFI_MIN, CalypsoPoUtils.SFI_MAX, "sfi") //
        .isInRange(
            counterNumber,
            CalypsoPoUtils.NB_CNT_MIN,
            CalypsoPoUtils.NB_CNT_MAX,
            "counterNumber") //
        .isInRange(
            decValue, CalypsoPoUtils.CNT_VALUE_MIN, CalypsoPoUtils.CNT_VALUE_MAX, "decValue");

    // create the builder and add it to the list of commands
    poCommandManager.addRegularCommand(
        new PoDecreaseBuilder(calypsoPoSmartCard.getPoClass(), sfi, counterNumber, decValue));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareSetCounter(byte sfi, int counterNumber, int newValue) {
    int delta;
    try {
      delta =
          newValue
              - calypsoPoSmartCard
                  .getFileBySfi(sfi)
                  .getData()
                  .getContentAsCounterValue(counterNumber);
    } catch (NoSuchElementException ex) {
      throw new CalypsoPoTransactionIllegalStateException(
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
  public final PoTransactionService prepareCheckPinStatus() {
    if (!calypsoPoSmartCard.isPinFeatureAvailable()) {
      throw new CalypsoPoTransactionIllegalStateException("PIN is not available for this PO.");
    }
    // create the builder and add it to the list of commands
    poCommandManager.addRegularCommand(new PoVerifyPinBuilder(calypsoPoSmartCard.getPoClass()));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareSvGet(
      SvSettings.Operation svOperation, SvSettings.Action svAction) {
    if (!calypsoPoSmartCard.isSvFeatureAvailable()) {
      throw new CalypsoPoTransactionIllegalStateException(
          "Stored Value is not available for this PO.");
    }
    if (poSecuritySettings.isLoadAndDebitSvLogRequired()
        && (calypsoPoSmartCard.getRevision() != PoRevision.REV3_2)) {
      // @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit logs are requested
      // for a non rev3.2 PO add two SvGet commands (for RELOAD then for DEBIT).
      SvSettings.Operation operation1 =
          SvSettings.Operation.RELOAD.equals(svOperation)
              ? SvSettings.Operation.DEBIT
              : SvSettings.Operation.RELOAD;
      poCommandManager.addStoredValueCommand(
          new PoSvGetBuilder(
              calypsoPoSmartCard.getPoClass(), calypsoPoSmartCard.getRevision(), operation1),
          operation1);
    }
    poCommandManager.addStoredValueCommand(
        new PoSvGetBuilder(
            calypsoPoSmartCard.getPoClass(), calypsoPoSmartCard.getRevision(), svOperation),
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
  public final PoTransactionService prepareSvReload(
      int amount, byte[] date, byte[] time, byte[] free) {
    // create the initial builder with the application data
    PoSvReloadBuilder svReloadCmdBuild =
        new PoSvReloadBuilder(
            calypsoPoSmartCard.getPoClass(),
            calypsoPoSmartCard.getRevision(),
            amount,
            CalypsoPoUtils.getSvKvc(),
            date,
            time,
            free);

    // get the security data from the SAM
    byte[] svReloadComplementaryData;
    try {
      svReloadComplementaryData =
          samCommandProcessor.getSvReloadComplementaryData(
              svReloadCmdBuild, CalypsoPoUtils.getSvGetHeader(), CalypsoPoUtils.getSvGetData());
    } catch (CalypsoSamCommandException e) {
      throw new CalypsoSamAnomalyException(
          SAM_COMMAND_ERROR + "preparing the SV reload command: " + e.getCommand().getName(), e);
    } catch (ReaderCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + "preparing the SV reload command.", e);
    } catch (CardCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_COMMUNICATION_ERROR + "preparing the SV reload command.", e);
    }

    // finalize the SvReload command builder with the data provided by the SAM
    svReloadCmdBuild.finalizeBuilder(svReloadComplementaryData);

    // create and keep the PoCommand
    poCommandManager.addStoredValueCommand(svReloadCmdBuild, SvSettings.Operation.RELOAD);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareSvReload(int amount) {
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
      throws CardCommunicationException, ReaderCommunicationException, CalypsoSamCommandException {

    if (!poSecuritySettings.isSvNegativeBalanceAllowed()
        && (calypsoPoSmartCard.getSvBalance() - amount) < 0) {
      throw new CalypsoPoTransactionIllegalStateException("Negative balances not allowed.");
    }

    // create the initial builder with the application data
    PoSvDebitBuilder svDebitCmdBuild =
        new PoSvDebitBuilder(
            calypsoPoSmartCard.getPoClass(),
            calypsoPoSmartCard.getRevision(),
            amount,
            CalypsoPoUtils.getSvKvc(),
            date,
            time);

    // get the security data from the SAM
    byte[] svDebitComplementaryData;
    svDebitComplementaryData =
        samCommandProcessor.getSvDebitComplementaryData(
            svDebitCmdBuild, CalypsoPoUtils.getSvGetHeader(), CalypsoPoUtils.getSvGetData());

    // finalize the SvDebit command builder with the data provided by the SAM
    svDebitCmdBuild.finalizeBuilder(svDebitComplementaryData);

    // create and keep the PoCommand
    poCommandManager.addStoredValueCommand(svDebitCmdBuild, SvSettings.Operation.DEBIT);
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
      throws CardCommunicationException, ReaderCommunicationException, CalypsoSamCommandException {

    // create the initial builder with the application data
    PoSvUndebitBuilder svUndebitCmdBuild =
        new PoSvUndebitBuilder(
            calypsoPoSmartCard.getPoClass(),
            calypsoPoSmartCard.getRevision(),
            amount,
            CalypsoPoUtils.getSvKvc(),
            date,
            time);

    // get the security data from the SAM
    byte[] svDebitComplementaryData;
    svDebitComplementaryData =
        samCommandProcessor.getSvUndebitComplementaryData(
            svUndebitCmdBuild, CalypsoPoUtils.getSvGetHeader(), CalypsoPoUtils.getSvGetData());

    // finalize the SvUndebit command builder with the data provided by the SAM
    svUndebitCmdBuild.finalizeBuilder(svDebitComplementaryData);

    // create and keep the PoCommand
    poCommandManager.addStoredValueCommand(svUndebitCmdBuild, SvSettings.Operation.DEBIT);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareSvDebit(int amount, byte[] date, byte[] time) {
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
    } catch (ReaderCommunicationException e) {
      throw new CalypsoSamIOException(
          SAM_READER_COMMUNICATION_ERROR + "preparing the SV debit/undebit command.", e);
    } catch (CardCommunicationException e) {
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
  public final PoTransactionService prepareSvDebit(int amount) {
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
  public final PoTransactionService prepareSvReadAllLogs() {
    if (calypsoPoSmartCard.getApplicationSubtype()
        != CalypsoPoUtils.STORED_VALUE_FILE_STRUCTURE_ID) {
      throw new CalypsoPoTransactionIllegalStateException(
          "The currently selected application is not an SV application.");
    }
    // reset SV data in PoSmartCard if any
    calypsoPoSmartCard.setSvData(0, 0, null, null);
    prepareReadRecordFile(
        CalypsoPoUtils.SV_RELOAD_LOG_FILE_SFI, CalypsoPoUtils.SV_RELOAD_LOG_FILE_NB_REC);
    prepareReadRecordFile(
        CalypsoPoUtils.SV_DEBIT_LOG_FILE_SFI,
        1,
        CalypsoPoUtils.SV_DEBIT_LOG_FILE_NB_REC,
        CalypsoPoUtils.SV_LOG_FILE_REC_LENGTH);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareInvalidate() {
    if (calypsoPoSmartCard.isDfInvalidated()) {
      throw new CalypsoPoTransactionIllegalStateException("This PO is already invalidated.");
    }
    poCommandManager.addRegularCommand(new PoInvalidateBuilder(calypsoPoSmartCard.getPoClass()));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final PoTransactionService prepareRehabilitate() {
    if (!calypsoPoSmartCard.isDfInvalidated()) {
      throw new CalypsoPoTransactionIllegalStateException("This PO is not invalidated.");
    }
    poCommandManager.addRegularCommand(new PoRehabilitateBuilder(calypsoPoSmartCard.getPoClass()));

    return this;
  }
}
