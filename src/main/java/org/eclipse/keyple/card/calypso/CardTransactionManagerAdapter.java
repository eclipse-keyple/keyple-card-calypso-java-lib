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
  private static final String MSG_CARD_SIGNATURE_NOT_VERIFIABLE =
      "Unable to verify the card signature associated to the successfully closed secure session.";
  private static final String MSG_CARD_SIGNATURE_NOT_VERIFIABLE_SV =
      "Unable to verify the card signature associated to the SV operation.";

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
  private final CardSecuritySettingAdapter securitySetting;
  private final CardControlSamTransactionManagerAdapter controlSamTransactionManager;
  private final List<AbstractCardCommand> cardCommands = new ArrayList<AbstractCardCommand>();

  /* Dynamic fields */
  private boolean isSessionOpen;
  private WriteAccessLevel writeAccessLevel;
  private ChannelControl channelControl = ChannelControl.KEEP_OPEN;
  private int modificationsCounter;
  private SvOperation svOperation;
  private SvAction svAction;
  private CalypsoCardCommand svLastCommandRef;
  private AbstractCardCommand svLastModifyingCommand;
  private boolean isSvOperationInsideSession;
  private boolean isSvOperationComplete;

  /**
   * (package-private)<br>
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
      CardSecuritySettingAdapter securitySetting) {

    super(card, securitySetting, null);

    this.cardReader = cardReader;
    this.card = card;
    this.securitySetting = securitySetting;

    if (securitySetting != null && securitySetting.getControlSam() != null) {
      // Secure operations mode
      this.controlSamTransactionManager =
          new CardControlSamTransactionManagerAdapter(
              card, securitySetting, getTransactionAuditData());
    } else {
      // Non-secure operations mode
      this.controlSamTransactionManager = null;
    }

    this.modificationsCounter = card.getModificationsCounter();
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
   * (private)<br>
   * Checks if the control SAM is set.
   *
   * @throws IllegalStateException If control SAM is not set.
   */
  private void checkControlSam() {
    if (controlSamTransactionManager == null) {
      throw new IllegalStateException("Control SAM is not set.");
    }
  }

  /**
   * (private)<br>
   * Process the eventually prepared SAM commands if control SAM is set.
   */
  private void processSamPreparedCommands() {
    if (controlSamTransactionManager != null) {
      controlSamTransactionManager.processCommands();
    }
  }

  /**
   * (private)<br>
   * Open a single Secure Session.
   *
   * @param cardCommands the card commands inside session.
   * @throws IllegalStateException if no {@link CardSecuritySetting} is available.
   */
  private void processAtomicOpening(List<AbstractCardCommand> cardCommands) {

    if (securitySetting == null) {
      throw new IllegalStateException("No security settings are available.");
    }

    card.backupFiles();

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

    // Compute the SAM challenge and process all pending SAM commands
    byte[] samChallenge = processSamGetChallenge();

    // Build the "Open Secure Session" card command.
    CmdCardOpenSession cmdCardOpenSession =
        new CmdCardOpenSession(
            card.getProductType(),
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

    isSessionOpen = true;

    // Open a secure session, transmit the commands to the card and keep channel open
    CardResponseApi cardResponse = transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);

    // Retrieve the list of R-APDUs
    List<ApduResponseApi> apduResponses =
        cardResponse.getApduResponses(); // NOSONAR cardResponse is not null

    // Parse all the responses and fills the CalypsoCard object with the command data.
    try {
      CalypsoCardUtilAdapter.updateCalypsoCard(card, cardCommands, apduResponses, true);
    } catch (CardCommandException e) {
      throw new UnexpectedCommandStatusException(
          MSG_CARD_COMMAND_ERROR
              + "while processing the response to open session: "
              + e.getCommand()
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

    Byte kvc = controlSamTransactionManager.computeKvc(writeAccessLevel, cardKvc);
    Byte kif = controlSamTransactionManager.computeKif(writeAccessLevel, cardKif, kvc);

    if (!securitySetting.isSessionKeyAuthorized(kif, kvc)) {
      throw new UnauthorizedKeyException(
          String.format(
              "Unauthorized key error: KIF=%s, KVC=%s %s",
              kif != null ? String.format(PATTERN_1_BYTE_HEX, kif) : null,
              kvc != null ? String.format(PATTERN_1_BYTE_HEX, kvc) : null,
              getTransactionAuditDataAsString()));
    }

    // Initialize a new SAM session.
    controlSamTransactionManager.initializeSession(
        apduResponses.get(0).getDataOut(), kif, kvc, false, false);

    // Add all commands data to the digest computation. The first command in the list is the
    // open secure session command. This command is not included in the digest computation, so
    // we skip it and start the loop at index 1.
    controlSamTransactionManager.updateSession(apduRequests, apduResponses, 1);
  }

  /**
   * (private)<br>
   * Aborts the secure session without raising any exception.
   */
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
    if (isSessionOpen) {
      controlSamTransactionManager.updateSession(apduRequests, apduResponses, 0);
    }

    try {
      CalypsoCardUtilAdapter.updateCalypsoCard(card, cardCommands, apduResponses, isSessionOpen);
    } catch (CardCommandException e) {
      throw new UnexpectedCommandStatusException(
          MSG_CARD_COMMAND_ERROR
              + "while processing responses to card commands: "
              + e.getCommand()
              + getTransactionAuditDataAsString(),
          e);
    } catch (InconsistentDataException e) {
      throw new InconsistentDataException(e.getMessage() + getTransactionAuditDataAsString());
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

    // Add all commands data to the digest computation.
    controlSamTransactionManager.updateSession(apduRequests, expectedApduResponses, 0);

    // All SAM digest operations will now run at once.
    // Get Terminal Signature from the latest response.
    byte[] sessionTerminalSignature = processSamSessionClosing();

    // Build the last "Close Secure Session" card command.
    CmdCardCloseSession cmdCardCloseSession =
        new CmdCardCloseSession(card, !isRatificationMechanismEnabled, sessionTerminalSignature);

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
      CalypsoCardUtilAdapter.updateCalypsoCard(card, cardCommands, apduResponses, true);
    } catch (CardCommandException e) {
      throw new UnexpectedCommandStatusException(
          MSG_CARD_COMMAND_ERROR
              + "while processing of responses preceding the close of the session: "
              + e.getCommand()
              + getTransactionAuditDataAsString(),
          e);
    } catch (InconsistentDataException e) {
      throw new InconsistentDataException(e.getMessage() + getTransactionAuditDataAsString());
    }

    isSessionOpen = false;

    // Check the card's response to Close Secure Session
    try {
      CalypsoCardUtilAdapter.updateCalypsoCard(
          card, cmdCardCloseSession, closeSecureSessionApduResponse, false);
    } catch (CardSecurityDataException e) {
      throw new UnexpectedCommandStatusException(
          "Invalid card session" + getTransactionAuditDataAsString(), e);
    } catch (CardCommandException e) {
      throw new UnexpectedCommandStatusException(
          MSG_CARD_COMMAND_ERROR
              + "while processing the response to close session: "
              + e.getCommand()
              + getTransactionAuditDataAsString(),
          e);
    }

    // Check the card signature
    // CL-CSS-MACVERIF.1
    processSamDigestAuthenticate(cmdCardCloseSession.getSignatureLo());

    // If necessary, we check the status of the SV after the session has been successfully
    // closed.
    // CL-SV-POSTPON.1
    if (isSvOperationCompleteOneTime()) {
      processSamSvCheck(cmdCardCloseSession.getPostponedData());
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
    ElementaryFile ef = card.getFileBySfi((byte) sfi);
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
  public CardTransactionManager processOpening(WriteAccessLevel writeAccessLevel) {
    try {
      checkNoSession();

      // CL-KEY-INDEXPO.1
      this.writeAccessLevel = writeAccessLevel;

      // Create a sublist of AbstractCardCommand to be sent atomically
      List<AbstractCardCommand> cardAtomicCommands = new ArrayList<AbstractCardCommand>();

      for (AbstractCardCommand command : cardCommands) {
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
   * (private)<br>
   * Throws an exception if the multiple session is not enabled.
   *
   * @param command The command.
   * @throws SessionBufferOverflowException If the multiple session is not allowed.
   */
  private void checkMultipleSessionEnabled(AbstractCardCommand command) {
    // CL-CSS-REQUEST.1
    // CL-CSS-SMEXCEED.1
    // CL-CSS-INFOCSS.1
    if (!securitySetting.isMultipleSessionEnabled()) {
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
   *
   * @param channelControl indicates if the card channel of the card reader must be closed after the
   *     last command.
   */
  private void processCommandsOutsideSession(ChannelControl channelControl) {

    // card commands sent outside a Secure Session. No modifications buffer limitation.
    processAtomicCardCommands(cardCommands, channelControl);

    // sets the flag indicating that the commands have been executed
    notifyCommandsProcessed();

    // If an SV transaction was performed, we check the signature returned by the card here
    if (isSvOperationCompleteOneTime()) {
      // Execute all prepared SAM commands and check SV status.
      processSamSvCheck(card.getSvOperationSignature());
    } else {
      // Execute all prepared SAM commands.
      processSamPreparedCommands();
    }
  }

  /**
   * (private)<br>
   * Process all prepared card commands in a Secure Session.
   *
   * <p>The multiple session mode is handled according to the session settings.
   */
  private void processCommandsInsideSession() {
    try {
      // A session is open, we have to care about the card modifications buffer
      List<AbstractCardCommand> cardAtomicCommands = new ArrayList<AbstractCardCommand>();
      boolean isAtLeastOneReadCommand = false;

      for (AbstractCardCommand command : cardCommands) {
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
  public CardTransactionManager prepareComputeSignature(SignatureComputationData data) {
    checkControlSam();
    controlSamTransactionManager.prepareComputeSignature(data);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public CardTransactionManager prepareVerifySignature(SignatureVerificationData data) {
    checkControlSam();
    controlSamTransactionManager.prepareVerifySignature(data);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public CardTransactionManager processCommands() {
    if (isSessionOpen) {
      processCommandsInsideSession();
    } else {
      processCommandsOutsideSession(channelControl);
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

      List<AbstractCardCommand> cardAtomicCommands = new ArrayList<AbstractCardCommand>();
      boolean isAtLeastOneReadCommand = false;

      for (AbstractCardCommand command : cardCommands) {
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
      }

      processAtomicClosing(
          cardAtomicCommands, securitySetting.isRatificationMechanismEnabled(), channelControl);

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
      cmdCardCloseSession
          .setApduResponse(
              cardResponse.getApduResponses().get(0)) // NOSONAR cardResponse is not null
          .checkStatus();
    } catch (CardCommandException e) {
      throw new UnexpectedCommandStatusException(
          MSG_CARD_COMMAND_ERROR
              + "while processing the response to close session: "
              + e.getCommand()
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

      // CL-PIN-PENCRYPT.1
      if (securitySetting != null && !securitySetting.isPinPlainTransmissionEnabled()) {

        // CL-PIN-GETCHAL.1
        cardCommands.add(new CmdCardGetChallenge(card.getCardClass()));

        // transmit and receive data with the card
        processAtomicCardCommands(cardCommands, ChannelControl.KEEP_OPEN);

        // sets the flag indicating that the commands have been executed
        notifyCommandsProcessed();

        // Get the encrypted PIN with the help of the SAM
        byte[] cipheredPin = processSamCardCipherPin(pin, null);

        cardCommands.add(new CmdCardVerifyPin(card.getCardClass(), true, cipheredPin));
      } else {
        cardCommands.add(new CmdCardVerifyPin(card.getCardClass(), false, pin));
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
   * (private)<br>
   * Processes the "Card Cipher PIN" command on the control SAM.
   *
   * @param currentPin The current PIN.
   * @param newPin The new PIN, or null in case of a PIN presentation.
   * @return The cipher PIN data from the SAM (ciphered PIN transmission or PIN change).
   */
  private byte[] processSamCardCipherPin(byte[] currentPin, byte[] newPin) {
    controlSamTransactionManager.prepareGiveRandom();
    CmdSamCardCipherPin cmdSamCardCipherPin =
        controlSamTransactionManager.prepareCardCipherPin(currentPin, newPin);
    controlSamTransactionManager.processCommands();
    return cmdSamCardCipherPin.getCipheredData();
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

      // CL-PIN-MENCRYPT.1
      if (securitySetting.isPinPlainTransmissionEnabled()) {
        // transmission in plain mode
        if (card.getPinAttemptRemaining() >= 0) {
          cardCommands.add(new CmdCardChangePin(card.getCardClass(), newPin));
        }
      } else {
        // CL-PIN-GETCHAL.1
        cardCommands.add(new CmdCardGetChallenge(card.getCardClass()));

        // transmit and receive data with the card
        processAtomicCardCommands(cardCommands, ChannelControl.KEEP_OPEN);

        // sets the flag indicating that the commands have been executed
        notifyCommandsProcessed();

        // Get the encrypted PIN with the help of the SAM
        byte[] currentPin = new byte[4]; // all zeros as required
        byte[] newPinData = processSamCardCipherPin(currentPin, newPin);

        cardCommands.add(new CmdCardChangePin(card.getCardClass(), newPinData));
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

    // CL-KEY-CHANGE.1
    cardCommands.add(new CmdCardGetChallenge(card.getCardClass()));

    // transmit and receive data with the card
    processAtomicCardCommands(cardCommands, ChannelControl.KEEP_OPEN);

    // sets the flag indicating that the commands have been executed
    notifyCommandsProcessed();

    // Get the encrypted key with the help of the SAM
    byte[] encryptedKey = processSamCardGenerateKey(issuerKif, issuerKvc, newKif, newKvc);

    cardCommands.add(new CmdCardChangeKey(card.getCardClass(), (byte) keyIndex, encryptedKey));

    // transmit and receive data with the card
    processAtomicCardCommands(cardCommands, channelControl);

    // sets the flag indicating that the commands have been executed
    notifyCommandsProcessed();

    return this;
  }

  /**
   * (private)<br>
   * Processes the "Card Generate Key" command on the control SAM.
   *
   * @param issuerKif The KIF of the key used for encryption.
   * @param issuerKvc The KVC of the key used for encryption.
   * @param newKif The KIF of the key to encrypt.
   * @param newKvc The KVC of the key to encrypt.
   * @return The value of the encrypted key.
   */
  private byte[] processSamCardGenerateKey(
      byte issuerKif, byte issuerKvc, byte newKif, byte newKvc) {
    controlSamTransactionManager.prepareGiveRandom();
    CmdSamCardGenerateKey cmdSamCardGenerateKey =
        controlSamTransactionManager.prepareCardGenerateKey(issuerKif, issuerKvc, newKif, newKvc);
    controlSamTransactionManager.processCommands();
    return cmdSamCardGenerateKey.getCipheredData();
  }

  /**
   * (private)<br>
   * Transmits a card request, processes and converts any exceptions.
   *
   * @param cardRequest The card request to transmit.
   * @param channelControl The channel control.
   * @return The card response.
   */
  private CardResponseApi transmitCardRequest(
      CardRequestSpi cardRequest, ChannelControl channelControl) {

    // Process SAM operations first for SV if needed.
    if (svLastModifyingCommand != null) {
      finalizeSvCommand();
    }

    // Process card request.
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
   * (private)<br>
   * Finalizes the last SV modifying command.
   */
  private void finalizeSvCommand() {

    byte[] svComplementaryData;

    if (svLastModifyingCommand.getCommandRef() == CalypsoCardCommand.SV_RELOAD) {

      // SV RELOAD: get the security data from the SAM
      CmdCardSvReload svCommand = (CmdCardSvReload) svLastModifyingCommand;

      svComplementaryData =
          processSamSvPrepareLoad(card.getSvGetHeader(), card.getSvGetData(), svCommand);

      // finalize the SV command with the data provided by the SAM
      svCommand.finalizeCommand(svComplementaryData);

    } else {

      // SV DEBIT/UNDEBIT: get the security data from the SAM
      CmdCardSvDebitOrUndebit svCommand = (CmdCardSvDebitOrUndebit) svLastModifyingCommand;

      svComplementaryData =
          processSamSvPrepareDebitOrUndebit(
              svCommand.getCommandRef() == CalypsoCardCommand.SV_DEBIT,
              card.getSvGetHeader(),
              card.getSvGetData(),
              svCommand);

      // finalize the SV command with the data provided by the SAM
      svCommand.finalizeCommand(svComplementaryData);
    }
  }

  /**
   * (private)<br>
   * Processes the "SV Prepare Load" command on the control SAM.
   *
   * <p>Computes the cryptographic data required for the SvReload command.
   *
   * <p>Use the data from the SvGet command and the partial data from the SvReload command for this
   * purpose.
   *
   * <p>The returned data will be used to finalize the card SvReload command.
   *
   * @param svGetHeader the SV Get command header.
   * @param svGetData the SV Get command response data.
   * @param cmdCardSvReload the SvDebit command providing the SvReload partial data.
   * @return The complementary security data to finalize the SvReload card command (sam ID + SV
   *     prepare load output)
   */
  private byte[] processSamSvPrepareLoad(
      byte[] svGetHeader, byte[] svGetData, CmdCardSvReload cmdCardSvReload) {
    CmdSamSvPrepareLoad cmdSamSvPrepareLoad =
        controlSamTransactionManager.prepareSvPrepareLoad(svGetHeader, svGetData, cmdCardSvReload);
    controlSamTransactionManager.processCommands();
    byte[] prepareOperationData = cmdSamSvPrepareLoad.getApduResponse().getDataOut();
    return computeOperationComplementaryData(prepareOperationData);
  }

  /**
   * (private)<br>
   * Processes the "SV Prepare Debit/Undebit" command on the control SAM.
   *
   * <p>Computes the cryptographic data required for the SvDebit or SvUndebit command.
   *
   * <p>Use the data from the SvGet command and the partial data from the SvDebit command for this
   * purpose.
   *
   * <p>The returned data will be used to finalize the card SvDebit command.
   *
   * @param isDebitCommand True if the command is a DEBIT, false for UNDEBIT.
   * @param svGetHeader the SV Get command header.
   * @param svGetData the SV Get command response data.
   * @param cmdCardSvDebitOrUndebit The SvDebit or SvUndebit command providing the partial data.
   * @return The complementary security data to finalize the SvDebit/SvUndebit card command (sam ID
   *     + SV prepare debit/debit output)
   */
  private byte[] processSamSvPrepareDebitOrUndebit(
      boolean isDebitCommand,
      byte[] svGetHeader,
      byte[] svGetData,
      CmdCardSvDebitOrUndebit cmdCardSvDebitOrUndebit) {
    CmdSamSvPrepareDebitOrUndebit cmdSamSvPrepareDebitOrUndebit =
        controlSamTransactionManager.prepareSvPrepareDebitOrUndebit(
            isDebitCommand, svGetHeader, svGetData, cmdCardSvDebitOrUndebit);
    controlSamTransactionManager.processCommands();
    byte[] prepareOperationData = cmdSamSvPrepareDebitOrUndebit.getApduResponse().getDataOut();
    return computeOperationComplementaryData(prepareOperationData);
  }

  /**
   * (private)<br>
   * Generic method to get the complementary data from SvPrepareLoad/Debit/Undebit commands
   *
   * <p>This data comprises:
   *
   * <ul>
   *   <li>The SAM identifier (4 bytes)
   *   <li>The SAM challenge (3 bytes)
   *   <li>The SAM transaction number (3 bytes)
   *   <li>The SAM part of the SV signature (5 or 10 bytes depending on card mode)
   * </ul>
   *
   * @param prepareOperationData the prepare operation output data.
   * @return a byte array containing the complementary data
   */
  private byte[] computeOperationComplementaryData(byte[] prepareOperationData) {

    byte[] samSerialNumber = securitySetting.getControlSam().getSerialNumber();
    byte[] operationComplementaryData =
        new byte[samSerialNumber.length + prepareOperationData.length];

    System.arraycopy(samSerialNumber, 0, operationComplementaryData, 0, samSerialNumber.length);
    System.arraycopy(
        prepareOperationData,
        0,
        operationComplementaryData,
        samSerialNumber.length,
        prepareOperationData.length);

    return operationComplementaryData;
  }

  /**
   * (private)<br>
   * Processes the "SV Prepare Debit/Undebit" command on the control SAM.
   *
   * <p>Checks the status of the last SV operation.
   *
   * <p>The card signature is compared by the SAM with the one it has computed on its side.
   *
   * @param svOperationData The data of the SV operation performed.
   */
  private void processSamSvCheck(byte[] svOperationData) {
    controlSamTransactionManager.prepareSvCheck(svOperationData);
    try {
      controlSamTransactionManager.processCommands();
    } catch (ReaderIOException e) {
      throw new CardSignatureNotVerifiableException(MSG_CARD_SIGNATURE_NOT_VERIFIABLE_SV, e);
    } catch (SamIOException e) {
      throw new CardSignatureNotVerifiableException(MSG_CARD_SIGNATURE_NOT_VERIFIABLE_SV, e);
    }
  }

  /**
   * (private)<br>
   * Processes the "Get Challenge" command on the control SAM.
   *
   * @return The SAM challenge.
   */
  private byte[] processSamGetChallenge() {
    CmdSamGetChallenge cmdSamGetChallenge = controlSamTransactionManager.prepareGetChallenge();
    controlSamTransactionManager.processCommands();
    byte[] samChallenge = cmdSamGetChallenge.getChallenge();
    if (logger.isDebugEnabled()) {
      logger.debug("SAM_CHALLENGE={}", HexUtil.toHex(samChallenge));
    }
    return samChallenge;
  }

  /**
   * (private)<br>
   * Processes the pending session command including the "Digest Close" command on the control SAM.
   *
   * @return The terminal signature from the SAM
   */
  private byte[] processSamSessionClosing() {
    CmdSamDigestClose cmdSamDigestClose = controlSamTransactionManager.prepareSessionClosing();
    controlSamTransactionManager.processCommands();
    byte[] terminalSignature = cmdSamDigestClose.getSignature();
    if (logger.isDebugEnabled()) {
      logger.debug("SAM_SIGNATURE={}", HexUtil.toHex(terminalSignature));
    }
    return terminalSignature;
  }

  /**
   * (private)<br>
   * Processes the "Digest Authenticate" command on the control SAM.
   *
   * @param cardSignature The card signature to check.
   */
  private void processSamDigestAuthenticate(byte[] cardSignature) {
    controlSamTransactionManager.prepareDigestAuthenticate(cardSignature);
    try {
      controlSamTransactionManager.processCommands();
    } catch (ReaderIOException e) {
      throw new CardSignatureNotVerifiableException(MSG_CARD_SIGNATURE_NOT_VERIFIABLE, e);
    } catch (SamIOException e) {
      throw new CardSignatureNotVerifiableException(MSG_CARD_SIGNATURE_NOT_VERIFIABLE, e);
    }
  }

  /**
   * (private)<br>
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
   * (private)<br>
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
   * (private)<br>
   * Computes the session buffer size of the provided command.<br>
   * The size may be a number of bytes or 1 depending on the card specificities.
   *
   * @param command The command.
   * @return A positive value.
   */
  private int computeCommandSessionBufferSize(AbstractCardCommand command) {
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
    cardCommands.add(new CmdCardSelectFile(card.getCardClass(), card.getProductType(), lid));
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
    cardCommands.add(new CmdCardSelectFile(card.getCardClass(), selectFileControl));

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
        cardCommands.add(new CmdCardGetDataFci(card.getCardClass()));
        break;
      case FCP_FOR_CURRENT_FILE:
        cardCommands.add(new CmdCardGetDataFcp(card.getCardClass()));
        break;
      case EF_LIST:
        cardCommands.add(new CmdCardGetDataEfList(card.getCardClass()));
        break;
      case TRACEABILITY_INFORMATION:
        cardCommands.add(new CmdCardGetDataTraceabilityInformation(card.getCardClass()));
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
        new CmdCardReadRecords(
            card.getCardClass(), sfi, recordNumber, CmdCardReadRecords.ReadMode.ONE_RECORD, 0);
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
            toRecordNumber, fromRecordNumber, CalypsoCardConstant.NB_REC_MAX, "toRecordNumber");

    if (toRecordNumber == fromRecordNumber) {
      // create the command and add it to the list of commands
      cardCommands.add(
          new CmdCardReadRecords(
              card.getCardClass(),
              sfi,
              fromRecordNumber,
              CmdCardReadRecords.ReadMode.ONE_RECORD,
              recordSize));
    } else {
      // Manages the reading of multiple records taking into account the transmission capacity
      // of the card and the response format (2 extra bytes).
      // Multiple APDUs can be generated depending on record size and transmission capacity.
      final CalypsoCardClass cardClass = card.getCardClass();
      final int nbBytesPerRecord = recordSize + 2;
      final int nbRecordsPerApdu = card.getPayloadCapacity() / nbBytesPerRecord;
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
        cardCommands.add(
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
            CalypsoCardConstant.DATA_LENGTH_MAX - offset,
            "nbBytesToRead");

    final CalypsoCardClass cardClass = card.getCardClass();
    final int nbRecordsPerApdu = card.getPayloadCapacity() / nbBytesToRead;

    int currentRecordNumber = fromRecordNumber;

    while (currentRecordNumber <= toRecordNumber) {
      cardCommands.add(
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

    if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3) {
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
      cardCommands.add(new CmdCardReadBinary(card.getCardClass(), sfi, 0, (byte) 1));
    }

    final int payloadCapacity = card.getPayloadCapacity();
    final CalypsoCardClass cardClass = card.getCardClass();

    int currentLength;
    int currentOffset = offset;
    int nbBytesRemainingToRead = nbBytesToRead;
    do {
      currentLength = Math.min(nbBytesRemainingToRead, payloadCapacity);

      cardCommands.add(new CmdCardReadBinary(cardClass, sfi, currentOffset, (byte) currentLength));

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

    cardCommands.add(new CmdCardSearchRecordMultiple(card.getCardClass(), dataAdapter));

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
        .notNull(recordData, "recordData");

    // create the command and add it to the list of commands
    cardCommands.add(new CmdCardAppendRecord(card.getCardClass(), sfi, recordData));

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
        .notNull(recordData, "recordData");

    // create the command and add it to the list of commands
    cardCommands.add(new CmdCardUpdateRecord(card.getCardClass(), sfi, recordNumber, recordData));

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
            RECORD_NUMBER);

    // create the command and add it to the list of commands
    cardCommands.add(new CmdCardWriteRecord(card.getCardClass(), sfi, recordNumber, recordData));

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

    if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3) {
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
      cardCommands.add(new CmdCardReadBinary(card.getCardClass(), sfi, 0, (byte) 1));
    }

    final int dataLength = data.length;
    final int payloadCapacity = card.getPayloadCapacity();
    final CalypsoCardClass cardClass = card.getCardClass();

    int currentLength;
    int currentOffset = offset;
    int currentIndex = 0;
    do {
      currentLength = Math.min(dataLength - currentIndex, payloadCapacity);

      cardCommands.add(
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
   * (private)<br>
   * Factorisation of prepareDecreaseCounter and prepareIncreaseCounter.
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
    cardCommands.add(
        new CmdCardIncreaseOrDecrease(
            isDecreaseCommand, card.getCardClass(), sfi, counterNumber, incDecValue));

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
   * (private)<br>
   * Factorisation of prepareDecreaseMultipleCounters and prepareIncreaseMultipleCounters.
   */
  private CardTransactionManager prepareIncreaseOrDecreaseCounters(
      boolean isDecreaseCommand, byte sfi, Map<Integer, Integer> counterNumberToIncDecValueMap) {

    if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3
        && card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_2) {
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
    final int nbCountersPerApdu = card.getPayloadCapacity() / 4;
    if (counterNumberToIncDecValueMap.size() <= nbCountersPerApdu) {
      // create the command and add it to the list of commands
      cardCommands.add(
          new CmdCardIncreaseOrDecreaseMultiple(
              isDecreaseCommand,
              card.getCardClass(),
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
          cardCommands.add(
              new CmdCardIncreaseOrDecreaseMultiple(
                  isDecreaseCommand, card.getCardClass(), sfi, new TreeMap<Integer, Integer>(map)));
          i = 0;
          map.clear();
        }
      }
      if (!map.isEmpty()) {
        cardCommands.add(
            new CmdCardIncreaseOrDecreaseMultiple(
                isDecreaseCommand, card.getCardClass(), sfi, map));
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
    cardCommands.add(new CmdCardVerifyPin(card.getCardClass()));

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

    // CL-SV-CMDMODE.1
    CalypsoSam calypsoSam = securitySetting.getControlSam();
    boolean useExtendedMode =
        card.isExtendedModeSupported()
            && (calypsoSam == null || calypsoSam.getProductType() == CalypsoSam.ProductType.SAM_C1);

    if (securitySetting.isSvLoadAndDebitLogEnabled() && (!useExtendedMode)) {
      // @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit logs are requested
      // for a non rev3.2 card add two SvGet commands (for RELOAD then for DEBIT).
      // CL-SV-GETNUMBER.1
      SvOperation operation1 =
          SvOperation.RELOAD.equals(svOperation) ? SvOperation.DEBIT : SvOperation.RELOAD;
      addStoredValueCommand(new CmdCardSvGet(card.getCardClass(), operation1, false), operation1);
    }
    addStoredValueCommand(
        new CmdCardSvGet(card.getCardClass(), svOperation, useExtendedMode), svOperation);
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
        new CmdCardSvReload(
            card.getCardClass(),
            amount,
            card.getSvKvc(),
            date,
            time,
            free,
            isExtendedModeAllowed());

    // create and keep the CalypsoCardCommand
    addStoredValueCommand(svReloadCmdBuild, SvOperation.RELOAD);

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
    if (isSessionOpen) {
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
    CalypsoSam calypsoSam = securitySetting.getControlSam();
    return card.isExtendedModeSupported()
        && calypsoSam.getProductType() == CalypsoSam.ProductType.SAM_C1;
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
        && !securitySetting.isSvNegativeBalanceAuthorized()
        && (card.getSvBalance() - amount) < 0) {
      throw new IllegalStateException("Negative balances not allowed.");
    }

    // create the initial command with the application data
    CmdCardSvDebitOrUndebit command =
        new CmdCardSvDebitOrUndebit(
            svAction == SvAction.DO,
            card.getCardClass(),
            amount,
            card.getSvKvc(),
            date,
            time,
            isExtendedModeAllowed());

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
    cardCommands.add(new CmdCardInvalidate(card.getCardClass()));

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
    cardCommands.add(new CmdCardRehabilitate(card.getCardClass()));

    return this;
  }

  /**
   * (private)<br>
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
  private void addStoredValueCommand(AbstractCardCommand command, SvOperation svOperation) {
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
        if (svLastCommandRef != CalypsoCardCommand.SV_GET) {
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
   * (private)<br>
   * Informs that the commands have been processed.
   *
   * <p>Just record the information. The initialization of the list of commands will be done only
   * the next time a command is added, this allows access to the commands contained in the list.
   */
  private void notifyCommandsProcessed() {
    cardCommands.clear();
    svLastModifyingCommand = null;
  }

  /**
   * (private)<br>
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
