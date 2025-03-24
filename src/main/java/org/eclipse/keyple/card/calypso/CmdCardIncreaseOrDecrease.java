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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the "Increase/Decrease" APDU command.
 *
 * @since 2.1.0
 */
final class CmdCardIncreaseOrDecrease extends CardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardIncreaseOrDecrease.class);

  private static final int SW_POSTPONED_DATA = 0x6200;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session.", CardSessionBufferOverflowException.class));
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CardIllegalParameterException.class));
    m.put(
        0x6981,
        new StatusProperties(
            "The current EF is not a Counters or Simulated Counter EF.",
            CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (no session, wrong key, encryption required).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, DF is invalidated, etc.)",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Command not allowed (no current EF).", CardDataAccessException.class));
    m.put(0x6A80, new StatusProperties("Overflow error.", CardDataOutOfBoundsException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardDataAccessException.class));
    m.put(0x6103, new StatusProperties("Successful execution (possible only in ISO7816 T=0)."));
    m.put(
        SW_POSTPONED_DATA,
        new StatusProperties(
            "Successful execution, response data postponed until session closing."));
    STATUS_TABLE = m;
  }

  private final int sfi;
  private final int counterNumber;
  private final int incDecValue;

  /**
   * Constructor.
   *
   * @param isDecreaseCommand True if it is a "Decrease" command, false if it is an "Increase"
   *     command.
   * @param calypsoCard The Calypso card.
   * @param sfi SFI of the file to select or 00h for current EF.
   * @param counterNumber &gt;= 01h: Counters file, number of the counter. 00h: Simulated Counter.
   *     file.
   * @param incDecValue Value to subtract or add to the counter (defined as a positive int &lt;=
   *     16777215 [FFFFFFh])
   * @deprecated
   */
  @Deprecated
  CmdCardIncreaseOrDecrease(
      boolean isDecreaseCommand,
      CalypsoCardAdapter calypsoCard,
      byte sfi,
      int counterNumber,
      int incDecValue) {

    super(
        isDecreaseCommand ? CardCommandRef.DECREASE : CardCommandRef.INCREASE,
        3,
        calypsoCard,
        null,
        null);

    byte cla = calypsoCard.getCardClass().getValue();
    this.sfi = sfi;
    this.counterNumber = counterNumber;
    this.incDecValue = incDecValue;

    // convert the integer value into a 3-byte buffer
    // CL-COUN-DATAIN.1
    byte[] valueBuffer = ByteArrayUtil.extractBytes(incDecValue, 3);

    byte p2 = (byte) (sfi * 8);

    ApduRequestAdapter apduRequest;
    if (!calypsoCard.isCounterValuePostponed()) {
      /* this is a case4 command, we set Le = 0 */
      apduRequest =
          new ApduRequestAdapter(
              ApduUtil.build(
                  cla,
                  getCommandRef().getInstructionByte(),
                  (byte) counterNumber,
                  p2,
                  valueBuffer,
                  (byte) 0x00));
    } else {
      /* this command is considered as a case 3, we set Le = null */
      apduRequest =
          new ApduRequestAdapter(
              ApduUtil.build(
                  cla,
                  getCommandRef().getInstructionByte(),
                  (byte) counterNumber,
                  p2,
                  valueBuffer,
                  null));
      setExpectedResponseLength(0);
      apduRequest.addSuccessfulStatusWord(SW_POSTPONED_DATA);
    }

    setApduRequest(apduRequest);

    if (logger.isDebugEnabled()) {
      String extraInfo =
          String.format(
              "SFI:%02Xh, COUNTER:%d, %s:%d",
              sfi, counterNumber, isDecreaseCommand ? "DECREMENT" : "INCREMENT", incDecValue);
      addSubName(extraInfo);
    }
  }

  /**
   * Constructor.
   *
   * @param isDecreaseCommand True if it is a "Decrease" command, false if it is an "Increase"
   *     command.
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param sfi SFI of the file to select or 00h for current EF.
   * @param counterNumber &gt;= 01h: Counters file, number of the counter. 00h: Simulated Counter.
   *     file.
   * @param incDecValue Value to subtract or add to the counter (defined as a positive int &lt;=
   *     16777215 [FFFFFFh])
   * @since 2.3.2
   */
  CmdCardIncreaseOrDecrease(
      boolean isDecreaseCommand,
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      byte sfi,
      int counterNumber,
      int incDecValue) {

    super(
        isDecreaseCommand ? CardCommandRef.DECREASE : CardCommandRef.INCREASE,
        3,
        null,
        transactionContext,
        commandContext);

    this.sfi = sfi;
    this.counterNumber = counterNumber;
    this.incDecValue = incDecValue;

    // convert the integer value into a 3-byte buffer
    // CL-COUN-DATAIN.1
    byte[] valueBuffer = ByteArrayUtil.extractBytes(incDecValue, 3);

    byte p2 = (byte) (sfi * 8);

    ApduRequestAdapter apduRequest;
    if (!transactionContext.getCard().isCounterValuePostponed()) {
      /* this is a case4 command, we set Le = 0 */
      apduRequest =
          new ApduRequestAdapter(
              ApduUtil.build(
                  transactionContext.getCard().getCardClass().getValue(),
                  getCommandRef().getInstructionByte(),
                  (byte) counterNumber,
                  p2,
                  valueBuffer,
                  (byte) 0x00));
    } else {
      /* this command is considered as a case 3, we set Le = null */
      apduRequest =
          new ApduRequestAdapter(
              ApduUtil.build(
                  transactionContext.getCard().getCardClass().getValue(),
                  getCommandRef().getInstructionByte(),
                  (byte) counterNumber,
                  p2,
                  valueBuffer,
                  null));
      setExpectedResponseLength(0);
      apduRequest.addSuccessfulStatusWord(SW_POSTPONED_DATA);
    }

    setApduRequest(apduRequest);

    if (logger.isDebugEnabled()) {
      String extraInfo =
          String.format(
              "SFI:%02Xh, COUNTER:%d, %s:%d",
              sfi, counterNumber, isDecreaseCommand ? "DECREMENT" : "INCREMENT", incDecValue);
      addSubName(extraInfo);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  void setApduResponseAndCheckStatus(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);
    if (apduResponse.getStatusWord() == SW_POSTPONED_DATA) {
      if (!getCalypsoCard().isCounterValuePostponed()) {
        throw new CardUnknownStatusException("Unexpected status word: 6200h", getCommandRef());
      }
      getCalypsoCard()
          .setCounter(
              (byte) sfi, counterNumber != 0 ? counterNumber : 1, buildAnticipatedDataOut());
    } else {
      // Set returned value
      getCalypsoCard()
          .setCounter(
              (byte) sfi, counterNumber != 0 ? counterNumber : 1, apduResponse.getDataOut());
    }
  }

  /**
   * Builds the anticipated APDU response with the SW.
   *
   * @return A not empty byte array.
   * @throws IllegalStateException If the counter has not been read beforehand.
   * @since 2.3.2
   */
  byte[] buildAnticipatedResponse() {
    byte[] response;
    CalypsoCardAdapter card =
        getTransactionContext() != null ? getTransactionContext().getCard() : getCalypsoCard();
    if (card.isCounterValuePostponed()) {
      // Response = 6200
      response = new byte[2];
      response[0] = (byte) 0x62; // SW 6200
    } else {
      // Response = NNNNNN9000
      byte[] dataOut = buildAnticipatedDataOut();
      response = new byte[5];
      response[0] = dataOut[0];
      response[1] = dataOut[1];
      response[2] = dataOut[2];
      response[3] = (byte) 0x90; // SW 9000
    }
    return response;
  }

  /**
   * Builds the anticipated value of the APDU DataOut field.
   *
   * @return A 3-byte byte array.
   * @throws IllegalStateException If the counter has not been read beforehand.
   */
  private byte[] buildAnticipatedDataOut() {
    CalypsoCardAdapter card =
        getTransactionContext() != null ? getTransactionContext().getCard() : getCalypsoCard();
    ElementaryFile ef = card.getFileBySfi((byte) sfi);
    if (ef != null) {
      Integer oldCounterValue =
          ef.getData().getContentAsCounterValue(counterNumber != 0 ? counterNumber : 1);
      if (oldCounterValue != null) {
        return ByteArrayUtil.extractBytes(
            getCommandRef() == CardCommandRef.DECREASE
                ? oldCounterValue - incDecValue
                : oldCounterValue + incDecValue,
            3);
      }
    }
    throw new IllegalStateException(
        String.format(
            "Unable to determine the anticipated APDU response for the command '%s' (SFI %02Xh, counter %d)"
                + " because the counter has not been read beforehand.",
            getName(), sfi, counterNumber));
  }

  /**
   * {@inheritDoc}
   *
   * @return True
   * @since 2.0.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void finalizeRequest() {
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean isCryptoServiceRequiredToFinalizeRequest() {
    return getCommandContext().isEncryptionActive();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    if (getCommandContext().isEncryptionActive()) {
      return false;
    }
    updateTerminalSessionMacIfNeeded(buildAnticipatedResponse());
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    super.setApduResponseAndCheckStatus(apduResponse);
    if (apduResponse.getStatusWord() == SW_POSTPONED_DATA) {
      if (!getTransactionContext().getCard().isCounterValuePostponed()) {
        throw new CardUnknownStatusException("Unexpected status word: 6200h", getCommandRef());
      }
      getTransactionContext()
          .getCard()
          .setCounter(
              (byte) sfi, counterNumber != 0 ? counterNumber : 1, buildAnticipatedDataOut());
    } else {
      // Set returned value
      getTransactionContext()
          .getCard()
          .setCounter(
              (byte) sfi, counterNumber != 0 ? counterNumber : 1, apduResponse.getDataOut());
    }
    updateTerminalSessionMacIfNeeded();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
