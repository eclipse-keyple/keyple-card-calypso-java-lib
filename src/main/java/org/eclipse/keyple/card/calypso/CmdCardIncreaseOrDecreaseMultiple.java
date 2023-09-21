/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keypop.calypso.card.card.ElementaryFile;
import org.eclipse.keypop.card.ApduResponseApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the "Increase/Decrease Multiple" APDU command.
 *
 * @since 2.1.0
 */
final class CmdCardIncreaseOrDecreaseMultiple extends CardCommand {

  private static final Logger logger =
      LoggerFactory.getLogger(CmdCardIncreaseOrDecreaseMultiple.class);
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
            "Incorrect EF type: not a Counters EF.", CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (no secure session, incorrect key, encryption required, PKI mode and not Always access mode).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, DF is invalid, etc.).",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Incorrect file type: the Current File is not an EF. Supersedes 6981h.",
            CardDataAccessException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect command data (Overflow error, Incorrect counter number, Counter number present more than once).",
            CardIllegalParameterException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final byte sfi;
  private final Map<Integer, Integer> counterNumberToIncDecValueMap;

  /**
   * Constructor.
   *
   * @param isDecreaseCommand True if it is a "Decrease Multiple" command, false if it is an
   *     "Increase Multiple" command.
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param sfi The SFI.
   * @param counterNumberToIncDecValueMap The map containing the counter numbers to be incremented
   *     and their associated increment values.
   * @since 2.1.0
   */
  CmdCardIncreaseOrDecreaseMultiple(
      boolean isDecreaseCommand,
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      byte sfi,
      SortedMap<Integer, Integer> counterNumberToIncDecValueMap) {

    super(
        isDecreaseCommand ? CardCommandRef.DECREASE_MULTIPLE : CardCommandRef.INCREASE_MULTIPLE,
        0,
        null,
        transactionContext,
        commandContext);

    this.sfi = sfi;
    this.counterNumberToIncDecValueMap = counterNumberToIncDecValueMap;
    byte p1 = 0;
    byte p2 = (byte) (sfi * 8);
    byte[] dataIn = new byte[4 * counterNumberToIncDecValueMap.size()];
    int index = 0;
    for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
      dataIn[index] = entry.getKey().byteValue();
      Integer incDecValue = entry.getValue();
      ByteArrayUtil.copyBytes(incDecValue, dataIn, index + 1, 3);
      index += 4;
    }
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                transactionContext.getCard().getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                p1,
                p2,
                dataIn,
                (byte) 0)));

    if (logger.isDebugEnabled()) {
      StringBuilder extraInfo = new StringBuilder(String.format("SFI:%02Xh", sfi));
      for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
        extraInfo.append(", ");
        extraInfo.append(entry.getKey());
        extraInfo.append(":");
        extraInfo.append(entry.getValue());
      }
      addSubName(extraInfo.toString());
    }
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
    if (apduResponse.getDataOut().length > 0) {
      byte[] dataOut = apduResponse.getDataOut();
      int nbCounters = dataOut.length / 4;
      for (int i = 0; i < nbCounters; i++) {
        getTransactionContext()
            .getCard()
            .setCounter(
                sfi, dataOut[i * 4] & 0xFF, Arrays.copyOfRange(dataOut, (i * 4) + 1, (i * 4) + 4));
      }
    }
    updateTerminalSessionMacIfNeeded();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * Builds the anticipated APDU response with the SW.
   *
   * @return A not empty byte array.
   * @throws IllegalStateException If some expected counters have not been read beforehand.
   * @since 2.3.2
   */
  byte[] buildAnticipatedResponse() {
    // Response = CCVVVVVV..CCVVVVVV9000
    Map<Integer, Integer> oldCounterValues = getOldCounterValues();
    byte[] response = new byte[2 + (counterNumberToIncDecValueMap.size() * 4)];
    int index = 0;
    for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
      response[index] = entry.getKey().byteValue();
      int newCounterValue;
      if (getCommandRef() == CardCommandRef.DECREASE_MULTIPLE) {
        newCounterValue = oldCounterValues.get(entry.getKey()) - entry.getValue();
      } else {
        newCounterValue = oldCounterValues.get(entry.getKey()) + entry.getValue();
      }
      ByteArrayUtil.copyBytes(newCounterValue, response, index + 1, 3);
      index += 4;
    }
    response[index] = (byte) 0x90; // SW 9000
    return response;
  }

  /**
   * Gets the value of all counters currently presents in the card image.
   *
   * @return A not empty map.
   * @throws IllegalStateException If some expected counters have not been read beforehand.
   */
  private Map<Integer, Integer> getOldCounterValues() {
    CalypsoCardAdapter card =
        getTransactionContext() != null ? getTransactionContext().getCard() : getCalypsoCard();
    ElementaryFile ef = card.getFileBySfi(sfi);
    if (ef != null) {
      Map<Integer, Integer> allCountersValue = ef.getData().getAllCountersValue();
      if (allCountersValue.keySet().containsAll(counterNumberToIncDecValueMap.keySet())) {
        return allCountersValue;
      }
    }
    throw new IllegalStateException(
        String.format(
            "Unable to determine the anticipated APDU response for the command '%s' (SFI %02Xh)"
                + " because some expected counters have not been read beforehand.",
            getName(), sfi));
  }
}
