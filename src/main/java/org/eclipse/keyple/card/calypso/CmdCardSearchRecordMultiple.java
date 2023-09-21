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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.card.ApduResponseApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the "Search Record Multiple" APDU command.
 *
 * @since 2.1.0
 */
final class CmdCardSearchRecordMultiple extends CardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardSearchRecordMultiple.class);
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6400,
        new StatusProperties(
            "Data Out overflow (outgoing data would be too long).",
            CardSessionBufferOverflowException.class));
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported (<4).", CardIllegalParameterException.class));
    m.put(
        0x6981,
        new StatusProperties("Incorrect EF type: Binary EF.", CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (PIN code not presented, encryption required).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, Stored Value log file and a Stored Value operation was done"
                + " during the current secure session).",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Incorrect file type: the Current File is not an EF. Supersedes 6981h.",
            CardDataAccessException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect command data (S. Length incompatible with Lc, S. Length > RecSize,"
                + " S. Offset + S. Length > RecSize, S. Mask bigger than S. Data).",
            CardIllegalParameterException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found (record index is 0, or above NumRec).",
            CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final SearchCommandDataAdapter data;

  /**
   * Constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param data The search command input/output data.
   * @since 2.3.2
   */
  CmdCardSearchRecordMultiple(
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      SearchCommandDataAdapter data) {

    super(CardCommandRef.SEARCH_RECORD_MULTIPLE, 0, null, transactionContext, commandContext);

    this.data = data;

    int searchDataLength = data.getSearchData().length;

    byte p2 = (byte) (data.getSfi() * 8 + 7);

    byte[] dataIn = new byte[3 + (2 * searchDataLength)];
    if (data.isEnableRepeatedOffset()) {
      dataIn[0] = (byte) 0x80;
    }
    if (data.isFetchFirstMatchingResult()) {
      dataIn[0] |= 1;
    }
    dataIn[1] = (byte) data.getOffset();
    dataIn[2] = (byte) searchDataLength;

    System.arraycopy(data.getSearchData(), 0, dataIn, 3, searchDataLength);

    if (data.getMask() == null) {
      // CL-CMD-SEARCH.1
      Arrays.fill(dataIn, dataIn.length - searchDataLength, dataIn.length, (byte) 0xFF);
    } else {
      System.arraycopy(
          data.getMask(), 0, dataIn, dataIn.length - searchDataLength, data.getMask().length);
      if (data.getMask().length != searchDataLength) {
        // CL-CMD-SEARCH.1
        Arrays.fill(
            dataIn,
            dataIn.length - searchDataLength + data.getMask().length,
            dataIn.length,
            (byte) 0xFF);
      }
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                transactionContext.getCard().getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                (byte) data.getRecordNumber(),
                p2,
                dataIn,
                (byte) 0)));

    if (logger.isDebugEnabled()) {
      String extraInfo =
          String.format(
              "SFI:%02Xh, RECORD_NUMBER:%d, OFFSET:%d, REPEATED_OFFSET:%s, FETCH_FIRST_RESULT:%s, SEARCH_DATA:%sh,"
                  + " MASK:%sh",
              data.getSfi(),
              data.getRecordNumber(),
              data.getOffset(),
              data.isEnableRepeatedOffset(),
              data.isFetchFirstMatchingResult(),
              HexUtil.toHex(data.getSearchData()),
              HexUtil.toHex(data.getMask()));
      addSubName(extraInfo);
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
    return !getCommandContext().isSecureSessionOpen();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    if (!setApduResponseAndCheckStatusInBestEffortMode(apduResponse)) {
      return;
    }
    byte[] dataOut = apduResponse.getDataOut();
    int nbRecords = dataOut[0];
    for (int i = 1; i <= nbRecords; i++) {
      data.getMatchingRecordNumbers().add((int) dataOut[i]);
    }
    if (data.isFetchFirstMatchingResult() && nbRecords > 0) {
      getTransactionContext()
          .getCard()
          .setContent(
              data.getSfi(),
              data.getMatchingRecordNumbers().get(0),
              Arrays.copyOfRange(dataOut, nbRecords + 1, dataOut.length));
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
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  void setApduResponseAndCheckStatus(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);
    byte[] dataOut = apduResponse.getDataOut();
    int nbRecords = dataOut[0];
    for (int i = 1; i <= nbRecords; i++) {
      data.getMatchingRecordNumbers().add((int) dataOut[i]);
    }
    if (data.isFetchFirstMatchingResult() && nbRecords > 0) {
      getCalypsoCard()
          .setContent(
              data.getSfi(),
              data.getMatchingRecordNumbers().get(0),
              Arrays.copyOfRange(dataOut, nbRecords + 1, dataOut.length));
    }
  }
}
