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
import org.eclipse.keypop.card.ApduResponseApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the "Read Record Multiple" APDU command.
 *
 * @since 2.1.0
 */
final class CmdCardReadRecordMultiple extends CardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardReadRecordMultiple.class);
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CardIllegalParameterException.class));
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
            "Incorrect command data (incorrect Tag, incorrect Length, R. Length > RecSize,"
                + " R. Offset + R. Length > RecSize, R. Length = 0).",
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
    m.put(
        0x6200,
        new StatusProperties(
            "Successful execution, partial read only: issue another Read Record Multiple from record"
                + " (P1 + (Size of returned data) / (R. Length)) to continue reading."));
    STATUS_TABLE = m;
  }

  private final byte sfi;
  private final byte recordNumber;
  private final byte offset;
  private final byte length;

  /**
   * Constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param sfi The SFI.
   * @param recordNumber The number of the first record to read.
   * @param offset The offset from which to read in each record.
   * @param length The number of bytes to read in each record.
   * @since 2.3.2
   */
  CmdCardReadRecordMultiple(
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      byte sfi,
      byte recordNumber,
      byte offset,
      byte length) {

    super(CardCommandRef.READ_RECORD_MULTIPLE, 0, transactionContext, commandContext);

    this.sfi = sfi;
    this.recordNumber = recordNumber;
    this.offset = offset;
    this.length = length;

    byte p2 = (byte) (sfi * 8 + 5);
    byte[] dataIn = {0x54, 0x02, offset, length};

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                transactionContext.getCard().getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                recordNumber,
                p2,
                dataIn,
                (byte) 0)));

    if (logger.isDebugEnabled()) {
      String extraInfo =
          String.format(
              "SFI:%02Xh, RECORD_NUMBER:%d, OFFSET:%d, LENGTH:%d",
              sfi, recordNumber, offset, length);
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
    int nbRecords = dataOut.length / length;
    for (int i = 0; i < nbRecords; i++) {
      getTransactionContext()
          .getCard()
          .setContent(
              sfi,
              recordNumber + i,
              Arrays.copyOfRange(dataOut, i * length, (i + 1) * length),
              offset);
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
}
