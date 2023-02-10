/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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
import org.calypsonet.terminal.calypso.card.SvDebitLogRecord;
import org.calypsonet.terminal.calypso.card.SvLoadLogRecord;
import org.calypsonet.terminal.calypso.transaction.SvOperation;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the SV Get command.
 *
 * @since 2.0.1
 */
final class CmdCardSvGet extends CardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardSvGet.class);

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled.", CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied (a store value operation was already done in the current session).",
            CardAccessForbiddenException.class));
    m.put(0x6A81, new StatusProperties("Incorrect P1 or P2.", CardIllegalParameterException.class));
    m.put(
        0x6A86,
        new StatusProperties("Le inconsistent with P2.", CardIllegalParameterException.class));
    m.put(
        0x6D00,
        new StatusProperties("SV function not present.", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final byte[] header;

  /**
   * Instantiates a new CmdCardSvGet.
   *
   * @param calypsoCard The Calypso card.
   * @param svOperation the desired SV operation.
   * @param useExtendedMode True if the extended mode must be used.
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.0.1
   * @deprecated
   */
  @Deprecated
  CmdCardSvGet(CalypsoCardAdapter calypsoCard, SvOperation svOperation, boolean useExtendedMode) {

    super(CardCommandRef.SV_GET, 0, calypsoCard, null);

    byte cla =
        calypsoCard.getCardClass() == CalypsoCardClass.LEGACY
            ? CalypsoCardClass.LEGACY_STORED_VALUE.getValue()
            : CalypsoCardClass.ISO.getValue();

    byte p1 = useExtendedMode ? (byte) 0x01 : (byte) 0x00;
    byte p2 = svOperation == SvOperation.RELOAD ? (byte) 0x07 : (byte) 0x09;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, null, (byte) 0x00)));

    if (logger.isDebugEnabled()) {
      addSubName(String.format("OPERATION:%s", svOperation.toString()));
    }

    header = new byte[4];
    header[0] = getCommandRef().getInstructionByte();
    header[1] = p1;
    header[2] = p2;
    header[3] = (byte) 0x00;
  }

  /**
   * Instantiates a new CmdCardSvGet.
   *
   * @param context The context.
   * @param svOperation the desired SV operation.
   * @param useExtendedMode True if the extended mode must be used.
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.3.2
   */
  CmdCardSvGet(CommandContextDto context, SvOperation svOperation, boolean useExtendedMode) {

    super(CardCommandRef.SV_GET, 0, null, context);

    byte cla =
        context.getCard().getCardClass() == CalypsoCardClass.LEGACY
            ? CalypsoCardClass.LEGACY_STORED_VALUE.getValue()
            : CalypsoCardClass.ISO.getValue();

    byte p1 = useExtendedMode ? (byte) 0x01 : (byte) 0x00;
    byte p2 = svOperation == SvOperation.RELOAD ? (byte) 0x07 : (byte) 0x09;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, null, (byte) 0x00)));

    if (logger.isDebugEnabled()) {
      addSubName(String.format("OPERATION:%s", svOperation.toString()));
    }

    header = new byte[4];
    header[0] = getCommandRef().getInstructionByte();
    header[1] = p1;
    header[2] = p2;
    header[3] = (byte) 0x00;
  }

  /**
   * {@inheritDoc}
   *
   * @return False
   * @since 2.0.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return false;
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
    return getContext().isEncryptionActive();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    return false;
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
    byte[] cardResponse = apduResponse.getDataOut();
    byte currentKvc;
    int transactionNumber;
    int balance;
    SvLoadLogRecord loadLog;
    SvDebitLogRecord debitLog;
    switch (cardResponse.length) {
      case 0x21: /* Compatibility mode, Reload */
      case 0x1E: /* Compatibility mode, Debit or Undebit */
        currentKvc = cardResponse[0];
        transactionNumber = ByteArrayUtil.extractInt(cardResponse, 1, 2, false);
        balance = ByteArrayUtil.extractInt(cardResponse, 8, 3, true);
        if (cardResponse.length == 0x21) {
          /* Reload */
          loadLog = new SvLoadLogRecordAdapter(cardResponse, 11);
          debitLog = null;
        } else {
          /* Debit */
          loadLog = null;
          debitLog = new SvDebitLogRecordAdapter(cardResponse, 11);
        }
        break;
      case 0x3D: /* Revision 3.2 mode */
        currentKvc = cardResponse[8];
        transactionNumber = ByteArrayUtil.extractInt(cardResponse, 9, 2, false);
        balance = ByteArrayUtil.extractInt(cardResponse, 17, 3, true);
        loadLog = new SvLoadLogRecordAdapter(cardResponse, 20);
        debitLog = new SvDebitLogRecordAdapter(cardResponse, 42);
        break;
      default:
        throw new IllegalStateException("Incorrect data length in response to SVGet");
    }
    getContext()
        .getCard()
        .setSvData(
            currentKvc,
            header,
            apduResponse.getApdu(),
            balance,
            transactionNumber,
            loadLog,
            debitLog);
    updateTerminalSessionMacIfNeeded();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  void setApduResponseAndCheckStatus(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);
    byte[] cardResponse = apduResponse.getDataOut();
    byte currentKvc;
    int transactionNumber;
    int balance;
    SvLoadLogRecord loadLog;
    SvDebitLogRecord debitLog;
    switch (cardResponse.length) {
      case 0x21: /* Compatibility mode, Reload */
      case 0x1E: /* Compatibility mode, Debit or Undebit */
        currentKvc = cardResponse[0];
        transactionNumber = ByteArrayUtil.extractInt(cardResponse, 1, 2, false);
        balance = ByteArrayUtil.extractInt(cardResponse, 8, 3, true);
        if (cardResponse.length == 0x21) {
          /* Reload */
          loadLog = new SvLoadLogRecordAdapter(cardResponse, 11);
          debitLog = null;
        } else {
          /* Debit */
          loadLog = null;
          debitLog = new SvDebitLogRecordAdapter(cardResponse, 11);
        }
        break;
      case 0x3D: /* Revision 3.2 mode */
        currentKvc = cardResponse[8];
        transactionNumber = ByteArrayUtil.extractInt(cardResponse, 9, 2, false);
        balance = ByteArrayUtil.extractInt(cardResponse, 17, 3, true);
        loadLog = new SvLoadLogRecordAdapter(cardResponse, 20);
        debitLog = new SvDebitLogRecordAdapter(cardResponse, 42);
        break;
      default:
        throw new IllegalStateException("Incorrect data length in response to SVGet");
    }
    getCalypsoCard()
        .setSvData(
            currentKvc,
            header,
            apduResponse.getApdu(),
            balance,
            transactionNumber,
            loadLog,
            debitLog);
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
