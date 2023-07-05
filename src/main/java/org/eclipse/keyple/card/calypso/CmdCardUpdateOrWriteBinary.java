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

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.card.ApduResponseApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the "Update/Write Binary" APDU command.
 *
 * @since 2.1.0
 */
final class CmdCardUpdateOrWriteBinary extends CardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardUpdateOrWriteBinary.class);
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session", CardSessionBufferOverflowException.class));
    m.put(
        0x6700,
        new StatusProperties(
            "Lc value not supported, or Offset+Lc > file size", CardDataAccessException.class));
    m.put(
        0x6981,
        new StatusProperties("Incorrect EF type: not a Binary EF", CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (no secure session, incorrect key, encryption required, PKI mode and not Always access mode)",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, DF is invalidated, etc..)",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Incorrect file type: the Current File is not an EF. Supersedes 6981h",
            CardDataAccessException.class));
    m.put(0x6A82, new StatusProperties("File not found", CardDataAccessException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Offset not in the file (offset overflow)", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 value not supported", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final byte sfi;
  private final int offset;
  private final byte[] data;

  /**
   * Constructor.
   *
   * @param isUpdateCommand True if it is an "Update Binary" command, false if it is a "Write
   *     Binary" command.
   * @param calypsoCard The Calypso card.
   * @param sfi the sfi to select.
   * @param offset the offset.
   * @param data the data to write.
   * @since 2.1.0
   * @deprecated
   */
  @Deprecated
  CmdCardUpdateOrWriteBinary(
      boolean isUpdateCommand, CalypsoCardAdapter calypsoCard, byte sfi, int offset, byte[] data) {

    super(
        isUpdateCommand ? CardCommandRef.UPDATE_BINARY : CardCommandRef.WRITE_BINARY,
        0,
        calypsoCard,
        null,
        null);

    this.sfi = sfi;
    this.offset = offset;
    this.data = data;

    byte msb = (byte) (offset >> Byte.SIZE);
    byte lsb = (byte) (offset & 0xFF);

    // 100xxxxx : 'xxxxx' = SFI of the EF to select.
    // 0xxxxxxx : 'xxxxxxx' = MSB of the offset of the first byte.
    byte p1 = msb > 0 ? msb : (byte) (0x80 + sfi);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCard.getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                p1,
                lsb,
                data,
                null)));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format("SFI:%02Xh, OFFSET:%d", sfi, offset);
      addSubName(extraInfo);
    }
  }

  /**
   * Constructor.
   *
   * @param isUpdateCommand True if it is an "Update Binary" command, false if it is a "Write
   *     Binary" command.
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param sfi the sfi to select.
   * @param offset the offset.
   * @param data the data to write.
   * @since 2.3.2
   */
  CmdCardUpdateOrWriteBinary(
      boolean isUpdateCommand,
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      byte sfi,
      int offset,
      byte[] data) {

    super(
        isUpdateCommand ? CardCommandRef.UPDATE_BINARY : CardCommandRef.WRITE_BINARY,
        0,
        null,
        transactionContext,
        commandContext);

    this.sfi = sfi;
    this.offset = offset;
    this.data = data;

    byte msb = (byte) (offset >> Byte.SIZE);
    byte lsb = (byte) (offset & 0xFF);

    // 100xxxxx : 'xxxxx' = SFI of the EF to select.
    // 0xxxxxxx : 'xxxxxxx' = MSB of the offset of the first byte.
    byte p1 = msb > 0 ? msb : (byte) (0x80 + sfi);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                transactionContext.getCard().getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                p1,
                lsb,
                data,
                null)));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format("SFI:%02Xh, OFFSET:%d", sfi, offset);
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
    if (getCommandRef() == CardCommandRef.UPDATE_BINARY) {
      getCalypsoCard().setContent(sfi, 1, data, offset);
    } else {
      getCalypsoCard().fillContent(sfi, 1, data, offset);
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command modified the contents of the card and therefore uses the session buffer.
   *
   * @return True
   * @since 2.1.0
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
    updateTerminalSessionMacIfNeeded(APDU_RESPONSE_9000);
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
    if (getCommandRef() == CardCommandRef.UPDATE_BINARY) {
      getTransactionContext().getCard().setContent(sfi, 1, data, offset);
    } else {
      getTransactionContext().getCard().fillContent(sfi, 1, data, offset);
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
