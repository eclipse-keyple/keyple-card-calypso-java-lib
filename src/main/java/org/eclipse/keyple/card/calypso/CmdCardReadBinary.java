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
import org.eclipse.keypop.calypso.card.card.ElementaryFile;
import org.eclipse.keypop.card.ApduResponseApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the "Read Binary" APDU command.
 *
 * @since 2.1.0
 */
final class CmdCardReadBinary extends CardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardReadBinary.class);
  private static final String MSG_SFI_02_XH_OFFSET_D_LENGTH_D = "SFI:%02Xh, OFFSET:%d, LENGTH:%d";
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6981,
        new StatusProperties("Incorrect EF type: not a Binary EF.", CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (PIN code not presented, encryption required).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode).", CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Incorrect file type: the Current File is not an EF. Supersedes 6981h.",
            CardDataAccessException.class));
    m.put(0x6A82, new StatusProperties("File not found", CardDataAccessException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Offset not in the file (offset overflow).", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 value not supported.", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final byte sfi;
  private final int offset;
  private transient boolean isPreOpenMode; // NOSONAR
  private transient byte[] anticipatedDataOut; // NOSONAR

  /**
   * Constructor.
   *
   * @param calypsoCard The Calypso card.
   * @param sfi The sfi to select.
   * @param offset The offset.
   * @param length The number of bytes to read.
   * @since 2.1.0
   * @deprecated
   */
  @Deprecated
  CmdCardReadBinary(CalypsoCardAdapter calypsoCard, byte sfi, int offset, int length) {

    super(CardCommandRef.READ_BINARY, length, calypsoCard, null, null);

    this.sfi = sfi;
    this.offset = offset;

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
                null,
                (byte) length)));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format(MSG_SFI_02_XH_OFFSET_D_LENGTH_D, sfi, offset, length);
      addSubName(extraInfo);
    }
  }

  /**
   * Constructor (to be used for card selection only).
   *
   * @param sfi The sfi to select.
   * @param offset The offset.
   * @param length The number of bytes to read.
   * @since 2.3.3
   */
  CmdCardReadBinary(byte sfi, int offset, int length) {

    super(CardCommandRef.READ_BINARY, length, null, null, null);

    this.sfi = sfi;
    this.offset = offset;

    byte msb = (byte) (offset >> Byte.SIZE);
    byte lsb = (byte) (offset & 0xFF);

    // 100xxxxx : 'xxxxx' = SFI of the EF to select.
    // 0xxxxxxx : 'xxxxxxx' = MSB of the offset of the first byte.
    byte p1 = msb > 0 ? msb : (byte) (0x80 + sfi);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                CalypsoCardClass.ISO.getValue(),
                getCommandRef().getInstructionByte(),
                p1,
                lsb,
                null,
                (byte) length)));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format(MSG_SFI_02_XH_OFFSET_D_LENGTH_D, sfi, offset, length);
      addSubName(extraInfo);
    }
  }

  /**
   * Constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param sfi The sfi to select.
   * @param offset The offset.
   * @param length The number of bytes to read.
   * @since 2.3.2
   */
  CmdCardReadBinary(
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      byte sfi,
      int offset,
      int length) {

    super(CardCommandRef.READ_BINARY, length, null, transactionContext, commandContext);
    isPreOpenMode = transactionContext.getCard().getPreOpenWriteAccessLevel() != null;
    this.sfi = sfi;
    this.offset = offset;

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
                null,
                (byte) length)));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format(MSG_SFI_02_XH_OFFSET_D_LENGTH_D, sfi, offset, length);
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
    getCalypsoCard().setContent(sfi, 1, apduResponse.getDataOut(), offset);
  }

  /**
   * {@inheritDoc}
   *
   * @return false
   * @since 2.1.0
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
    return getCommandContext().isEncryptionActive();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    if (!getCommandContext().isSecureSessionOpen()) {
      return true; // Nothing to synchronize
    }
    if (getCommandContext().isEncryptionActive()) {
      return false;
    }
    if (!isPreOpenMode) {
      return false;
    }
    // Pre-open mode without encryption in secure session
    if (!isCryptoServiceSynchronized()) {
      byte[] anticipatedApduResponse = buildAnticipatedResponse();
      if (anticipatedApduResponse == null) {
        logger.warn(
            "Unable to determine the anticipated APDU response for the command '{}' (SFI {}h, offset {}, length {})"
                + " because the record or some records have not been read beforehand.",
            getName(),
            HexUtil.toHex(sfi),
            offset,
            getLe());
        return false;
      }
      anticipatedDataOut =
          Arrays.copyOf(anticipatedApduResponse, anticipatedApduResponse.length - 2);
      updateTerminalSessionMacIfNeeded(anticipatedApduResponse);
    }
    return true;
  }

  /**
   * Builds the anticipated APDU response with the SW.
   *
   * @return Null if the record has not been read beforehand.
   */
  private byte[] buildAnticipatedResponse() {
    ElementaryFile ef = getTransactionContext().getCard().getFileBySfi(sfi);
    if (ef == null) {
      return null; // NOSONAR
    }
    try {
      byte[] content = ef.getData().getContent(1, offset, getLe());
      byte[] apdu = new byte[getLe() + 2];
      System.arraycopy(content, 0, apdu, 0, getLe()); // Record content
      apdu[getLe()] = (byte) 0x90; // SW 9000
      return apdu;
    } catch (IndexOutOfBoundsException e) {
      // NOP
    }
    return null; // NOSONAR
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
    getTransactionContext().getCard().setContent(sfi, 1, apduResponse.getDataOut(), offset);
    if (!isCryptoServiceSynchronized()) {
      updateTerminalSessionMacIfNeeded();
    } else if (getCommandContext().isSecureSessionOpen()
        && isPreOpenMode
        && !Arrays.equals(apduResponse.getDataOut(), anticipatedDataOut)) {
      throw new CardSecurityContextException(
          "Data out does not match the anticipated data out", CardCommandRef.READ_BINARY);
    }
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
