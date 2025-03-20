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

import static org.eclipse.keyple.card.calypso.CalypsoCardConstant.CARD_PUBLIC_KEY_SIZE;
import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.calypso.card.PutDataTag;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Put Data command.
 *
 * @since 3.1.0
 */
final class CommandPutData extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session", CardSessionBufferOverflowException.class));
    m.put(0x6700, new StatusProperties("Lc value not supported", CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled", CardSecurityContextException.class));
    m.put(0x6985, new StatusProperties("Access forbidden", CardAccessForbiddenException.class));
    m.put(
        0x6A80,
        new StatusProperties("Lc not compatible with P1P2", CardIllegalParameterException.class));
    m.put(
        0x6A87,
        new StatusProperties("Incorrect incoming data", CardIllegalParameterException.class));
    m.put(0x6A88, new StatusProperties("Data object not found", CardDataAccessException.class));
    m.put(0x6A8A, new StatusProperties("Incorrect AID", CardIllegalParameterException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1, P2", CardIllegalParameterException.class));
    m.put(
        0x6D00,
        new StatusProperties(
            "Command Put Data not supported", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final PutDataTag tag;
  private final byte[] data;
  private final boolean isFirstPart;

  /**
   * Constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @since 3.1.0
   */
  CommandPutData(
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      PutDataTag tag,
      boolean isFirstPart,
      byte[] data) {
    super(CardCommandRef.PUT_DATA, 0, transactionContext, commandContext);
    this.tag = tag;
    this.data = data;
    this.isFirstPart = isFirstPart;
    byte tagMsb;
    byte tagLsb;
    ByteBuffer dataIn;
    switch (tag) {
      case CARD_KEY_PAIR:
        tagMsb = CalypsoCardConstant.TAG_CARD_KEY_PAIR_MSB;
        tagLsb = CalypsoCardConstant.TAG_CARD_KEY_PAIR_LSB;
        dataIn = ByteBuffer.wrap(data);
        break;
      case CARD_CERTIFICATE:
        tagMsb = CalypsoCardConstant.TAG_CARD_CERTIFICATE_MSB;
        tagLsb =
            isFirstPart
                ? CalypsoCardConstant.TAG_CARD_CERTIFICATE_LSB
                : CalypsoCardConstant.TAG_CARD_CERTIFICATE_LSB + 1;
        if (isFirstPart) {
          dataIn =
              ByteBuffer.allocate(data.length + CalypsoCardConstant.TAG_CERTIFICATE_HEADER_SIZE);
          dataIn.put(CalypsoCardConstant.TAG_CARD_CERTIFICATE_HEADER);
          dataIn.put(data);
        } else {
          dataIn = ByteBuffer.wrap(data);
        }
        break;
      case CA_CERTIFICATE:
        tagMsb = CalypsoCardConstant.TAG_CA_CERTIFICATE_MSB;
        tagLsb =
            isFirstPart
                ? CalypsoCardConstant.TAG_CA_CERTIFICATE_LSB
                : CalypsoCardConstant.TAG_CA_CERTIFICATE_LSB + 1;
        if (isFirstPart) {
          dataIn =
              ByteBuffer.allocate(data.length + CalypsoCardConstant.TAG_CERTIFICATE_HEADER_SIZE);
          dataIn.put(CalypsoCardConstant.TAG_CA_CERTIFICATE_HEADER);
          dataIn.put(data);
        } else {
          dataIn = ByteBuffer.wrap(data);
        }
        break;
      default:
        throw new UnsupportedOperationException("Unsupported tag: " + tag);
    }

    // APDU Case 3 - always outside secure session
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                getTransactionContext().getCard().getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                tagMsb,
                tagLsb,
                dataIn.array(),
                null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  void finalizeRequest() {
    // NOP
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  boolean isCryptoServiceRequiredToFinalizeRequest() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);
    if (tag == PutDataTag.CARD_KEY_PAIR) {
      getTransactionContext().getCard().setCardPublicKey(Arrays.copyOf(data, CARD_PUBLIC_KEY_SIZE));
    } else if (tag == PutDataTag.CARD_CERTIFICATE) {
      getTransactionContext().getCard().addCardCertificateBytes(data, isFirstPart);
    } else if (tag == PutDataTag.CA_CERTIFICATE) {
      getTransactionContext().getCard().addCaCertificateBytes(data, isFirstPart);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
