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

/**
 * Builds the Get data APDU commands for the CARD PUBLIC KEY tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because it would generate a
 * 6Cxx status and thus make calculation of the digest impossible.
 *
 * @since 3.1.0
 */
final class CommandGetDataCardPublicKey extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(
        0x6A88,
        new StatusProperties(
            "Data object not found (optional mode not available)", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported", CardDataAccessException.class));
    STATUS_TABLE = m;
  }

  /**
   * Constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @since 3.1.0
   */
  CommandGetDataCardPublicKey(
      TransactionContextDto transactionContext, CommandContextDto commandContext) {
    super(CardCommandRef.GET_DATA, null, transactionContext, commandContext);
    byte cardClass =
        transactionContext.getCard() != null
            ? transactionContext.getCard().getCardClass().getValue()
            : CalypsoCardClass.ISO.getValue();

    // APDU Case 2 - always outside secure session
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cardClass,
                getCommandRef().getInstructionByte(),
                CalypsoCardConstant.TAG_CARD_PUBLIC_KEY_MSB,
                CalypsoCardConstant.TAG_CARD_PUBLIC_KEY_LSB,
                null,
                (byte) 0x00)));
    addSubName("ECC_PUBLIC_KEY");
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
    getTransactionContext()
        .getCard()
        .setCardPublicKey(
            Arrays.copyOfRange(
                apduResponse.getDataOut(),
                CalypsoCardConstant.TAG_CARD_PUBLIC_KEY_HEADER_SIZE,
                apduResponse.getDataOut().length));
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
