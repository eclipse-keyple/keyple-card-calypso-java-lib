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
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Generate Asymmetric Key Pair command.
 *
 * @since 3.1.0
 */
final class CommandGenerateAsymmetricKeyPair extends Command {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;
  private static final String SECP256R1_OID = "06082A8648CE3D030107";

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Lc value not supported", CardDataAccessException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Conditions of use not satisfied: a secure session is running or a card key pair already available",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Incorrect file type: the current DF is not an autonomous PKI application",
            CardDataAccessException.class));
    m.put(
        0x6A80,
        new StatusProperties("Incorrect incoming data", CardIllegalParameterException.class));
    m.put(
        0x6D00,
        new StatusProperties("PKI mode not available", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * Constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @since 3.1.0
   */
  CommandGenerateAsymmetricKeyPair(
      TransactionContextDto transactionContext, CommandContextDto commandContext) {
    super(CardCommandRef.GENERATE_ASYMMETRIC_KEY_PAIR, 0, transactionContext, commandContext);
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                getTransactionContext().getCard().getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                (byte) 0x00,
                (byte) 0x00,
                HexUtil.toByteArray(SECP256R1_OID),
                ISO7816_LE_ABSENT)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  void finalizeRequest() {
    /* nothing to do */
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
    return false; // Need to synchronize the card image
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);
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
