/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoIOException;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Change key APDU command.
 *
 * @since 2.1.0
 */
final class CmdCardChangeKey extends CardCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc value not supported (not 04h, 10h, 18h, 20h).",
            CardIllegalParameterException.class));
    m.put(0x6900, new StatusProperties("Transaction Counter is 0.", CardTerminatedException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (Get Challenge not done: challenge unavailable).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (a session is open or DF is invalidated).",
            CardAccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("Incorrect Cryptogram.", CardSecurityDataException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Decrypted message incorrect (key algorithm not supported, incorrect padding, etc.).",
            CardSecurityDataException.class));
    m.put(
        0x6A87,
        new StatusProperties("Lc not compatible with P2.", CardIllegalParameterException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1, P2.", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final byte keyIndex;
  private final byte newKif;
  private final byte newKvc;
  private final byte issuerKif;
  private final byte issuerKvc;

  /**
   * Constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param keyIndex The key index.
   * @param newKif The new KIF.
   * @param newKvc The new KVC.
   * @param issuerKif The issuer KIF.
   * @param issuerKvc The issuer KVC.
   * @since 2.3.2
   */
  CmdCardChangeKey(
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      byte keyIndex,
      byte newKif,
      byte newKvc,
      byte issuerKif,
      byte issuerKvc) {
    super(CardCommandRef.CHANGE_KEY, 0, null, transactionContext, commandContext);
    this.keyIndex = keyIndex;
    this.newKif = newKif;
    this.newKvc = newKvc;
    this.issuerKif = issuerKif;
    this.issuerKvc = issuerKvc;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void finalizeRequest() {
    byte[] cipheredKey;
    try {
      cipheredKey =
          getTransactionContext()
              .getSymmetricCryptoTransactionManagerSpi()
              .generateCipheredCardKey(
                  getTransactionContext().getCard().getChallenge(),
                  issuerKif,
                  issuerKvc,
                  newKif,
                  newKvc);
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                getTransactionContext().getCard().getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                (byte) 0x00,
                keyIndex,
                cipheredKey,
                null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean isCryptoServiceRequiredToFinalizeRequest() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);
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
