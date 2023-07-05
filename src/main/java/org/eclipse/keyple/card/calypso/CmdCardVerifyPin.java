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
import org.eclipse.keypop.card.ApduResponseApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the "Verify PIN" command.
 *
 * @since 2.0.1
 */
final class CmdCardVerifyPin extends CardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardVerifyPin.class);

  private static final CardCommandRef commandRef = CardCommandRef.VERIFY_PIN;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc value not supported (only 00h, 04h or 08h are supported).",
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
    m.put(
        0x63C1,
        new StatusProperties("Incorrect PIN (1 attempt remaining).", CardPinException.class));
    m.put(
        0x63C2,
        new StatusProperties("Incorrect PIN (2 attempt remaining).", CardPinException.class));
    m.put(
        0x6983,
        new StatusProperties("Presentation rejected (PIN is blocked).", CardPinException.class));
    m.put(
        0x6D00,
        new StatusProperties("PIN function not present.", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private byte[] pin;
  private final boolean isReadCounterMode;
  private final boolean isPinEncryptedMode;
  private final byte cipheringKif;
  private final byte cipheringKvc;

  /**
   * Verify the PIN
   *
   * @param calypsoCard The Calypso card.
   * @param encryptPinTransmission true if the PIN transmission has to be encrypted.
   * @param pin the PIN data. The PIN is always 4-byte long here, even in the case of an encrypted
   *     transmission (@see setCipheredPinData).
   * @since 2.0.1
   * @deprecated
   */
  @Deprecated
  CmdCardVerifyPin(CalypsoCardAdapter calypsoCard, boolean encryptPinTransmission, byte[] pin) {
    super(commandRef, 0, calypsoCard, null, null);
    this.isReadCounterMode = false;
    this.pin = pin;
    this.isPinEncryptedMode = false;
    this.cipheringKif = 0;
    this.cipheringKvc = 0;
    if (pin == null
        || (!encryptPinTransmission && pin.length != 4)
        || (encryptPinTransmission && pin.length != 8)) {
      throw new IllegalArgumentException("The PIN must be 4 bytes long");
    }
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCard.getCardClass().getValue(),
                commandRef.getInstructionByte(),
                (byte) 0x00,
                (byte) 0x00,
                pin,
                null)));
    if (logger.isDebugEnabled()) {
      addSubName(encryptPinTransmission ? "ENCRYPTED" : "PLAIN");
    }
  }

  /**
   * Verify the PIN in encrypted mode.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param pin the PIN data. The PIN is always 4-byte long here, even in the case of an encrypted
   *     transmission (@see setCipheredPinData).
   * @param cipheringKif The ciphering KIF.
   * @param cipheringKvc The ciphering KVC.
   * @since 2.3.2
   */
  CmdCardVerifyPin(
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      byte[] pin,
      byte cipheringKif,
      byte cipheringKvc) {
    super(commandRef, 0, null, transactionContext, commandContext);
    this.isReadCounterMode = false;
    this.pin = pin;
    this.isPinEncryptedMode = true;
    this.cipheringKif = cipheringKif;
    this.cipheringKvc = cipheringKvc;
  }

  /**
   * Verify the PIN in plain mode.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param pin the PIN data. The PIN is always 4-byte long here, even in the case of an encrypted
   *     transmission (@see setCipheredPinData).
   * @since 2.3.2
   */
  CmdCardVerifyPin(
      TransactionContextDto transactionContext, CommandContextDto commandContext, byte[] pin) {
    super(commandRef, 0, null, transactionContext, commandContext);
    this.isReadCounterMode = false;
    this.pin = pin;
    this.isPinEncryptedMode = false;
    this.cipheringKif = 0;
    this.cipheringKvc = 0;
  }

  /**
   * Alternate command dedicated to the reading of the wrong presentation counter
   *
   * @param calypsoCard The Calypso card.
   * @since 2.0.1
   * @deprecated
   */
  @Deprecated
  CmdCardVerifyPin(CalypsoCardAdapter calypsoCard) {
    super(commandRef, 0, calypsoCard, null, null);
    this.isReadCounterMode = true;
    this.pin = null;
    this.isPinEncryptedMode = false;
    this.cipheringKif = 0;
    this.cipheringKvc = 0;
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCard.getCardClass().getValue(),
                commandRef.getInstructionByte(),
                (byte) 0x00,
                (byte) 0x00,
                null,
                null)));
    if (logger.isDebugEnabled()) {
      addSubName("Read presentation counter");
    }
  }

  /**
   * Alternate command dedicated to the reading of the wrong presentation counter
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @since 2.3.2
   */
  CmdCardVerifyPin(TransactionContextDto transactionContext, CommandContextDto commandContext) {
    super(commandRef, 0, null, transactionContext, commandContext);
    this.isReadCounterMode = true;
    this.pin = null;
    this.isPinEncryptedMode = false;
    this.cipheringKif = 0;
    this.cipheringKvc = 0;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  void setApduResponseAndCheckStatus(ApduResponseApi apduResponse) throws CardCommandException {
    try {
      super.setApduResponseAndCheckStatus(apduResponse);
      getCalypsoCard().setPinAttemptRemaining(3);
    } catch (CardPinException e) {
      switch (apduResponse.getStatusWord()) {
        case 0x63C2:
          getCalypsoCard().setPinAttemptRemaining(2);
          break;
        case 0x63C1:
          getCalypsoCard().setPinAttemptRemaining(1);
          break;
        case 0x6983:
          getCalypsoCard().setPinAttemptRemaining(0);
          break;
        default: // NOP
      }
      // Forward the exception if the operation do not target the reading of the attempt counter.
      // Catch it silently otherwise
      if (!isReadCounterMode) {
        throw e;
      }
    }
  }

  /**
   * {@inheritDoc}
   *
   * @return false
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
    if (isPinEncryptedMode) {
      try {
        pin =
            getTransactionContext()
                .getSymmetricCryptoTransactionManagerSpi()
                .cipherPinForPresentation(
                    getTransactionContext().getCard().getChallenge(),
                    pin,
                    cipheringKif,
                    cipheringKvc);
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      } catch (SymmetricCryptoIOException e) {
        throw (RuntimeException) e.getCause();
      }
    }
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                getTransactionContext().getCard().getCardClass().getValue(),
                commandRef.getInstructionByte(),
                (byte) 0x00, // CL-PIN-PP1P2.1
                (byte) 0x00,
                pin,
                null)));
    if (logger.isDebugEnabled()) {
      addSubName(
          isReadCounterMode
              ? "Read presentation counter"
              : isPinEncryptedMode ? "ENCRYPTED" : "PLAIN");
    }
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean isCryptoServiceRequiredToFinalizeRequest() {
    return isPinEncryptedMode || getCommandContext().isEncryptionActive();
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
    try {
      super.setApduResponseAndCheckStatus(apduResponse);
      getTransactionContext().getCard().setPinAttemptRemaining(3);
    } catch (CardPinException e) {
      switch (apduResponse.getStatusWord()) {
        case 0x63C2:
          getTransactionContext().getCard().setPinAttemptRemaining(2);
          break;
        case 0x63C1:
          getTransactionContext().getCard().setPinAttemptRemaining(1);
          break;
        case 0x6983:
          getTransactionContext().getCard().setPinAttemptRemaining(0);
          break;
        default: // NOP
      }
      // Forward the exception if the operation do not target the reading of the attempt counter.
      // Catch it silently otherwise
      if (!isReadCounterMode) {
        throw e;
      }
    }
    updateTerminalSessionMacIfNeeded();
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
