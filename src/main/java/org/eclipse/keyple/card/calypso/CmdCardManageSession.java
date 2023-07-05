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

import static org.eclipse.keyple.card.calypso.DtoAdapters.ApduRequestAdapter;

import java.util.*;
import org.eclipse.keyple.card.calypso.DtoAdapters.CommandContextDto;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.calypso.card.transaction.InvalidCardMacException;
import org.eclipse.keypop.card.ApduResponseApi;

/**
 * Builds the Manage Secure Session APDU command.
 *
 * @since 2.3.1
 */
final class CmdCardManageSession extends CardCommand {

  private static final CardCommandRef commandRef = CardCommandRef.MANAGE_SECURE_SESSION;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CardIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied:\n"
                + "- No secure session running in Extended mode.\n"
                + "- Manage Secure Session not authorized during the running\n"
                + "session (as indicated by the Flags byte of Open Secure Session).",
            CardSecurityDataException.class));
    m.put(
        0x6988,
        new StatusProperties(
            "Incorrect terminal Session MAC (the secure session is aborted).",
            CardSecurityDataException.class));
    m.put(
        0x6D00,
        new StatusProperties(
            "Extended mode not supported, or AES keys not supported.",
            CardSecurityContextException.class));
    STATUS_TABLE = m;
  }

  private boolean isEncryptionRequested;
  private boolean isMutualAuthenticationRequested;
  private byte[] cardSessionMac;

  /**
   * Instantiates a new Manage Secure Session card command depending on the product type of the
   * card.
   *
   * @param calypsoCard The Calypso card.
   * @param activateEncryption True if the activation of the encryption is required.
   * @param terminalSessionMac The terminal session MAC when the card authentication is required.
   * @since 2.3.1
   * @deprecated
   */
  @Deprecated
  CmdCardManageSession(
      CalypsoCardAdapter calypsoCard, boolean activateEncryption, byte[] terminalSessionMac) {

    super(commandRef, terminalSessionMac != null ? 8 : 0, calypsoCard, null, null);

    byte p2;
    Byte le;

    if (terminalSessionMac != null) {
      // case 4: this command contains incoming and outgoing data. We define le = 0, the actual
      // length will be processed by the lower layers.
      p2 = activateEncryption ? (byte) 0x03 : (byte) 0x01;
      le = 0;
    } else {
      // case 1: this command contains no data. We define le = null.
      p2 = activateEncryption ? (byte) 0x02 : (byte) 0x00;
      le = null;
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCard.getCardClass().getValue(),
                commandRef.getInstructionByte(),
                (byte) 0x00,
                p2,
                terminalSessionMac,
                le)));
  }

  /**
   * Constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @since 2.3.2
   */
  CmdCardManageSession(
      DtoAdapters.TransactionContextDto transactionContext, CommandContextDto commandContext) {
    super(commandRef, 0, null, transactionContext, commandContext);
  }

  /**
   * @param isEncryptionRequested The flag value to set.
   * @return The current instance.
   * @since 2.3.2
   */
  CmdCardManageSession setEncryptionRequested(boolean isEncryptionRequested) {
    this.isEncryptionRequested = isEncryptionRequested;
    return this;
  }

  /**
   * @param isMutualAuthenticationRequested The flag value to set.
   * @return The current instance.
   * @since 2.3.2
   */
  CmdCardManageSession setMutualAuthenticationRequested(boolean isMutualAuthenticationRequested) {
    this.isMutualAuthenticationRequested = isMutualAuthenticationRequested;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void finalizeRequest() {
    byte p2;
    Byte le;
    byte[] terminalSessionMac;
    if (isMutualAuthenticationRequested) {
      // case 4: this command contains incoming and outgoing data. We define le = 0, the actual
      // length will be processed by the lower layers.
      setLe(8); // for auto check of response length
      p2 = isEncryptionRequested ? (byte) 0x03 : (byte) 0x01;
      try {
        terminalSessionMac =
            getTransactionContext()
                .getSymmetricCryptoTransactionManagerSpi()
                .generateTerminalSessionMac();
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      } catch (SymmetricCryptoIOException e) {
        throw (RuntimeException) e.getCause();
      }
      le = 0;
    } else {
      // case 1: this command contains no data. We define le = null.
      setLe(0);
      p2 = isEncryptionRequested ? (byte) 0x02 : (byte) 0x00;
      terminalSessionMac = null;
      le = null;
    }
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                getTransactionContext().getCard().getCardClass().getValue(),
                commandRef.getInstructionByte(),
                (byte) 0x00,
                p2,
                terminalSessionMac,
                le)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean isCryptoServiceRequiredToFinalizeRequest() {
    return isMutualAuthenticationRequested;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    if (isMutualAuthenticationRequested) {
      return false;
    }
    if (!isCryptoServiceSynchronized()) {
      updateCryptoServiceEncryptionStateIfNeeded();
      confirmCryptoServiceSuccessfullySynchronized();
    }
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    try {
      super.setApduResponseAndCheckStatus(apduResponse);
    } catch (CardSecurityDataException e) {
      if (apduResponse.getStatusWord() == 0x6985
          && !getTransactionContext().getCard().isExtendedModeSupported()) {
        throw new UnsupportedOperationException(
            "'Manage Secure Session' command not available for this context"
                + " (Card and/or SAM does not support extended mode)");
      }
      throw e;
    }
    cardSessionMac = getApduResponse().getDataOut();
    if (isMutualAuthenticationRequested) {
      try {
        if (!getTransactionContext()
            .getSymmetricCryptoTransactionManagerSpi()
            .isCardSessionMacValid(cardSessionMac)) {
          throw new InvalidCardMacException("Invalid card (authentication failed!)");
        }
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      } catch (SymmetricCryptoIOException e) {
        throw (RuntimeException) e.getCause();
      }
    }
    if (!isCryptoServiceSynchronized()) {
      updateCryptoServiceEncryptionStateIfNeeded();
    }
  }

  /** Updates the crypto service "encryption" state if needed. */
  private void updateCryptoServiceEncryptionStateIfNeeded() {
    try {
      if (!getCommandContext().isEncryptionActive() && isEncryptionRequested) {
        getTransactionContext().getSymmetricCryptoTransactionManagerSpi().activateEncryption();
      } else if (getCommandContext().isEncryptionActive() && !isEncryptionRequested) {
        getTransactionContext().getSymmetricCryptoTransactionManagerSpi().deactivateEncryption();
      }
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }
  }

  /**
   * {@inheritDoc}
   *
   * @return False
   * @since 2.3.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Checks the card response length; the admissible lengths are 0, 4 or 8 bytes.
   *
   * @since 2.3.1
   */
  @Override
  void setApduResponseAndCheckStatus(ApduResponseApi apduResponse) throws CardCommandException {
    try {
      super.setApduResponseAndCheckStatus(apduResponse);
    } catch (CardSecurityDataException e) {
      if (apduResponse.getStatusWord() == 0x6985 && !getCalypsoCard().isExtendedModeSupported()) {
        throw new UnsupportedOperationException(
            "'Manage Secure Session' command not available for this context"
                + " (Card and/or SAM does not support extended mode)");
      }
      throw e;
    }
    cardSessionMac = getApduResponse().getDataOut();
  }

  /**
   * Gets the low part of the session MAC.
   *
   * @return An empty or 8-byte array of bytes.
   * @since 2.3.1
   */
  byte[] getCardSessionMac() {
    return cardSessionMac;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
