/* **************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/
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

import org.eclipse.keypop.calypso.card.transaction.SecureExtendedModeTransactionManager;
import org.eclipse.keypop.card.ProxyReaderApi;

/**
 * Adapter of {@link SecureExtendedModeTransactionManager}.
 *
 * @since 3.0.0
 */
final class SecureExtendedModeTransactionManagerAdapter
    extends SecureSymmetricCryptoTransactionManagerAdapter<SecureExtendedModeTransactionManager>
    implements SecureExtendedModeTransactionManager {

  /**
   * Builds a new instance.
   *
   * @param cardReader The card reader to be used.
   * @param card The selected card on which to operate the transaction.
   * @param symmetricCryptoSecuritySetting The symmetric crypto security setting to be used.
   * @since 3.0.0
   */
  SecureExtendedModeTransactionManagerAdapter(
      ProxyReaderApi cardReader,
      CalypsoCardAdapter card,
      SymmetricCryptoSecuritySettingAdapter symmetricCryptoSecuritySetting) {
    super(cardReader, card, symmetricCryptoSecuritySetting);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SecureExtendedModeTransactionManager prepareEarlyMutualAuthentication() {
    try {
      if (!isExtendedMode) {
        throw new UnsupportedOperationException(MSG_MSS_COMMAND_NOT_SUPPORTED);
      }
      checkSecureSession();
      // Add a new command or update the last command if it is an MSS command.
      if (!commands.isEmpty()
          && commands.get(commands.size() - 1).getCommandRef()
              == CardCommandRef.MANAGE_SECURE_SESSION) {
        ((CommandManageSession) commands.get(commands.size() - 1))
            .setMutualAuthenticationRequested(true);
      } else {
        commands.add(
            new CommandManageSession(transactionContext, getCommandContext())
                .setMutualAuthenticationRequested(true)
                .setEncryptionRequested(isEncryptionActive));
      }
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SecureExtendedModeTransactionManager prepareActivateEncryption() {
    try {
      if (!isExtendedMode) {
        throw new UnsupportedOperationException(MSG_MSS_COMMAND_NOT_SUPPORTED);
      }
      checkSecureSession();
      if (isEncryptionActive) {
        throw new IllegalStateException(MSG_ENCRYPTION_ALREADY_ACTIVE);
      }
      // Add a new command or update the last command if it is an MSS command.
      if (!commands.isEmpty()
          && commands.get(commands.size() - 1).getCommandRef()
              == CardCommandRef.MANAGE_SECURE_SESSION) {
        ((CommandManageSession) commands.get(commands.size() - 1)).setEncryptionRequested(true);
      } else {
        commands.add(
            new CommandManageSession(transactionContext, getCommandContext())
                .setEncryptionRequested(true));
      }
      isEncryptionActive = true;
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  public SecureExtendedModeTransactionManager prepareDeactivateEncryption() {
    try {
      if (!isExtendedMode) {
        throw new UnsupportedOperationException(MSG_MSS_COMMAND_NOT_SUPPORTED);
      }
      checkSecureSession();
      if (!isEncryptionActive) {
        throw new IllegalStateException(MSG_ENCRYPTION_NOT_ACTIVE);
      }
      // Add a new command or update the last command if it is an MSS command.
      if (!commands.isEmpty()
          && commands.get(commands.size() - 1).getCommandRef()
              == CardCommandRef.MANAGE_SECURE_SESSION) {
        ((CommandManageSession) commands.get(commands.size() - 1)).setEncryptionRequested(false);
      } else {
        commands.add(
            new CommandManageSession(transactionContext, getCommandContext())
                .setEncryptionRequested(false));
      }
      isEncryptionActive = false;
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return this;
  }
}
