package org.eclipse.keyple.card.calypso;

import org.eclipse.keypop.calypso.card.transaction.SecureExtendedModeTransactionManager;
import org.eclipse.keypop.card.ProxyReaderApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link SecureExtendedModeTransactionManager}.
 * @since 3.0.0
 */
class SecureExtendedModeTransactionManagerAdapter extends SecureSymmetricCryptoTransactionManagerAdapter<SecureExtendedModeTransactionManager> implements SecureExtendedModeTransactionManager {

  private static final Logger logger = LoggerFactory.getLogger(SecureExtendedModeTransactionManagerAdapter.class);

  /**
   * Builds a new instance.
   * @param cardReader The card reader to be used.
   * @param card The selected card on which to operate the transaction.
   * @param symmetricCryptoSecuritySetting The symmetric crypto security setting to be used.
   * @since 3.0.0
   */
  SecureExtendedModeTransactionManagerAdapter(ProxyReaderApi cardReader, CalypsoCardAdapter card, SymmetricCryptoSecuritySettingAdapter symmetricCryptoSecuritySetting) {
    super(cardReader, card, null);
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
      if (!cardCommands.isEmpty()
              && cardCommands.get(cardCommands.size() - 1).getCommandRef()
              == CardCommandRef.MANAGE_SECURE_SESSION) {
        ((CmdCardManageSession) cardCommands.get(cardCommands.size() - 1))
                .setMutualAuthenticationRequested(true);
      } else {
        cardCommands.add(
                new CmdCardManageSession(transactionContext, getCommandContext())
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
      if (!cardCommands.isEmpty()
              && cardCommands.get(cardCommands.size() - 1).getCommandRef()
              == CardCommandRef.MANAGE_SECURE_SESSION) {
        ((CmdCardManageSession) cardCommands.get(cardCommands.size() - 1))
                .setEncryptionRequested(true);
      } else {
        cardCommands.add(
                new CmdCardManageSession(transactionContext, getCommandContext())
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
      if (!cardCommands.isEmpty()
              && cardCommands.get(cardCommands.size() - 1).getCommandRef()
              == CardCommandRef.MANAGE_SECURE_SESSION) {
        ((CmdCardManageSession) cardCommands.get(cardCommands.size() - 1))
                .setEncryptionRequested(false);
      } else {
        cardCommands.add(
                new CmdCardManageSession(transactionContext, getCommandContext())
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
