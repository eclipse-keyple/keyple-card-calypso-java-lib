package org.eclipse.keyple.card.calypso;

import org.eclipse.keypop.calypso.card.transaction.SecureRegularModeTransactionManager;
import org.eclipse.keypop.card.ProxyReaderApi;

/**
 * Adapter of {@link SecureRegularModeTransactionManager}.
 * @since 3.0.0
 */
class SecureRegularModeTransactionManagerAdapter extends SecureSymmetricCryptoTransactionManagerAdapter<SecureRegularModeTransactionManager> implements SecureRegularModeTransactionManager {

  /**
   * Builds a new instance.
   * @param cardReader The card reader to be used.
   * @param card The selected card on which to operate the transaction.
   * @param symmetricCryptoSecuritySetting The symmetric crypto security setting to be used.
   * @since 3.0.0
   */
  SecureRegularModeTransactionManagerAdapter(ProxyReaderApi cardReader, CalypsoCardAdapter card, SymmetricCryptoSecuritySettingAdapter symmetricCryptoSecuritySetting) {
    super(cardReader, card, null);
  }
}
