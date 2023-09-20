package org.eclipse.keyple.card.calypso;

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;
import org.eclipse.keypop.calypso.card.transaction.*;
import org.eclipse.keypop.calypso.card.transaction.spi.CardTransactionCryptoExtension;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.reader.CardReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link SecureTransactionManager}.
 *
 * @param <T> The type of the lowest level child object.
 * @since 3.0.0
 */
class SecureTransactionManagerAdapter<T extends SecureTransactionManager<T>> extends TransactionManagerAdapter<T> implements SecureTransactionManager<T> {

  private static final Logger logger = LoggerFactory.getLogger(SecureTransactionManagerAdapter.class);

  /**
   * Builds a new instance.
   *
   * @param cardReader                     The card reader to be used.
   * @param card                           The selected card on which to operate the transaction.
   * @param symmetricCryptoSecuritySetting The symmetric crypto security setting to be used.
   * @since 3.0.0
   */
  SecureTransactionManagerAdapter(ProxyReaderApi cardReader, CalypsoCardAdapter card, SymmetricCryptoSecuritySettingAdapter symmetricCryptoSecuritySetting) {
    super(cardReader, card, symmetricCryptoSecuritySetting);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public <E extends CardTransactionCryptoExtension> E getCryptoExtension(Class<E> cryptoExtensionClass) {
    return (E) cryptoExtension;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public T prepareCloseSecureSession() {
    try {
      checkSecureSession();
      if (symmetricCryptoSecuritySetting.isRatificationMechanismEnabled()
              && ((CardReader) cardReader).isContactless()) {
        // CL-RAT-CMD.1
        // CL-RAT-DELAY.1
        // CL-RAT-NXTCLOSE.1
        cardCommands.add(
                new CmdCardCloseSecureSession(
                        transactionContext, getCommandContext(), false, svPostponedDataIndex));
        cardCommands.add(new CmdCardRatification(transactionContext, getCommandContext()));
      } else {
        cardCommands.add(
                new CmdCardCloseSecureSession(
                        transactionContext, getCommandContext(), true, svPostponedDataIndex));
      }
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      isSecureSessionOpen = false;
      isEncryptionActive = false;
      disablePreOpenMode();
    }
    return currentInstance;
  }

  /**
   * Checks if a secure session is open.
   *
   * @throws IllegalStateException If no secure session is open.
   */
  void checkSecureSession() {
    if (!isSecureSessionOpen) {
      throw new IllegalStateException(SECURE_SESSION_NOT_OPEN);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public T prepareCancelSecureSession() {
    try {
      cardCommands.add(new CmdCardCloseSecureSession(transactionContext, getCommandContext()));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      isSecureSessionOpen = false;
      isEncryptionActive = false;
      disablePreOpenMode();
    }
    return currentInstance;
  }
}
