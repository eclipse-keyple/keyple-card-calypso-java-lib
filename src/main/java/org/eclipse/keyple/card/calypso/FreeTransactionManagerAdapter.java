package org.eclipse.keyple.card.calypso;
import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import org.eclipse.keypop.calypso.card.transaction.FreeTransactionManager;
import org.eclipse.keypop.card.ProxyReaderApi;

/**
 * Adapter of {@link FreeTransactionManager}.
 * @since 3.0.0
 */
class FreeTransactionManagerAdapter extends TransactionManagerAdapter<FreeTransactionManager> implements FreeTransactionManager {

  /**
   * Builds a new instance.
   * @param cardReader The card reader to be used.
   * @param card The selected card on which to operate the transaction.
   * @since 3.0.0
   */
  FreeTransactionManagerAdapter(ProxyReaderApi cardReader, CalypsoCardAdapter card) {
    super(cardReader, card, null);
  }
}
