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

import org.eclipse.keypop.calypso.card.transaction.SecureRegularModeTransactionManager;
import org.eclipse.keypop.card.ProxyReaderApi;

/**
 * Adapter of {@link SecureRegularModeTransactionManager}.
 *
 * @since 3.0.0
 */
final class SecureRegularModeTransactionManagerAdapter
    extends SecureSymmetricCryptoTransactionManagerAdapter<SecureRegularModeTransactionManager>
    implements SecureRegularModeTransactionManager {

  /**
   * Builds a new instance.
   *
   * @param cardReader The card reader to be used.
   * @param card The selected card on which to operate the transaction.
   * @param symmetricCryptoSecuritySetting The symmetric crypto security setting to be used.
   * @since 3.0.0
   */
  SecureRegularModeTransactionManagerAdapter(
      ProxyReaderApi cardReader,
      CalypsoCardAdapter card,
      SymmetricCryptoSecuritySettingAdapter symmetricCryptoSecuritySetting) {
    super(cardReader, card, symmetricCryptoSecuritySetting);
  }
}
