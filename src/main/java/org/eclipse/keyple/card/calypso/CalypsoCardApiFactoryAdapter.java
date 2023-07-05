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

import org.eclipse.keypop.calypso.card.CalypsoCardApiFactory;
import org.eclipse.keypop.calypso.card.card.CalypsoCard;
import org.eclipse.keypop.calypso.card.card.CalypsoCardSelectionExtension;
import org.eclipse.keypop.calypso.card.transaction.*;
import org.eclipse.keypop.calypso.card.transaction.SymmetricCryptoSecuritySetting;
import org.eclipse.keypop.calypso.card.transaction.spi.AsymmetricCryptoTransactionManagerFactory;
import org.eclipse.keypop.calypso.card.transaction.spi.SymmetricCryptoTransactionManagerFactory;
import org.eclipse.keypop.reader.CardReader;

/**
 * Adapter of {@link CalypsoCardApiFactory}.
 *
 * @since 1.0.0
 */
public class CalypsoCardApiFactoryAdapter implements CalypsoCardApiFactory {

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public CalypsoCardSelectionExtension createCalypsoCardSelectionExtension() {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SymmetricCryptoSecuritySetting createSymmetricCryptoSecuritySetting(
      SymmetricCryptoTransactionManagerFactory cryptoTransactionManagerFactory) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public AsymmetricCryptoSecuritySetting createAsymmetricCryptoSecuritySetting(
      AsymmetricCryptoTransactionManagerFactory cryptoTransactionManagerFactory) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public FreeTransactionManager createFreeTransactionManager(
      CardReader cardReader, CalypsoCard card) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SecureStandardModeTransactionManager createSecureStandardModeTransactionManager(
      CardReader cardReader, CalypsoCard card, SymmetricCryptoSecuritySetting securitySetting) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SecureExtendedModeTransactionManager createSecureExtendedModeTransactionManager(
      CardReader cardReader, CalypsoCard card, SymmetricCryptoSecuritySetting securitySetting) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SecurePkiModeTransactionManager createSecurePkiModeTransactionManager(
      CardReader cardReader, CalypsoCard card, AsymmetricCryptoSecuritySetting securitySetting) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SearchCommandData createSearchCommandData() {
    return new DtoAdapters.SearchCommandDataAdapter();
  }
}
