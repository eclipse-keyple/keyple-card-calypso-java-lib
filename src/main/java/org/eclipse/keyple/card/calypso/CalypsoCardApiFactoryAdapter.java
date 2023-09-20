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

import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.card.CalypsoCardApiFactory;
import org.eclipse.keypop.calypso.card.card.CalypsoCard;
import org.eclipse.keypop.calypso.card.card.CalypsoCardSelectionExtension;
import org.eclipse.keypop.calypso.card.transaction.*;
import org.eclipse.keypop.calypso.card.transaction.SymmetricCryptoSecuritySetting;
import org.eclipse.keypop.calypso.card.transaction.spi.AsymmetricCryptoTransactionManagerFactory;
import org.eclipse.keypop.calypso.card.transaction.spi.SymmetricCryptoTransactionManagerFactory;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoTransactionManagerFactorySpi;
import org.eclipse.keypop.card.ProxyReaderApi;
import org.eclipse.keypop.reader.CardReader;

/**
 * Adapter of {@link CalypsoCardApiFactory}.
 *
 * @since 1.0.0
 */
class CalypsoCardApiFactoryAdapter implements CalypsoCardApiFactory {

  private static final String MSG_THE_PROVIDED_CARD_READER_MUST_IMPLEMENT_PROXY_READER_API =
          "The provided 'cardReader' must implement 'ProxyReaderApi'";
  private static final String MSG_THE_PROVIDED_CARD_MUST_BE_AN_INSTANCE_OF_CALYPSO_CARD_ADAPTER =
          "The provided 'card' must be an instance of 'CalypsoCardAdapter'";
  private static final String MSG_THE_PROVIDED_SECURITY_SETTING_MUST_BE_AN_INSTANCE_OF_SYMMETRIC_CRYPTO_SECURITY_SETTING_ADAPTER =
          "The provided 'securitySetting' must be an instance of 'SymmetricCryptoSecuritySettingAdapter'";

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public CalypsoCardSelectionExtension createCalypsoCardSelectionExtension() {
    return new CalypsoCardSelectionAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SymmetricCryptoSecuritySetting createSymmetricCryptoSecuritySetting(
      SymmetricCryptoTransactionManagerFactory cryptoTransactionManagerFactory) {
    Assert.getInstance().notNull(cryptoTransactionManagerFactory, "cryptoTransactionManagerFactory");
    if (!(cryptoTransactionManagerFactory instanceof SymmetricCryptoTransactionManagerFactorySpi)) {
      throw new IllegalArgumentException("The provided 'factory' must implement 'SymmetricCryptoTransactionManagerFactorySpi'");
    }
    return new SymmetricCryptoSecuritySettingAdapter((SymmetricCryptoTransactionManagerFactorySpi) cryptoTransactionManagerFactory);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public AsymmetricCryptoSecuritySetting createAsymmetricCryptoSecuritySetting(
      AsymmetricCryptoTransactionManagerFactory cryptoTransactionManagerFactory) {
    return null; //TODO
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public FreeTransactionManager createFreeTransactionManager(
      CardReader cardReader, CalypsoCard card) {
    Assert.getInstance().notNull(cardReader, "cardReader").notNull(card, "card");
    if (!(cardReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
              MSG_THE_PROVIDED_CARD_READER_MUST_IMPLEMENT_PROXY_READER_API);
    }
    if (!(card instanceof CalypsoCardAdapter)) {
      throw new IllegalArgumentException(
              MSG_THE_PROVIDED_CARD_MUST_BE_AN_INSTANCE_OF_CALYPSO_CARD_ADAPTER);
    }
    return new FreeTransactionManagerAdapter((ProxyReaderApi) cardReader, (CalypsoCardAdapter) card);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SecureRegularModeTransactionManager createSecureRegularModeTransactionManager(
      CardReader cardReader, CalypsoCard card, SymmetricCryptoSecuritySetting securitySetting) {
    Assert.getInstance().notNull(cardReader, "cardReader").notNull(card, "card").notNull(securitySetting, "securitySetting");
    if (!(cardReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
              MSG_THE_PROVIDED_CARD_READER_MUST_IMPLEMENT_PROXY_READER_API);
    }
    if (!(card instanceof CalypsoCardAdapter)) {
      throw new IllegalArgumentException(
              MSG_THE_PROVIDED_CARD_MUST_BE_AN_INSTANCE_OF_CALYPSO_CARD_ADAPTER);
    }
    if (!(securitySetting instanceof SymmetricCryptoSecuritySettingAdapter)) {
      throw new IllegalArgumentException(
              MSG_THE_PROVIDED_SECURITY_SETTING_MUST_BE_AN_INSTANCE_OF_SYMMETRIC_CRYPTO_SECURITY_SETTING_ADAPTER);
    }
    return new SecureRegularModeTransactionManagerAdapter((ProxyReaderApi) cardReader, (CalypsoCardAdapter) card, (SymmetricCryptoSecuritySettingAdapter) securitySetting);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SecureExtendedModeTransactionManager createSecureExtendedModeTransactionManager(
      CardReader cardReader, CalypsoCard card, SymmetricCryptoSecuritySetting securitySetting) {
    Assert.getInstance().notNull(cardReader, "cardReader").notNull(card, "card").notNull(securitySetting, "securitySetting");
    if (!(cardReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
              MSG_THE_PROVIDED_CARD_READER_MUST_IMPLEMENT_PROXY_READER_API);
    }
    if (!(card instanceof CalypsoCardAdapter)) {
      throw new IllegalArgumentException(
              MSG_THE_PROVIDED_CARD_MUST_BE_AN_INSTANCE_OF_CALYPSO_CARD_ADAPTER);
    }
    if (!(securitySetting instanceof SymmetricCryptoSecuritySettingAdapter)) {
      throw new IllegalArgumentException(
              MSG_THE_PROVIDED_SECURITY_SETTING_MUST_BE_AN_INSTANCE_OF_SYMMETRIC_CRYPTO_SECURITY_SETTING_ADAPTER);
    }
    return new SecureExtendedModeTransactionManagerAdapter((ProxyReaderApi) cardReader, (CalypsoCardAdapter) card, (SymmetricCryptoSecuritySettingAdapter) securitySetting);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SecurePkiModeTransactionManager createSecurePkiModeTransactionManager(
      CardReader cardReader, CalypsoCard card, AsymmetricCryptoSecuritySetting securitySetting) {
    Assert.getInstance().notNull(cardReader, "cardReader").notNull(card, "card").notNull(securitySetting, "securitySetting");
    if (!(cardReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
              MSG_THE_PROVIDED_CARD_READER_MUST_IMPLEMENT_PROXY_READER_API);
    }
    if (!(card instanceof CalypsoCardAdapter)) {
      throw new IllegalArgumentException(
              MSG_THE_PROVIDED_CARD_MUST_BE_AN_INSTANCE_OF_CALYPSO_CARD_ADAPTER);
    }
    // TODO test securitySetting
    return null; // TODO
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
