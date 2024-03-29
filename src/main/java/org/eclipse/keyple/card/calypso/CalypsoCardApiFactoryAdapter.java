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
import org.eclipse.keypop.calypso.card.transaction.spi.SymmetricCryptoCardTransactionManagerFactory;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoCardTransactionManagerFactorySpi;
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
  private static final String
      MSG_THE_PROVIDED_SECURITY_SETTING_MUST_BE_AN_INSTANCE_OF_SYMMETRIC_CRYPTO_SECURITY_SETTING_ADAPTER =
          "The provided 'securitySetting' must be an instance of 'SymmetricCryptoSecuritySettingAdapter'";
  private static final String MSG_THE_PROVIDED_CARD_HAS_AN_UNDEFINED_PRODUCT_TYPE =
      "The provided 'card' has an undefined product type";
  private static final String MSG_CARD_READER = "cardReader";

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public CalypsoCardSelectionExtension createCalypsoCardSelectionExtension() {
    return new CalypsoCardSelectionExtensionAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SymmetricCryptoSecuritySetting createSymmetricCryptoSecuritySetting(
      SymmetricCryptoCardTransactionManagerFactory cryptoCardTransactionManagerFactory) {
    Assert.getInstance()
        .notNull(cryptoCardTransactionManagerFactory, "cryptoTransactionManagerFactory");
    if (!(cryptoCardTransactionManagerFactory
        instanceof SymmetricCryptoCardTransactionManagerFactorySpi)) {
      throw new IllegalArgumentException(
          "The provided 'factory' must implement 'SymmetricCryptoCardTransactionManagerFactorySpi'");
    }
    return new SymmetricCryptoSecuritySettingAdapter(
        (SymmetricCryptoCardTransactionManagerFactorySpi) cryptoCardTransactionManagerFactory);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public FreeTransactionManager createFreeTransactionManager(
      CardReader cardReader, CalypsoCard card) {
    Assert.getInstance().notNull(cardReader, MSG_CARD_READER).notNull(card, "card");
    if (!(cardReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
          MSG_THE_PROVIDED_CARD_READER_MUST_IMPLEMENT_PROXY_READER_API);
    }
    if (!(card instanceof CalypsoCardAdapter)) {
      throw new IllegalArgumentException(
          MSG_THE_PROVIDED_CARD_MUST_BE_AN_INSTANCE_OF_CALYPSO_CARD_ADAPTER);
    }
    if (card.getProductType() == CalypsoCard.ProductType.UNKNOWN) {
      throw new IllegalArgumentException(MSG_THE_PROVIDED_CARD_HAS_AN_UNDEFINED_PRODUCT_TYPE);
    }
    return new FreeTransactionManagerAdapter(
        (ProxyReaderApi) cardReader, (CalypsoCardAdapter) card);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SecureRegularModeTransactionManager createSecureRegularModeTransactionManager(
      CardReader cardReader, CalypsoCard card, SymmetricCryptoSecuritySetting securitySetting) {
    Assert.getInstance()
        .notNull(cardReader, MSG_CARD_READER)
        .notNull(card, "card")
        .notNull(securitySetting, "securitySetting");
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
    if (card.getProductType() == CalypsoCard.ProductType.UNKNOWN) {
      throw new IllegalArgumentException(MSG_THE_PROVIDED_CARD_HAS_AN_UNDEFINED_PRODUCT_TYPE);
    }
    return new SecureRegularModeTransactionManagerAdapter(
        (ProxyReaderApi) cardReader,
        (CalypsoCardAdapter) card,
        (SymmetricCryptoSecuritySettingAdapter) securitySetting);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public SecureExtendedModeTransactionManager createSecureExtendedModeTransactionManager(
      CardReader cardReader, CalypsoCard card, SymmetricCryptoSecuritySetting securitySetting) {
    Assert.getInstance()
        .notNull(cardReader, MSG_CARD_READER)
        .notNull(card, "card")
        .notNull(securitySetting, "securitySetting");
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
    if (card.getProductType() == CalypsoCard.ProductType.UNKNOWN) {
      throw new IllegalArgumentException(MSG_THE_PROVIDED_CARD_HAS_AN_UNDEFINED_PRODUCT_TYPE);
    }
    return new SecureExtendedModeTransactionManagerAdapter(
        (ProxyReaderApi) cardReader,
        (CalypsoCardAdapter) card,
        (SymmetricCryptoSecuritySettingAdapter) securitySetting);
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
