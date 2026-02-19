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
import org.eclipse.keypop.calypso.card.transaction.spi.AsymmetricCryptoCardTransactionManagerFactory;
import org.eclipse.keypop.calypso.card.transaction.spi.SymmetricCryptoCardTransactionManagerFactory;
import org.eclipse.keypop.calypso.crypto.asymmetric.transaction.spi.AsymmetricCryptoCardTransactionManagerFactorySpi;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoCardTransactionManagerFactorySpi;
import org.eclipse.keypop.card.ProxyReaderApi;
import org.eclipse.keypop.reader.CardReader;

/**
 * Adapter of {@link CalypsoCardApiFactory}.
 *
 * @since 1.0.0
 */
class CalypsoCardApiFactoryAdapter implements CalypsoCardApiFactory {

  private static final String MSG_THE_PROVIDED_CARD_HAS_AN_UNDEFINED_PRODUCT_TYPE =
      "The provided 'card' has an undefined product type";
  private static final String MSG_CARD_READER = "cardReader";
  private static final String MSG_CARD = "card";
  private static final String MSG_SECURITY_SETTING = "securitySetting";

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
        .notNull(cryptoCardTransactionManagerFactory, "cryptoCardTransactionManagerFactory");
    if (!(cryptoCardTransactionManagerFactory
        instanceof SymmetricCryptoCardTransactionManagerFactorySpi)) {
      throw new IllegalArgumentException(
          "Cannot cast 'factory' to SymmetricCryptoCardTransactionManagerFactorySpi. Actual type: "
              + cryptoCardTransactionManagerFactory.getClass().getName());
    }
    return new SymmetricCryptoSecuritySettingAdapter(
        (SymmetricCryptoCardTransactionManagerFactorySpi) cryptoCardTransactionManagerFactory);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public AsymmetricCryptoSecuritySetting createAsymmetricCryptoSecuritySetting(
      AsymmetricCryptoCardTransactionManagerFactory cryptoCardTransactionManagerFactory) {
    Assert.getInstance()
        .notNull(cryptoCardTransactionManagerFactory, "cryptoCardTransactionManagerFactory");
    if (!(cryptoCardTransactionManagerFactory
        instanceof AsymmetricCryptoCardTransactionManagerFactorySpi)) {
      throw new IllegalArgumentException(
          "Cannot cast 'factory' to AsymmetricCryptoCardTransactionManagerFactorySpi. Actual type: "
              + cryptoCardTransactionManagerFactory.getClass().getName());
    }
    return new AsymmetricCryptoSecuritySettingAdapter(
        (AsymmetricCryptoCardTransactionManagerFactorySpi) cryptoCardTransactionManagerFactory);
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.0.0
   */
  @Override
  public FreeTransactionManager createFreeTransactionManager(
      CardReader cardReader, CalypsoCard card) {
    Assert.getInstance().notNull(cardReader, MSG_CARD_READER).notNull(card, MSG_CARD);
    if (!(cardReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
          "Cannot cast 'cardReader' to ProxyReaderApi. Actual type: "
              + cardReader.getClass().getName());
    }
    if (!(card instanceof CalypsoCardAdapter)) {
      throw new IllegalArgumentException(
          "Cannot cast 'card' to CalypsoCardAdapter. Actual type: " + card.getClass().getName());
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
        .notNull(card, MSG_CARD)
        .notNull(securitySetting, MSG_SECURITY_SETTING);
    if (!(cardReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
          "Cannot cast 'cardReader' to ProxyReaderApi. Actual type: "
              + cardReader.getClass().getName());
    }
    if (!(card instanceof CalypsoCardAdapter)) {
      throw new IllegalArgumentException(
          "Cannot cast 'card' to CalypsoCardAdapter. Actual type: " + card.getClass().getName());
    }
    if (!(securitySetting instanceof SymmetricCryptoSecuritySettingAdapter)) {
      throw new IllegalArgumentException(
          "Cannot cast 'securitySetting' to SymmetricCryptoSecuritySettingAdapter. Actual type: "
              + securitySetting.getClass().getName());
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
        .notNull(card, MSG_CARD)
        .notNull(securitySetting, MSG_SECURITY_SETTING);
    if (!(cardReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
          "Cannot cast 'cardReader' to ProxyReaderApi. Actual type: "
              + cardReader.getClass().getName());
    }
    if (!(card instanceof CalypsoCardAdapter)) {
      throw new IllegalArgumentException(
          "Cannot cast 'card' to CalypsoCardAdapter. Actual type: " + card.getClass().getName());
    }
    if (!(securitySetting instanceof SymmetricCryptoSecuritySettingAdapter)) {
      throw new IllegalArgumentException(
          "Cannot cast 'securitySetting' to SymmetricCryptoSecuritySettingAdapter. Actual type: "
              + securitySetting.getClass().getName());
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
   * @since 3.1.0
   */
  @Override
  public SecurePkiModeTransactionManager createSecurePkiModeTransactionManager(
      CardReader cardReader, CalypsoCard card, AsymmetricCryptoSecuritySetting securitySetting) {
    Assert.getInstance()
        .notNull(cardReader, MSG_CARD_READER)
        .notNull(card, MSG_CARD)
        .notNull(securitySetting, MSG_SECURITY_SETTING);
    if (!(cardReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
          "Cannot cast 'cardReader' to ProxyReaderApi. Actual type: "
              + cardReader.getClass().getName());
    }
    if (!(card instanceof CalypsoCardAdapter)) {
      throw new IllegalArgumentException(
          "Cannot cast 'card' to CalypsoCardAdapter. Actual type: " + card.getClass().getName());
    }
    if (!(securitySetting instanceof AsymmetricCryptoSecuritySettingAdapter)) {
      throw new IllegalArgumentException(
          "Cannot cast 'securitySetting' to AsymmetricCryptoSecuritySettingAdapter. Actual type: "
              + securitySetting.getClass().getName());
    }
    return new SecurePkiModeTransactionManagerAdapter(
        (ProxyReaderApi) cardReader,
        (CalypsoCardAdapter) card,
        (AsymmetricCryptoSecuritySettingAdapter) securitySetting);
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
