/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
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

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.transaction.AsymmetricCryptoSecuritySetting;
import org.eclipse.keypop.calypso.card.transaction.InvalidCertificateException;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificate;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificateParser;
import org.eclipse.keypop.calypso.card.transaction.spi.CardCertificateParser;
import org.eclipse.keypop.calypso.card.transaction.spi.PcaCertificate;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.*;
import org.eclipse.keypop.calypso.crypto.asymmetric.transaction.spi.AsymmetricCryptoCardTransactionManagerFactorySpi;

/**
 * Adapter of {@link AsymmetricCryptoSecuritySetting}.
 *
 * @since 3.1.0
 */
class AsymmetricCryptoSecuritySettingAdapter implements AsymmetricCryptoSecuritySetting {

  private static final String MSG_THE_PROVIDED_PCA_CERTIFICATE_MUST_IMPLEMENT_PCA_CERTIFICATE_SPI =
      "The provided 'pcaCertificate' must implement 'PcaCertificateSpi'";
  private static final String MSG_THE_PROVIDED_CA_CERTIFICATE_MUST_IMPLEMENT_CA_CERTIFICATE_SPI =
      "The provided 'caCertificate' must implement 'CaCertificateSpi'";
  private static final String
      MSG_THE_PROVIDED_CA_CERTIFICATE_PARSER_MUST_IMPLEMENT_CA_CERTIFICATE_PARSER_SPI =
          "The provided 'caCertificateParser' must implement 'CaCertificateParserSpi'";

  private final AsymmetricCryptoCardTransactionManagerFactorySpi
      cryptoCardTransactionManagerFactorySpi;
  private final Map<String, CaCertificateContentSpi> caCertificates =
      new HashMap<String, CaCertificateContentSpi>();
  private final Map<Byte, CaCertificateParserSpi> caCertificateParsers =
      new HashMap<Byte, CaCertificateParserSpi>();
  private final Map<Byte, CardCertificateParserSpi> cardCertificateParsers =
      new HashMap<Byte, CardCertificateParserSpi>();

  /**
   * Constructor.
   *
   * @param cryptoCardTransactionManagerFactorySpi The asymmetric transaction manager factory.
   * @since 3.1.0
   */
  AsymmetricCryptoSecuritySettingAdapter(
      AsymmetricCryptoCardTransactionManagerFactorySpi cryptoCardTransactionManagerFactorySpi) {
    this.cryptoCardTransactionManagerFactorySpi = cryptoCardTransactionManagerFactorySpi;
  }

  /**
   * @return The {@link AsymmetricCryptoCardTransactionManagerFactorySpi}.
   * @since 3.1.0
   */
  AsymmetricCryptoCardTransactionManagerFactorySpi getCryptoCardTransactionManagerFactorySpi() {
    return cryptoCardTransactionManagerFactorySpi;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public AsymmetricCryptoSecuritySetting addPcaCertificate(PcaCertificate pcaCertificate) {

    Assert.getInstance().notNull(pcaCertificate, "pcaCertificate");
    if (!(pcaCertificate instanceof PcaCertificateSpi)) {
      throw new IllegalArgumentException(
          MSG_THE_PROVIDED_PCA_CERTIFICATE_MUST_IMPLEMENT_PCA_CERTIFICATE_SPI);
    }
    PcaCertificateSpi pcaCertificateSpi = (PcaCertificateSpi) pcaCertificate;

    CaCertificateContentSpi certificateContent;
    try {
      certificateContent = pcaCertificateSpi.checkCertificateAndGetContent();
    } catch (CertificateException e) {
      throw new InvalidCertificateException(
          "An error occurs during the check of the certificate: " + e.getMessage(), e);
    }

    String keyRef = HexUtil.toHex(certificateContent.getPublicKeyReference());
    if (caCertificates.containsKey(keyRef)) {
      throw new IllegalStateException(
          "The provided public key reference already exists: " + keyRef);
    }
    caCertificates.put(keyRef, certificateContent);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public AsymmetricCryptoSecuritySetting addCaCertificate(CaCertificate caCertificate) {

    Assert.getInstance().notNull(caCertificate, "caCertificate");
    if (!(caCertificate instanceof CaCertificateSpi)) {
      throw new IllegalArgumentException(
          MSG_THE_PROVIDED_CA_CERTIFICATE_MUST_IMPLEMENT_CA_CERTIFICATE_SPI);
    }
    CaCertificateSpi caCertificateSpi = (CaCertificateSpi) caCertificate;

    // Get the issuer public key reference
    String issuerKeyRef = HexUtil.toHex(caCertificateSpi.getIssuerPublicKeyReference());

    // Search the issuer certificate
    CaCertificateContentSpi issuerCertificateContent = caCertificates.get(issuerKeyRef);
    if (issuerCertificateContent == null) {
      throw new IllegalStateException("The issuer certificate is not loaded: " + issuerKeyRef);
    }

    // Check the CA certificate using the issuer's public key
    CaCertificateContentSpi caCertificateContent;
    try {
      caCertificateContent =
          caCertificateSpi.checkCertificateAndGetContent(issuerCertificateContent);
    } catch (CertificateException e) {
      throw new InvalidCertificateException(
          "An error occurs during the check of the certificate: " + e.getMessage(), e);
    }

    // Try to save the certificate into the store
    String caKeyRef = HexUtil.toHex(caCertificateContent.getPublicKeyReference());
    if (caCertificates.containsKey(caKeyRef)) {
      throw new IllegalStateException("The certificate is already loaded: " + caKeyRef);
    }

    caCertificates.put(caKeyRef, caCertificateContent);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public AsymmetricCryptoSecuritySetting addCaCertificateParser(
      CaCertificateParser caCertificateParser) {
    Assert.getInstance().notNull(caCertificateParser, "caCertificateParser");
    if (!(caCertificateParser instanceof CaCertificateParserSpi)) {
      throw new IllegalArgumentException(
          MSG_THE_PROVIDED_CA_CERTIFICATE_PARSER_MUST_IMPLEMENT_CA_CERTIFICATE_PARSER_SPI);
    }
    CaCertificateParserSpi caCertificateParserSpi = (CaCertificateParserSpi) caCertificateParser;
    byte certificateType = caCertificateParserSpi.getCertificateType();
    if (caCertificateParsers.containsKey(certificateType)) {
      throw new IllegalStateException(
          "A parser is already registered for the certificate type "
              + HexUtil.toHex(certificateType));
    }
    this.caCertificateParsers.put(certificateType, caCertificateParserSpi);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public AsymmetricCryptoSecuritySetting addCardCertificateParser(
      CardCertificateParser cardCertificateParser) {
    Assert.getInstance().notNull(cardCertificateParser, "cardCertificateParser");
    byte certificateType = ((CardCertificateParserSpi) cardCertificateParser).getCertificateType();
    this.cardCertificateParsers.put(certificateType, cardCertificateParser);
    return this;
  }

  /**
   * Retrieves the certificate based on the provided public key reference.
   *
   * @param publicKeyReference The public key reference as a 29-byte byte array.
   * @return null if no certificate certificate matches the provided reference.
   * @since 3.1.0
   */
  CaCertificateContentSpi getCertificate(byte[] publicKeyReference) {
    return caCertificates.get(HexUtil.toHex(publicKeyReference));
  }

  /**
   * Retrieves the CA certificate parser.
   *
   * @param certificateType The type of certificate.
   * @return The CA certificate parser.
   * @since 3.1.0
   */
  CaCertificateParser getCaCertificateParser(byte certificateType) {
    return caCertificateParsers.get(certificateType);
  }

  /**
   * Retrieves the card certificate parser.
   *
   * @param certificateType The type of certificate.
   * @return The card certificate parser.
   * @since 3.1.0
   */
  CardCertificateParser getCardCertificateParser(byte certificateType) {
    return cardCertificateParsers.get(certificateType);
  }
}
