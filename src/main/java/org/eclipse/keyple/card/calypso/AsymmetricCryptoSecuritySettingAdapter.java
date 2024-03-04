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
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateParserSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateParserSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.transaction.spi.AsymmetricCryptoCardTransactionManagerFactorySpi;

/**
 * Adapter of {@link AsymmetricCryptoSecuritySetting}.
 *
 * @since 3.1.0
 */
class AsymmetricCryptoSecuritySettingAdapter implements AsymmetricCryptoSecuritySetting {
  private final AsymmetricCryptoCardTransactionManagerFactorySpi transactionManagerFactorySpi;
  private final Map<String, CaCertificateContentSpi> certificates =
      new HashMap<String, CaCertificateContentSpi>();
  private final Map<Byte, CardCertificateParser> cardCertificateParsers =
      new HashMap<Byte, CardCertificateParser>();
  private final Map<Byte, CaCertificateParser> caCertificateParsers =
      new HashMap<Byte, CaCertificateParser>();

  /**
   * Constructor.
   *
   * @param cryptoCardTransactionManagerFactorySpi The asymmetric transaction manager factory.
   * @since 3.1.0
   */
  AsymmetricCryptoSecuritySettingAdapter(
      AsymmetricCryptoCardTransactionManagerFactorySpi cryptoCardTransactionManagerFactorySpi) {
    this.transactionManagerFactorySpi = cryptoCardTransactionManagerFactorySpi;
  }

  /**
   * @return The {@link AsymmetricCryptoCardTransactionManagerFactorySpi}.
   * @since 3.1.0
   */
  AsymmetricCryptoCardTransactionManagerFactorySpi getCryptoCardTransactionManagerFactorySpi() {
    return transactionManagerFactorySpi;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public AsymmetricCryptoSecuritySetting addPcaCertificate(PcaCertificate pcaCertificate) {
    Assert.getInstance().notNull(pcaCertificate, "pcaCertificate");
    CaCertificateContentSpi certificateContent = (CaCertificateContentSpi) pcaCertificate;
    String publicKeyRefHex = HexUtil.toHex(certificateContent.getPublicKeyReference());
    if (certificates.containsKey(publicKeyRefHex)) {
      throw new IllegalStateException(
          "The provided public key reference already exists: " + publicKeyRefHex);
    }
    certificates.put(publicKeyRefHex, certificateContent);
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
    CaCertificateContentSpi certificateContent = (CaCertificateContentSpi) caCertificate;
    String publicKeyRefHex = HexUtil.toHex(certificateContent.getPublicKeyReference());
    if (certificates.containsKey(publicKeyRefHex)) {
      throw new IllegalStateException(
          "The provided public key reference already exists: " + publicKeyRefHex);
    }
    CaCertificateSpi caCertificateSpi = (CaCertificateSpi) caCertificate;
    byte[] issuerPublicKeyReference = caCertificateSpi.getIssuerPublicKeyReference();
    try {
      certificates.put(
          publicKeyRefHex,
          caCertificateSpi.checkCertificateAndGetContent(
              certificates.get(HexUtil.toHex(issuerPublicKeyReference))));
    } catch (CertificateException e) {
      throw new InvalidCertificateException("CA Certificate signature verification failed.", e);
    }
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
    byte certificateType = ((CaCertificateParserSpi) caCertificateParser).getCertificateType();
    this.caCertificateParsers.put(certificateType, caCertificateParser);
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
    return certificates.get(HexUtil.toHex(publicKeyReference));
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
