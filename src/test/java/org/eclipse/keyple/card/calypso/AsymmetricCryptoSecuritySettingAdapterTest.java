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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.transaction.InvalidCertificateException;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificate;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificateParser;
import org.eclipse.keypop.calypso.card.transaction.spi.CardCertificateParser;
import org.eclipse.keypop.calypso.card.transaction.spi.PcaCertificate;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.*;
import org.eclipse.keypop.calypso.crypto.asymmetric.transaction.spi.AsymmetricCryptoCardTransactionManagerFactorySpi;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class AsymmetricCryptoSecuritySettingAdapterTest {
  private static final byte[] PUBLIC_KEY_REFERENCE_1 =
      HexUtil.toByteArray("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCC");
  private static final byte[] PUBLIC_KEY_REFERENCE_2 =
      HexUtil.toByteArray("112233445566778899AABBCCDDEEFF00112233445566778899AABBCC00");
  private static final byte CA_CERTIFICATE_TYPE = (byte) 0x90;
  private static final byte CARD_CERTIFICATE_TYPE = (byte) 0x91;
  private static final AsymmetricCryptoCardTransactionManagerFactorySpi
      asymmetricCryptoCardTransactionManagerFactorySpi =
          mock(AsymmetricCryptoCardTransactionManagerFactorySpi.class);
  private AsymmetricCryptoSecuritySettingAdapter asymmetricCryptoSecuritySettingAdapter;

  @Before
  public void setUp() throws Exception {
    // Initialize the class to be tested
    asymmetricCryptoSecuritySettingAdapter =
        new AsymmetricCryptoSecuritySettingAdapter(
            asymmetricCryptoCardTransactionManagerFactorySpi);
  }

  @Test
  public void getCryptoCardTransactionManagerFactorySpi_shouldReturnFactory() {
    assertThat(asymmetricCryptoSecuritySettingAdapter.getCryptoCardTransactionManagerFactorySpi())
        .isEqualTo(asymmetricCryptoCardTransactionManagerFactorySpi);
  }

  @Test
  public void addPcaCertificate_whenValidCertificate_shouldFillCertificateStore()
      throws CertificateValidationException, AsymmetricCryptoException {
    // Mock PcaCertificateSpi and necessary methods
    Object mockPcaCert =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(
                    PcaCertificate.class, PcaCertificateSpi.class, CaCertificateContentSpi.class));
    CaCertificateContentSpi mockPcaCertContent = mock(CaCertificateContentSpi.class);

    // Mocking methods of PcaCertificateSpi
    when(((PcaCertificateSpi) mockPcaCert).checkCertificateAndGetContent())
        .thenReturn(mockPcaCertContent);
    when(mockPcaCertContent.getPublicKeyReference()).thenReturn(PUBLIC_KEY_REFERENCE_1);

    // Run the method being tested
    asymmetricCryptoSecuritySettingAdapter.addPcaCertificate((PcaCertificate) mockPcaCert);

    assertThat(asymmetricCryptoSecuritySettingAdapter.getCaCertificate(PUBLIC_KEY_REFERENCE_1))
        .isEqualTo(mockPcaCertContent);
  }

  @Test(expected = IllegalArgumentException.class)
  public void addPcaCertificate_whenInvalidInstance_shouldThrowIAE() {
    // Mock PcaCertificateSpi and necessary methods
    Object mockPcaCert =
        Mockito.mock(
            Object.class,
            withSettings().extraInterfaces(PcaCertificate.class, CaCertificateContentSpi.class));

    // Run the method being tested
    asymmetricCryptoSecuritySettingAdapter.addPcaCertificate((PcaCertificate) mockPcaCert);
  }

  @Test(expected = InvalidCertificateException.class)
  public void addPcaCertificate_whenInvalidCertificate_shouldThrowInvalidCertificateException()
      throws CertificateValidationException, AsymmetricCryptoException {
    // Mock PcaCertificateSpi and necessary methods
    Object mockPcaCert =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(
                    PcaCertificate.class, PcaCertificateSpi.class, CaCertificateContentSpi.class));
    CaCertificateContentSpi mockPcaCertContent = mock(CaCertificateContentSpi.class);

    // Mocking methods of PcaCertificateSpi
    when(((PcaCertificateSpi) mockPcaCert).checkCertificateAndGetContent())
        .thenThrow(CertificateValidationException.class);
    when(mockPcaCertContent.getPublicKeyReference()).thenReturn(PUBLIC_KEY_REFERENCE_1);

    // Run the method being tested
    asymmetricCryptoSecuritySettingAdapter.addPcaCertificate((PcaCertificate) mockPcaCert);
  }

  @Test(expected = IllegalStateException.class)
  public void addPcaCertificate_whenValidCertificateAlreadyRegistered_shouldThrowISE()
      throws CertificateValidationException, AsymmetricCryptoException {
    // Mock PcaCertificateSpi and necessary methods
    Object mockPcaCert =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(
                    PcaCertificate.class, PcaCertificateSpi.class, CaCertificateContentSpi.class));
    CaCertificateContentSpi mockPcaCertContent = mock(CaCertificateContentSpi.class);

    // Mocking methods of PcaCertificateSpi
    when(((PcaCertificateSpi) mockPcaCert).checkCertificateAndGetContent())
        .thenReturn(mockPcaCertContent);
    when(mockPcaCertContent.getPublicKeyReference()).thenReturn(PUBLIC_KEY_REFERENCE_1);

    // Run twice the method being tested
    asymmetricCryptoSecuritySettingAdapter.addPcaCertificate((PcaCertificate) mockPcaCert);
    asymmetricCryptoSecuritySettingAdapter.addPcaCertificate((PcaCertificate) mockPcaCert);
  }

  @Test
  public void addCaCertificate_whenValidCertificate_shouldFillCertificateStore()
      throws CertificateValidationException, AsymmetricCryptoException {
    // Mocking methods of PcaCertificateSpi
    Object mockPcaCert =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(
                    PcaCertificate.class, PcaCertificateSpi.class, CaCertificateContentSpi.class));
    CaCertificateContentSpi mockPcaCertContent = mock(CaCertificateContentSpi.class);
    when(mockPcaCertContent.getPublicKeyReference()).thenReturn(PUBLIC_KEY_REFERENCE_1);
    when(((PcaCertificateSpi) mockPcaCert).checkCertificateAndGetContent())
        .thenReturn(mockPcaCertContent);

    asymmetricCryptoSecuritySettingAdapter.addPcaCertificate((PcaCertificate) mockPcaCert);

    // Mock CaCertificateSpi and necessary methods
    Object mockCaCert =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(
                    CaCertificate.class, CaCertificateSpi.class, CaCertificateContentSpi.class));
    CaCertificateContentSpi mockCaCertContent = mock(CaCertificateContentSpi.class);

    when(((CaCertificateSpi) mockCaCert)
            .checkCertificateAndGetContent((CaCertificateContentSpi) mockPcaCert))
        .thenReturn(mockCaCertContent);
    when(((CaCertificateSpi) mockCaCert).getIssuerPublicKeyReference())
        .thenReturn(PUBLIC_KEY_REFERENCE_1);
    when(mockCaCertContent.getPublicKeyReference()).thenReturn(PUBLIC_KEY_REFERENCE_2);
    when(((CaCertificateSpi) mockCaCert).checkCertificateAndGetContent(mockPcaCertContent))
        .thenReturn(mockCaCertContent);

    // Run the method being tested
    asymmetricCryptoSecuritySettingAdapter.addCaCertificate((CaCertificate) mockCaCert);

    assertThat(asymmetricCryptoSecuritySettingAdapter.getCaCertificate(PUBLIC_KEY_REFERENCE_2))
        .isEqualTo(mockCaCertContent);
  }

  @Test(expected = IllegalArgumentException.class)
  public void addCaCertificate_whenInvalidInstance_shouldThrowIAE() {
    // Mock PcaCertificateSpi and necessary methods
    Object mockCaCert =
        Mockito.mock(
            Object.class,
            withSettings().extraInterfaces(CaCertificate.class, CaCertificateContentSpi.class));

    // Run the method being tested
    asymmetricCryptoSecuritySettingAdapter.addCaCertificate((CaCertificate) mockCaCert);
  }

  @Test(expected = IllegalStateException.class)
  public void addCaCertificate_whenIssuerIsUnknown_shouldThrowISE()
      throws CertificateValidationException, AsymmetricCryptoException {
    // Mocking methods of PcaCertificateSpi
    Object mockPcaCert =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(
                    PcaCertificate.class, PcaCertificateSpi.class, CaCertificateContentSpi.class));
    CaCertificateContentSpi mockPcaCertContent = mock(CaCertificateContentSpi.class);
    when(mockPcaCertContent.getPublicKeyReference()).thenReturn(PUBLIC_KEY_REFERENCE_1);
    when(((PcaCertificateSpi) mockPcaCert).checkCertificateAndGetContent())
        .thenReturn(mockPcaCertContent);

    // Mock CaCertificateSpi and necessary methods
    Object mockCaCert =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(
                    CaCertificate.class, CaCertificateSpi.class, CaCertificateContentSpi.class));
    CaCertificateContentSpi mockCaCertContent = mock(CaCertificateContentSpi.class);

    when(((CaCertificateSpi) mockCaCert)
            .checkCertificateAndGetContent((CaCertificateContentSpi) mockPcaCert))
        .thenReturn(mockCaCertContent);
    when(((CaCertificateSpi) mockCaCert).getIssuerPublicKeyReference())
        .thenReturn(PUBLIC_KEY_REFERENCE_1);
    when(mockCaCertContent.getPublicKeyReference()).thenReturn(PUBLIC_KEY_REFERENCE_2);
    when(((CaCertificateSpi) mockCaCert).checkCertificateAndGetContent(mockPcaCertContent))
        .thenReturn(mockCaCertContent);

    // Run the method being tested
    asymmetricCryptoSecuritySettingAdapter.addCaCertificate((CaCertificate) mockCaCert);
  }

  @Test(expected = InvalidCertificateException.class)
  public void addCaCertificate_whenInvalidCertificate_shouldThrowInvalidCertificateException()
      throws CertificateValidationException, AsymmetricCryptoException {
    // Mocking methods of PcaCertificateSpi
    Object mockPcaCert =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(
                    PcaCertificate.class, PcaCertificateSpi.class, CaCertificateContentSpi.class));
    CaCertificateContentSpi mockPcaCertContent = mock(CaCertificateContentSpi.class);
    when(mockPcaCertContent.getPublicKeyReference()).thenReturn(PUBLIC_KEY_REFERENCE_1);
    when(((PcaCertificateSpi) mockPcaCert).checkCertificateAndGetContent())
        .thenReturn(mockPcaCertContent);

    asymmetricCryptoSecuritySettingAdapter.addPcaCertificate((PcaCertificate) mockPcaCert);

    // Mock CaCertificateSpi and necessary methods
    Object mockCaCert =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(
                    CaCertificate.class, CaCertificateSpi.class, CaCertificateContentSpi.class));
    CaCertificateContentSpi mockCaCertContent = mock(CaCertificateContentSpi.class);

    when(((CaCertificateSpi) mockCaCert)
            .checkCertificateAndGetContent((CaCertificateContentSpi) mockPcaCert))
        .thenReturn(mockCaCertContent);
    when(((CaCertificateSpi) mockCaCert).getIssuerPublicKeyReference())
        .thenReturn(PUBLIC_KEY_REFERENCE_1);
    when(mockCaCertContent.getPublicKeyReference()).thenReturn(PUBLIC_KEY_REFERENCE_2);
    when(((CaCertificateSpi) mockCaCert).checkCertificateAndGetContent(mockPcaCertContent))
        .thenThrow(CertificateValidationException.class);

    // Run the method being tested
    asymmetricCryptoSecuritySettingAdapter.addCaCertificate((CaCertificate) mockCaCert);
  }

  @Test(expected = IllegalStateException.class)
  public void addCaCertificate_whenValidCertificateAlreadyRegistered_shouldThrowISE()
      throws CertificateValidationException, AsymmetricCryptoException {
    // Mocking methods of PcaCertificateSpi
    Object mockPcaCert =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(
                    PcaCertificate.class, PcaCertificateSpi.class, CaCertificateContentSpi.class));
    CaCertificateContentSpi mockPcaCertContent = mock(CaCertificateContentSpi.class);
    when(mockPcaCertContent.getPublicKeyReference()).thenReturn(PUBLIC_KEY_REFERENCE_1);
    when(((PcaCertificateSpi) mockPcaCert).checkCertificateAndGetContent())
        .thenReturn(mockPcaCertContent);

    asymmetricCryptoSecuritySettingAdapter.addPcaCertificate((PcaCertificate) mockPcaCert);

    // Mock CaCertificateSpi and necessary methods
    Object mockCaCert =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(
                    CaCertificate.class, CaCertificateSpi.class, CaCertificateContentSpi.class));
    CaCertificateContentSpi mockCaCertContent = mock(CaCertificateContentSpi.class);

    when(((CaCertificateSpi) mockCaCert)
            .checkCertificateAndGetContent((CaCertificateContentSpi) mockPcaCert))
        .thenReturn(mockCaCertContent);
    when(((CaCertificateSpi) mockCaCert).getIssuerPublicKeyReference())
        .thenReturn(PUBLIC_KEY_REFERENCE_1);
    when(mockCaCertContent.getPublicKeyReference()).thenReturn(PUBLIC_KEY_REFERENCE_2);
    when(((CaCertificateSpi) mockCaCert).checkCertificateAndGetContent(mockPcaCertContent))
        .thenReturn(mockCaCertContent);

    // Run twice the method being tested
    asymmetricCryptoSecuritySettingAdapter.addCaCertificate((CaCertificate) mockCaCert);
    asymmetricCryptoSecuritySettingAdapter.addCaCertificate((CaCertificate) mockCaCert);
  }

  @Test
  public void addCaCertificateParser_whenValidParser_shouldFillParserStore() {
    // Mocking methods of CaCertificateParserSpi
    Object mockCaCertParser =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(CaCertificateParser.class, CaCertificateParserSpi.class));
    when(((CaCertificateParserSpi) mockCaCertParser).getCertificateType())
        .thenReturn(CA_CERTIFICATE_TYPE);
    asymmetricCryptoSecuritySettingAdapter.addCaCertificateParser(
        (CaCertificateParser) mockCaCertParser);
    assertThat(asymmetricCryptoSecuritySettingAdapter.getCaCertificateParser(CA_CERTIFICATE_TYPE))
        .isEqualTo(mockCaCertParser);
  }

  @Test(expected = IllegalArgumentException.class)
  public void addCaCertificateParser_whenInvalidParser_shouldIAE() {
    // Mocking methods of CaCertificateParserSpi
    Object mockCaCertParser =
        Mockito.mock(Object.class, withSettings().extraInterfaces(CaCertificateParser.class));
    asymmetricCryptoSecuritySettingAdapter.addCaCertificateParser(
        (CaCertificateParser) mockCaCertParser);
  }

  @Test(expected = IllegalStateException.class)
  public void addCaCertificateParser_whenValidParserAlreadyRegistered_shouldThrowISE() {
    // Mocking methods of CaCertificateParserSpi
    Object mockCaCertParser =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(CaCertificateParser.class, CaCertificateParserSpi.class));
    when(((CaCertificateParserSpi) mockCaCertParser).getCertificateType())
        .thenReturn(CA_CERTIFICATE_TYPE);
    asymmetricCryptoSecuritySettingAdapter.addCaCertificateParser(
        (CaCertificateParser) mockCaCertParser);
    asymmetricCryptoSecuritySettingAdapter.addCaCertificateParser(
        (CaCertificateParser) mockCaCertParser);
  }

  @Test
  public void addCardCertificateParser_whenValidParser_shouldFillParserStore() {
    // Mocking methods of CardCertificateParserSpi
    Object mockCardCertParser =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(CardCertificateParser.class, CardCertificateParserSpi.class));
    when(((CardCertificateParserSpi) mockCardCertParser).getCertificateType())
        .thenReturn(CARD_CERTIFICATE_TYPE);
    asymmetricCryptoSecuritySettingAdapter.addCardCertificateParser(
        (CardCertificateParser) mockCardCertParser);
    assertThat(
            asymmetricCryptoSecuritySettingAdapter.getCardCertificateParser(CARD_CERTIFICATE_TYPE))
        .isEqualTo(mockCardCertParser);
  }

  @Test(expected = IllegalArgumentException.class)
  public void addCardCertificateParser_whenInvalidParser_shouldIAE() {
    // Mocking methods of CardCertificateParserSpi
    Object mockCardCertParser =
        Mockito.mock(Object.class, withSettings().extraInterfaces(CardCertificateParser.class));
    asymmetricCryptoSecuritySettingAdapter.addCardCertificateParser(
        (CardCertificateParser) mockCardCertParser);
  }

  @Test(expected = IllegalStateException.class)
  public void addCardCertificateParser_whenValidParserAlreadyRegistered_shouldThrowISE() {
    // Mocking methods of CardCertificateParserSpi
    Object mockCardCertParser =
        Mockito.mock(
            Object.class,
            withSettings()
                .extraInterfaces(CardCertificateParser.class, CardCertificateParserSpi.class));
    when(((CardCertificateParserSpi) mockCardCertParser).getCertificateType())
        .thenReturn(CARD_CERTIFICATE_TYPE);
    asymmetricCryptoSecuritySettingAdapter.addCardCertificateParser(
        (CardCertificateParser) mockCardCertParser);
    asymmetricCryptoSecuritySettingAdapter.addCardCertificateParser(
        (CardCertificateParser) mockCardCertParser);
  }
}
