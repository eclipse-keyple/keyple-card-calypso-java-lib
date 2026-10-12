/* **************************************************************************************
 * Copyright (c) 2026 Calypso Networks Association https://calypsonet.org/
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.GetDataTag;
import org.eclipse.keypop.calypso.card.transaction.SecurePkiModeTransactionManager;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificate;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificateParser;
import org.eclipse.keypop.calypso.card.transaction.spi.CardCertificateParser;
import org.eclipse.keypop.calypso.card.transaction.spi.CardTransactionCryptoExtension;
import org.eclipse.keypop.calypso.card.transaction.spi.PcaCertificate;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.*;
import org.eclipse.keypop.calypso.crypto.asymmetric.transaction.spi.AsymmetricCryptoCardTransactionManagerFactorySpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.transaction.spi.AsymmetricCryptoCardTransactionManagerSpi;
import org.eclipse.keypop.card.ApduResponseApi;
import org.eclipse.keypop.card.ChannelControl;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;
import org.junit.Before;
import org.junit.Test;

public class SecurePkiModeTransactionManagerAdapterTest extends AbstractTransactionManagerTest {

  private static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_PKI =
      "6F238409315449432E49434131A516BF0C13C708" + CARD_SERIAL_NUMBER + "53070A3C30051410019000";

  private static final byte CA_CERTIFICATE_TYPE = (byte) 0x90;
  private static final byte CARD_CERTIFICATE_TYPE = (byte) 0x91;
  private static final byte[] PCA_PUBLIC_KEY_REFERENCE =
      HexUtil.toByteArray("0BA000000291A0000101B0010000000000000000000000000000000002");
  private static final byte[] CA_PUBLIC_KEY_REFERENCE =
      HexUtil.toByteArray("0BA000000291A0010002B8010000000000000000000000000000000001");

  private static final String GET_DATA_CARD_CERTIFICATE_FIRST_PART = "00CADF4C00";
  private static final String GET_DATA_CARD_CERTIFICATE_NEXT_PART = "00CADF4D00";
  private static final String GET_DATA_CA_CERTIFICATE_FIRST_PART = "00CADF4A00";
  private static final String GET_DATA_CA_CERTIFICATE_NEXT_PART = "00CADF4B00";
  private static final String OPEN_SECURE_SESSION_PREFIX = "008A0003";
  private static final String READ_RECORD_SFI7_REC1 = "00B2013C1D";
  private static final String CLOSE_SECURE_SESSION = "008E000000";

  private static final String OPEN_SECURE_SESSION_RSP =
      "0BA0000002910E8405004301" + CARD_SERIAL_NUMBER + "00030DAC21215374BF00000000" + SW_9000;
  private static final String READ_RECORD_SFI7_REC1_RSP =
      "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D" + SW_9000;
  private static final String CLOSE_SECURE_SESSION_RSP =
      "4C084DBC2D6F233189AB5F3899EFC713318531A15A755275E2E769ABE212D395"
          + "22BAD5455F2380EB3FD72B9BA900F738956806A73025419D4C036D1D4B650C5E"
          + SW_9000;

  private SecurePkiModeTransactionManager cardTransactionManager;
  private AsymmetricCryptoSecuritySettingAdapter securitySetting;
  private AsymmetricCryptoCardTransactionManagerMock cryptoManager;
  private CaCertificateMock caCertificate;
  private final Map<String, String> cardResponses = new LinkedHashMap<>();
  private final List<List<String>> transmittedRequests = new ArrayList<>();
  private final List<ChannelControl> transmittedChannelControls = new ArrayList<>();

  interface AsymmetricCryptoCardTransactionManagerMock
      extends AsymmetricCryptoCardTransactionManagerSpi, CardTransactionCryptoExtension {}

  interface PcaCertificateMock extends PcaCertificate, PcaCertificateSpi {}

  interface CaCertificateMock extends CaCertificate, CaCertificateSpi {}

  interface CaCertificateParserMock extends CaCertificateParser, CaCertificateParserSpi {}

  interface CardCertificateParserMock extends CardCertificateParser, CardCertificateParserSpi {}

  @Override
  void initTransactionManager() {
    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecurePkiModeTransactionManager(cardReader, calypsoCard, securitySetting);
  }

  @Before
  public void setUp() throws Exception {
    cardReader = mock(ReaderMock.class);
    when(cardReader.transmitCardRequest(any(CardRequestSpi.class), any(ChannelControl.class)))
        .thenAnswer(
            invocation ->
                respond(
                    (CardRequestSpi) invocation.getArgument(0),
                    (ChannelControl) invocation.getArgument(1)));

    cryptoManager = mock(AsymmetricCryptoCardTransactionManagerMock.class);
    when(cryptoManager.isCardPkiSessionValid(any(byte[].class))).thenReturn(true);
    AsymmetricCryptoCardTransactionManagerFactorySpi cryptoManagerFactory =
        mock(AsymmetricCryptoCardTransactionManagerFactorySpi.class);
    when(cryptoManagerFactory.createCardTransactionManager()).thenReturn(cryptoManager);

    securitySetting = new AsymmetricCryptoSecuritySettingAdapter(cryptoManagerFactory);
    mockCertificates();

    cardResponses.put(GET_DATA_CARD_CERTIFICATE_FIRST_PART, getCardCertificateFirstPartRsp());
    cardResponses.put(GET_DATA_CARD_CERTIFICATE_NEXT_PART, getCardCertificateNextPartRsp());
    cardResponses.put(GET_DATA_CA_CERTIFICATE_FIRST_PART, getCaCertificateFirstPartRsp());
    cardResponses.put(GET_DATA_CA_CERTIFICATE_NEXT_PART, getCaCertificateNextPartRsp());
    cardResponses.put(OPEN_SECURE_SESSION_PREFIX, OPEN_SECURE_SESSION_RSP);
    cardResponses.put(READ_RECORD_SFI7_REC1, READ_RECORD_SFI7_REC1_RSP);
    cardResponses.put(CLOSE_SECURE_SESSION, CLOSE_SECURE_SESSION_RSP);

    initCalypsoCardAndTransactionManager(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_PKI);
  }

  private void mockCertificates() throws Exception {
    // PCA certificate (registered by the application)
    CaCertificateContentSpi pcaContent = mock(CaCertificateContentSpi.class);
    when(pcaContent.getPublicKeyReference()).thenReturn(PCA_PUBLIC_KEY_REFERENCE);
    PcaCertificateMock pcaCertificate = mock(PcaCertificateMock.class);
    when(pcaCertificate.checkCertificateAndGetContent()).thenReturn(pcaContent);
    securitySetting.addPcaCertificate(pcaCertificate);

    // CA certificate (stored in the card)
    CaCertificateContentSpi caContent = mock(CaCertificateContentSpi.class);
    when(caContent.getPublicKeyReference()).thenReturn(CA_PUBLIC_KEY_REFERENCE);
    caCertificate = mock(CaCertificateMock.class);
    when(caCertificate.getIssuerPublicKeyReference()).thenReturn(PCA_PUBLIC_KEY_REFERENCE);
    when(caCertificate.checkCertificateAndGetContent(pcaContent)).thenReturn(caContent);
    CaCertificateParserMock caCertificateParser = mock(CaCertificateParserMock.class);
    when(caCertificateParser.getCertificateType()).thenReturn(CA_CERTIFICATE_TYPE);
    when(caCertificateParser.parseCertificate(any(byte[].class))).thenReturn(caCertificate);
    securitySetting.addCaCertificateParser(caCertificateParser);

    // Card certificate (stored in the card)
    CardCertificateSpi cardCertificate = mock(CardCertificateSpi.class);
    when(cardCertificate.getCardSerialNumber()).thenReturn(HexUtil.toByteArray(CARD_SERIAL_NUMBER));
    when(cardCertificate.getIssuerPublicKeyReference()).thenReturn(CA_PUBLIC_KEY_REFERENCE);
    when(cardCertificate.checkCertificateAndGetPublicKey(caContent))
        .thenReturn(mock(CardPublicKeySpi.class));
    CardCertificateParserMock cardCertificateParser = mock(CardCertificateParserMock.class);
    when(cardCertificateParser.getCertificateType()).thenReturn(CARD_CERTIFICATE_TYPE);
    when(cardCertificateParser.parseCertificate(any(byte[].class))).thenReturn(cardCertificate);
    securitySetting.addCardCertificateParser(cardCertificateParser);
  }

  private static String getCertificateBytes(byte type, int size) {
    byte[] certificate = new byte[size];
    certificate[0] = type;
    return HexUtil.toHex(certificate);
  }

  // The card returns at most 250 data bytes per Get Data, starting with the 5-byte TLV header
  private static String getCardCertificateFirstPartRsp() {
    return ("DF4C82013C" + getCertificateBytes(CARD_CERTIFICATE_TYPE, 316)).substring(0, 500)
        + SW_9000;
  }

  private static String getCardCertificateNextPartRsp() {
    return ("DF4C82013C" + getCertificateBytes(CARD_CERTIFICATE_TYPE, 316)).substring(500)
        + SW_9000;
  }

  private static String getCaCertificateFirstPartRsp() {
    return ("DF4A820180" + getCertificateBytes(CA_CERTIFICATE_TYPE, 384)).substring(0, 500)
        + SW_9000;
  }

  private static String getCaCertificateNextPartRsp() {
    return ("DF4A820180" + getCertificateBytes(CA_CERTIFICATE_TYPE, 384)).substring(500) + SW_9000;
  }

  private TestDtoAdapters.CardResponseAdapter respond(
      CardRequestSpi cardRequest, ChannelControl channelControl) {
    List<String> requests = new ArrayList<>();
    List<ApduResponseApi> responses = new ArrayList<>();
    for (ApduRequestSpi apduRequest : cardRequest.getApduRequests()) {
      String apdu = HexUtil.toHex(apduRequest.getApdu());
      requests.add(apdu);
      String response = null;
      for (Map.Entry<String, String> entry : cardResponses.entrySet()) {
        if (apdu.startsWith(entry.getKey())) {
          response = entry.getValue();
          break;
        }
      }
      if (response == null) {
        throw new IllegalStateException("Unexpected APDU: " + apdu);
      }
      responses.add(new TestDtoAdapters.ApduResponseAdapter(HexUtil.toByteArray(response)));
    }
    transmittedRequests.add(requests);
    transmittedChannelControls.add(channelControl);
    return new TestDtoAdapters.CardResponseAdapter(responses, true);
  }

  private static List<String> batch(String... apdus) {
    return Arrays.asList(apdus);
  }

  private List<String> getTransmittedApdusStartingWith(String prefix) {
    List<String> apdus = new ArrayList<>();
    for (List<String> requests : transmittedRequests) {
      for (String apdu : requests) {
        if (apdu.startsWith(prefix)) {
          apdus.add(apdu);
        }
      }
    }
    return apdus;
  }

  private void verifyNoGetDataInTerminalSessionHash() throws Exception {
    verify(cryptoManager, never())
        .updateTerminalPkiSession(
            argThat(apdu -> apdu != null && HexUtil.toHex(apdu).startsWith("00CA")));
  }

  @Test
  public void
      processCommands_whenCaCertificateIsNotRegisteredAndSessionIsSplit_shouldReadCaCertificateBeforeOpening()
          throws Exception {

    cardTransactionManager
        .prepareOpenSecureSession()
        .processCommands(org.eclipse.keypop.reader.ChannelControl.KEEP_OPEN);
    cardTransactionManager
        .prepareReadRecords(FILE7, 1, 1, RECORD_SIZE)
        .processCommands(org.eclipse.keypop.reader.ChannelControl.KEEP_OPEN);
    cardTransactionManager
        .prepareCloseSecureSession()
        .processCommands(org.eclipse.keypop.reader.ChannelControl.CLOSE_AFTER);

    assertThat(transmittedRequests).hasSize(5);
    assertThat(transmittedRequests.get(0))
        .isEqualTo(
            batch(GET_DATA_CARD_CERTIFICATE_FIRST_PART, GET_DATA_CARD_CERTIFICATE_NEXT_PART));
    assertThat(transmittedRequests.get(1))
        .isEqualTo(batch(GET_DATA_CA_CERTIFICATE_FIRST_PART, GET_DATA_CA_CERTIFICATE_NEXT_PART));
    assertThat(transmittedRequests.get(2)).hasSize(1);
    assertThat(transmittedRequests.get(2).get(0)).startsWith(OPEN_SECURE_SESSION_PREFIX);
    assertThat(transmittedRequests.get(3)).isEqualTo(batch(READ_RECORD_SFI7_REC1));
    assertThat(transmittedRequests.get(4)).isEqualTo(batch(CLOSE_SECURE_SESSION));
    assertThat(transmittedChannelControls)
        .containsExactly(
            ChannelControl.KEEP_OPEN,
            ChannelControl.KEEP_OPEN,
            ChannelControl.KEEP_OPEN,
            ChannelControl.KEEP_OPEN,
            ChannelControl.CLOSE_AFTER);
    verifyNoGetDataInTerminalSessionHash();
    assertThat(securitySetting.getCaCertificate(CA_PUBLIC_KEY_REFERENCE)).isNotNull();
  }

  @Test
  public void
      processCommands_whenCaCertificateIsNotRegisteredAndSessionInOneCall_shouldReadCaCertificateBeforeOpening()
          throws Exception {

    cardTransactionManager
        .prepareOpenSecureSession()
        .prepareCloseSecureSession()
        .processCommands(org.eclipse.keypop.reader.ChannelControl.CLOSE_AFTER);

    assertThat(transmittedRequests).hasSize(3);
    assertThat(transmittedRequests.get(0))
        .isEqualTo(
            batch(GET_DATA_CARD_CERTIFICATE_FIRST_PART, GET_DATA_CARD_CERTIFICATE_NEXT_PART));
    assertThat(transmittedRequests.get(1))
        .isEqualTo(batch(GET_DATA_CA_CERTIFICATE_FIRST_PART, GET_DATA_CA_CERTIFICATE_NEXT_PART));
    assertThat(transmittedRequests.get(2)).hasSize(2);
    assertThat(transmittedRequests.get(2).get(0)).startsWith(OPEN_SECURE_SESSION_PREFIX);
    assertThat(transmittedRequests.get(2).get(1)).isEqualTo(CLOSE_SECURE_SESSION);
    assertThat(transmittedChannelControls)
        .containsExactly(
            ChannelControl.KEEP_OPEN, ChannelControl.KEEP_OPEN, ChannelControl.CLOSE_AFTER);
    verifyNoGetDataInTerminalSessionHash();
  }

  @Test
  public void processCommands_whenCaCertificateIsRegistered_shouldNotReadCaCertificate()
      throws Exception {
    securitySetting.addCaCertificate(caCertificate);

    cardTransactionManager
        .prepareOpenSecureSession()
        .processCommands(org.eclipse.keypop.reader.ChannelControl.KEEP_OPEN);
    cardTransactionManager
        .prepareCloseSecureSession()
        .processCommands(org.eclipse.keypop.reader.ChannelControl.CLOSE_AFTER);

    assertThat(getTransmittedApdusStartingWith("00CADF4A")).isEmpty();
    assertThat(transmittedRequests).hasSize(3);
    assertThat(transmittedRequests.get(0))
        .isEqualTo(
            batch(GET_DATA_CARD_CERTIFICATE_FIRST_PART, GET_DATA_CARD_CERTIFICATE_NEXT_PART));
    assertThat(transmittedRequests.get(1).get(0)).startsWith(OPEN_SECURE_SESSION_PREFIX);
    assertThat(transmittedRequests.get(2)).isEqualTo(batch(CLOSE_SECURE_SESSION));
  }

  @Test
  public void
      processCommands_whenCardCertificateIsAlreadyKnown_shouldNotSplitTheOpeningAndReadNoCertificate()
          throws Exception {
    cardTransactionManager
        .prepareOpenSecureSession()
        .prepareCloseSecureSession()
        .processCommands(org.eclipse.keypop.reader.ChannelControl.KEEP_OPEN);
    transmittedRequests.clear();
    transmittedChannelControls.clear();

    cardTransactionManager
        .prepareReadRecords(FILE7, 1, 1, RECORD_SIZE)
        .prepareOpenSecureSession()
        .prepareCloseSecureSession()
        .processCommands(org.eclipse.keypop.reader.ChannelControl.CLOSE_AFTER);

    assertThat(transmittedRequests).hasSize(1);
    assertThat(transmittedRequests.get(0)).hasSize(3);
    assertThat(transmittedRequests.get(0).get(0)).isEqualTo(READ_RECORD_SFI7_REC1);
    assertThat(transmittedRequests.get(0).get(1)).startsWith(OPEN_SECURE_SESSION_PREFIX);
    assertThat(transmittedRequests.get(0).get(2)).isEqualTo(CLOSE_SECURE_SESSION);
    assertThat(transmittedChannelControls).containsExactly(ChannelControl.CLOSE_AFTER);
  }

  @Test
  public void
      processCommands_whenCaCertificateIsPreparedByTheApplication_shouldReadCaCertificateOnlyOnce()
          throws Exception {

    cardTransactionManager
        .prepareGetData(GetDataTag.CA_CERTIFICATE)
        .prepareOpenSecureSession()
        .prepareCloseSecureSession()
        .processCommands(org.eclipse.keypop.reader.ChannelControl.CLOSE_AFTER);

    assertThat(getTransmittedApdusStartingWith("00CADF4A")).hasSize(1);
    assertThat(transmittedRequests).hasSize(2);
    assertThat(transmittedRequests.get(0))
        .isEqualTo(
            batch(
                GET_DATA_CA_CERTIFICATE_FIRST_PART,
                GET_DATA_CA_CERTIFICATE_NEXT_PART,
                GET_DATA_CARD_CERTIFICATE_FIRST_PART,
                GET_DATA_CARD_CERTIFICATE_NEXT_PART));
    assertThat(transmittedRequests.get(1).get(0)).startsWith(OPEN_SECURE_SESSION_PREFIX);
    assertThat(transmittedRequests.get(1).get(1)).isEqualTo(CLOSE_SECURE_SESSION);
    verifyNoGetDataInTerminalSessionHash();
  }
}
