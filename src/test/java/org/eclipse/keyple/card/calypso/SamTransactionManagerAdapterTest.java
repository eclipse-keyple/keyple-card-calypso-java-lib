/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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
import static org.assertj.core.api.Assertions.shouldHaveThrown;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.spi.SamRevocationServiceSpi;
import org.calypsonet.terminal.calypso.transaction.InvalidSignatureException;
import org.calypsonet.terminal.calypso.transaction.SamRevokedException;
import org.calypsonet.terminal.calypso.transaction.SamSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.SamTransactionManager;
import org.calypsonet.terminal.calypso.transaction.SignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.SignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.UnexpectedCommandStatusException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardResponseApi;
import org.calypsonet.terminal.card.CardSelectionResponseApi;
import org.calypsonet.terminal.card.ChannelControl;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.calypsonet.terminal.reader.CardReader;
import org.eclipse.keyple.core.util.HexUtil;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.InOrder;

public class SamTransactionManagerAdapterTest {

  private static final String SAM_SERIAL_NUMBER = "11223344";
  private static final String PSO_MESSAGE = "A1A2A3A4A5A6A7A8A9AA";
  private static final String PSO_MESSAGE_SAM_TRACEABILITY = "B1B2B3B4B5B6B7B8B9BA";
  private static final String PSO_MESSAGE_SIGNATURE = "C1C2C3C4C5C6C7C8";
  private static final String SPECIFIC_KEY_DIVERSIFIER = "AABBCCDD";

  private static final String R_9000 = "9000";
  private static final String R_INCORRECT_SIGNATURE = "6988";

  private static final String SAM_C1_POWER_ON_DATA =
      "3B3F9600805A4880C1205017" + SAM_SERIAL_NUMBER + "82" + R_9000;

  private static final String C_SELECT_DIVERSIFIER = "8014000004" + SAM_SERIAL_NUMBER;
  private static final String C_SELECT_DIVERSIFIER_SPECIFIC =
      "8014000004" + SPECIFIC_KEY_DIVERSIFIER;

  private static final String C_PSO_COMPUTE_SIGNATURE_DEFAULT = "802A9E9A0EFF010288" + PSO_MESSAGE;
  private static final String R_PSO_COMPUTE_SIGNATURE_DEFAULT = PSO_MESSAGE_SIGNATURE + R_9000;

  private static final String C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL =
      "802A9E9A10FF0102480001" + PSO_MESSAGE;
  private static final String R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL =
      PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE + R_9000;

  private static final String C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL =
      "802A9E9A10FF0102680001" + PSO_MESSAGE;
  private static final String R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL =
      PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE + R_9000;

  private static final String C_PSO_VERIFY_SIGNATURE_DEFAULT =
      "802A00A816FF010288" + PSO_MESSAGE + PSO_MESSAGE_SIGNATURE;
  private static final String C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_PARTIAL =
      "802A00A818FF0102480001" + PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE;
  private static final String C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_FULL =
      "802A00A818FF0102680001" + PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE;

  private SamTransactionManager samTransactionManager;
  private ReaderMock samReader;
  private CalypsoSam sam;
  private SamSecuritySetting samSecuritySetting;

  interface ReaderMock extends CardReader, ProxyReaderApi {}

  @Before
  public void setUp() {

    samReader = mock(ReaderMock.class);

    CardSelectionResponseApi samCardSelectionResponse = mock(CardSelectionResponseApi.class);
    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);
    sam = new CalypsoSamAdapter(samCardSelectionResponse);

    ReaderMock controlSamReader = mock(ReaderMock.class);

    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);
    CalypsoSam controlSam = new CalypsoSamAdapter(samCardSelectionResponse);

    samSecuritySetting =
        CalypsoExtensionService.getInstance()
            .createSamSecuritySetting()
            .setControlSamResource(controlSamReader, controlSam);

    samTransactionManager =
        CalypsoExtensionService.getInstance()
            .createSamTransaction(samReader, sam, samSecuritySetting);
  }

  private CardRequestSpi createCardRequest(String... apduCommands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    for (String apduCommand : apduCommands) {
      apduRequests.add(new ApduRequestAdapter(HexUtil.toByteArray(apduCommand)));
    }
    return new CardRequestAdapter(apduRequests, false);
  }

  private CardResponseApi createCardResponse(String... apduCommandResponses) {
    List<ApduResponseApi> apduResponses = new ArrayList<ApduResponseApi>();
    for (String apduResponse : apduCommandResponses) {
      apduResponses.add(new ApduResponseAdapter(HexUtil.toByteArray(apduResponse)));
    }
    return new CardResponseAdapter(apduResponses, true);
  }

  private static class CardRequestMatcher implements ArgumentMatcher<CardRequestSpi> {
    List<ApduRequestSpi> leftApduRequests;

    CardRequestMatcher(CardRequestSpi cardRequest) {
      leftApduRequests = cardRequest.getApduRequests();
    }

    @Override
    public boolean matches(CardRequestSpi right) {
      if (right == null) {
        return false;
      }
      List<ApduRequestSpi> rightApduRequests = right.getApduRequests();
      if (leftApduRequests.size() != rightApduRequests.size()) {
        return false;
      }
      Iterator<ApduRequestSpi> itLeft = leftApduRequests.iterator();
      Iterator<ApduRequestSpi> itRight = rightApduRequests.iterator();
      while (itLeft.hasNext() && itRight.hasNext()) {
        byte[] leftApdu = itLeft.next().getApdu();
        byte[] rightApdu = itRight.next().getApdu();
        if (!Arrays.equals(leftApdu, rightApdu)) {
          return false;
        }
      }
      return true;
    }
  }

  @Test
  public void getSamReader_shouldReturnSamReader() {
    assertThat(samTransactionManager.getSamReader()).isSameAs(samReader);
  }

  @Test
  public void getCalypsoSam_shouldReturnCalypsoSam() {
    assertThat(samTransactionManager.getCalypsoSam()).isSameAs(sam);
  }

  @Test
  public void getSecuritySetting_shouldReturnSecuritySetting() {
    assertThat(samTransactionManager.getSecuritySetting()).isSameAs(samSecuritySetting);
  }

  @Test
  public void getTransactionAuditData_shouldReturnANotNullList() {
    assertThat(samTransactionManager.getTransactionAuditData()).isNotNull();
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_whenDataIsNull_shouldThrowIAE() {
    samTransactionManager.prepareComputeSignature(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_whenDataIsNotInstanceOfSignatureComputationDataAdapter_shouldThrowIAE() {
    SignatureComputationData data = mock(SignatureComputationData.class);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_whenMessageIsNull_shouldThrowIAE() {
    SignatureComputationData data = new SignatureComputationDataAdapter();
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_whenMessageIsEmpty_shouldThrowIAE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter().setData(new byte[0], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(new byte[207], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, true);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_whenNotTraceabilityModeAndMessageLengthIsGreaterThan208_shouldThrowIAE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter().setData(new byte[209], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void prepareComputeSignature_whenMessageLengthIsInCorrectRange_shouldBeSuccessful() {

    SignatureComputationData data =
        new SignatureComputationDataAdapter().setData(new byte[1], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);

    data.setData(new byte[208], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);

    data.setData(new byte[206], (byte) 1, (byte) 2).withSamTraceabilityMode(0, true);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_whenSignatureSizeIsLessThan1_shouldThrowIAE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(0);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_whenSignatureSizeIsGreaterThan8_shouldThrowIAE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(9);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void prepareComputeSignature_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful() {

    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(1);
    samTransactionManager.prepareComputeSignature(data);

    data.setSignatureSize(8);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_whenTraceabilityOffsetIsNegative_shouldThrowIAE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(-1, true);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_whenPartialSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(3 * 8 + 1, true);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_whenFullSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(2 * 8 + 1, false);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void prepareComputeSignature_whenTraceabilityOffsetIsInCorrectRange_shouldBeSuccessful() {

    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, true);
    samTransactionManager.prepareComputeSignature(data);

    data.withSamTraceabilityMode(3 * 8, true);
    samTransactionManager.prepareComputeSignature(data);

    data.withSamTraceabilityMode(2 * 8, false);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_whenKeyDiversifierSizeIs0_shouldThrowIAE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[0]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[9]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void prepareComputeSignature_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful() {

    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[1]);
    samTransactionManager.prepareComputeSignature(data);

    data.setKeyDiversifier(new byte[8]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalStateException.class)
  public void prepareComputeSignature_whenTryToGetSignatureButNotProcessed_shouldThrowISE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter().setData(new byte[10], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
    data.getSignature();
  }

  @Test(expected = IllegalStateException.class)
  public void prepareComputeSignature_whenTryToGetSignedDataButNotProcessed_shouldThrowISE() {
    SignatureComputationData data =
        new SignatureComputationDataAdapter().setData(new byte[10], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
    data.getSignedData();
  }

  @Test
  public void
      prepareComputeSignature_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureComputationData data =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
  }

  @Test
  public void
      prepareComputeSignature_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT, C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT, R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureComputationData data1 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    SignatureComputationData data2 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager
        .prepareComputeSignature(data1)
        .prepareComputeSignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data1.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data2.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
  }

  @Test
  public void
      prepareComputeSignature_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_COMPUTE_SIGNATURE_DEFAULT,
            C_SELECT_DIVERSIFIER,
            C_PSO_COMPUTE_SIGNATURE_DEFAULT,
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000,
            R_PSO_COMPUTE_SIGNATURE_DEFAULT,
            R_9000,
            R_PSO_COMPUTE_SIGNATURE_DEFAULT,
            R_9000,
            R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureComputationData data1 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    SignatureComputationData data2 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    SignatureComputationData data3 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareComputeSignature(data1)
        .prepareComputeSignature(data2)
        .prepareComputeSignature(data3)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data1.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data2.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
    assertThat(data3.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data3.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
  }

  @Test
  public void
      prepareComputeSignature_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_COMPUTE_SIGNATURE_DEFAULT,
            C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT, R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureComputationData data1 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    SignatureComputationData data2 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareComputeSignature(data1)
        .prepareComputeSignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data1.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data2.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE));
  }

  @Test
  public void prepareComputeSignature_whenSamTraceabilityModePartialAndNotBusy_shouldBeSuccessful()
      throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER,
            C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
            C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000,
            R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
            R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureComputationData data1 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .withSamTraceabilityMode(1, true)
            .withoutBusyMode();
    SignatureComputationData data2 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .withSamTraceabilityMode(1, false)
            .withoutBusyMode();
    samTransactionManager
        .prepareComputeSignature(data1)
        .prepareComputeSignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data1.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE));
    assertThat(data2.getSignedData()).isEqualTo(HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY));
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_whenDataIsNull_shouldThrowIAE() {
    samTransactionManager.prepareVerifySignature(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_whenDataIsNotInstanceOfSignatureVerificationDataAdapter_shouldThrowIAE() {
    SignatureVerificationData data = mock(SignatureVerificationData.class);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_whenMessageIsNull_shouldThrowIAE() {
    SignatureVerificationData data = new SignatureVerificationDataAdapter();
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_whenMessageIsEmpty_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[0], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[207], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, true, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_whenNotTraceabilityModeAndMessageLengthIsGreaterThan208_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[209], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_whenMessageLengthIsInCorrectRange_shouldBeSuccessful() {

    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[1], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[208], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[206], new byte[8], (byte) 1, (byte) 2)
        .withSamTraceabilityMode(0, true, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_whenSignatureIsNull_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter().setData(new byte[10], null, (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_whenSignatureSizeIsLessThan1_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[0], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_whenSignatureSizeIsGreaterThan8_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[9], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful() {

    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[1], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[10], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_whenTraceabilityOffsetIsNegative_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(-1, true, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_whenPartialSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(3 * 8 + 1, true, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_whenFullSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(2 * 8 + 1, false, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_whenTraceabilityOffsetIsInCorrectRange_shouldBeSuccessful() {

    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, true, false);
    samTransactionManager.prepareVerifySignature(data);

    data.withSamTraceabilityMode(3 * 8, true, false);
    samTransactionManager.prepareVerifySignature(data);

    data.withSamTraceabilityMode(2 * 8, false, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_whenKeyDiversifierSizeIs0_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[0]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[9]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful() {

    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[1]);
    samTransactionManager.prepareVerifySignature(data);

    data.setKeyDiversifier(new byte[8]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalStateException.class)
  public void
      prepareVerifySignature_whenTryToCheckIfSignatureIsValidButNotAlreadyProcessed_shouldThrowISE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
    data.isSignatureValid();
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_whenCheckSamRevocationStatusButNoServiceAvailable_shouldThrowIAE() {
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, true, true);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_whenCheckSamRevocationStatusOK_shouldBeSuccessful() {
    SamRevocationServiceSpi samRevocationServiceSpi = mock(SamRevocationServiceSpi.class);
    when(samRevocationServiceSpi.isSamRevoked(HexUtil.toByteArray("B2B3B4"), 0xC5C6C7))
        .thenReturn(false);
    samSecuritySetting.setSamRevocationService(samRevocationServiceSpi);
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(8, true, true);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = SamRevokedException.class)
  public void prepareVerifySignature_whenCheckSamRevocationStatusKOPartial_shouldThrow() {
    SamRevocationServiceSpi samRevocationServiceSpi = mock(SamRevocationServiceSpi.class);
    when(samRevocationServiceSpi.isSamRevoked(HexUtil.toByteArray("B2B3B4"), 0xB5B6B7))
        .thenReturn(true);
    samSecuritySetting.setSamRevocationService(samRevocationServiceSpi);
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(8, true, true);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = SamRevokedException.class)
  public void prepareVerifySignature_whenCheckSamRevocationStatusKOFull_shouldThrow() {
    SamRevocationServiceSpi samRevocationServiceSpi = mock(SamRevocationServiceSpi.class);
    when(samRevocationServiceSpi.isSamRevoked(HexUtil.toByteArray("B2B3B4B5"), 0xB6B7B8))
        .thenReturn(true);
    samSecuritySetting.setSamRevocationService(samRevocationServiceSpi);
    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(8, false, true);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void
      prepareVerifySignature_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    samTransactionManager.prepareVerifySignature(data).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void prepareVerifySignature_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice()
      throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureVerificationData data1 =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    SignatureVerificationData data2 =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    samTransactionManager
        .prepareVerifySignature(data1)
        .prepareVerifySignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void
      prepareVerifySignature_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_VERIFY_SIGNATURE_DEFAULT,
            C_SELECT_DIVERSIFIER,
            C_PSO_VERIFY_SIGNATURE_DEFAULT,
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(R_9000, R_9000, R_9000, R_9000, R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureVerificationData data1 =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    SignatureVerificationData data2 =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    SignatureVerificationData data3 =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareVerifySignature(data1)
        .prepareVerifySignature(data2)
        .prepareVerifySignature(data3)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void
      prepareVerifySignature_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_PSO_VERIFY_SIGNATURE_DEFAULT,
            C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureVerificationData data1 =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    SignatureVerificationData data2 =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager
        .prepareVerifySignature(data1)
        .prepareVerifySignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void prepareVerifySignature_whenSamTraceabilityModePartialAndNotBusy_shouldBeSuccessful()
      throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER,
            C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
            C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_FULL);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureVerificationData data1 =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .withSamTraceabilityMode(1, true, false)
            .withoutBusyMode();
    SignatureVerificationData data2 =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .withSamTraceabilityMode(1, false, false)
            .withoutBusyMode();
    samTransactionManager
        .prepareVerifySignature(data1)
        .prepareVerifySignature(data2)
        .processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void prepareVerifySignature_whenSignatureIsValid_shouldUpdateOutputData()
      throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    samTransactionManager.prepareVerifySignature(data).processCommands();

    assertThat(data.isSignatureValid()).isTrue();
  }

  @Test
  public void prepareVerifySignature_whenSignatureIsInvalid_shouldThrowISEAndUpdateOutputData()
      throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_INCORRECT_SIGNATURE);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    SignatureVerificationData data =
        new SignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    try {
      samTransactionManager.prepareVerifySignature(data).processCommands();
      shouldHaveThrown(UnexpectedCommandStatusException.class);
    } catch (InvalidSignatureException e) {
    }
    assertThat(data.isSignatureValid()).isFalse();
  }

  @Test
  public void processCommands_whenNoError_shouldClearCommandList() throws Exception {

    CardRequestSpi cardRequest1 =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse1 = createCardResponse(R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    CardRequestSpi cardRequest2 = createCardRequest(C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse2 = createCardResponse(R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest1)), any(ChannelControl.class)))
        .thenReturn(cardResponse1);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest2)), any(ChannelControl.class)))
        .thenReturn(cardResponse2);

    SignatureComputationData data1 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data1).processCommands();

    SignatureComputationData data2 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data2).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest1)), any(ChannelControl.class));
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest2)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }

  @Test
  public void processCommands_whenError_shouldClearCommandList() throws Exception {

    CardRequestSpi cardRequest1 =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse1 = createCardResponse(R_9000, R_INCORRECT_SIGNATURE);

    CardRequestSpi cardRequest2 = createCardRequest(C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse2 = createCardResponse(R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest1)), any(ChannelControl.class)))
        .thenReturn(cardResponse1);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest2)), any(ChannelControl.class)))
        .thenReturn(cardResponse2);

    try {
      SignatureComputationData data1 =
          new SignatureComputationDataAdapter()
              .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
      samTransactionManager.prepareComputeSignature(data1).processCommands();
      shouldHaveThrown(UnexpectedCommandStatusException.class);
    } catch (UnexpectedCommandStatusException e) {
    }

    SignatureComputationData data2 =
        new SignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data2).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest1)), any(ChannelControl.class));
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest2)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);
  }
}
