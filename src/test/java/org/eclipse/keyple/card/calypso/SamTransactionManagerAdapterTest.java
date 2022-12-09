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
import static org.eclipse.keyple.card.calypso.DtoAdapters.*;
import static org.eclipse.keyple.card.calypso.TestDtoAdapters.*;
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
import org.calypsonet.terminal.calypso.transaction.BasicSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.BasicSignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.InvalidSignatureException;
import org.calypsonet.terminal.calypso.transaction.SamRevokedException;
import org.calypsonet.terminal.calypso.transaction.SamSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.SamTransactionManager;
import org.calypsonet.terminal.calypso.transaction.TraceableSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.TraceableSignatureVerificationData;
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
  private static final String CIPHER_MESSAGE = "A1A2A3A4A5A6A7A8";
  private static final String CIPHER_MESSAGE_SIGNATURE = "C1C2C3C4C5C6C7C8";
  private static final String CIPHER_MESSAGE_INCORRECT_SIGNATURE = "C1C2C3C4C5C6C7C9";
  private static final String CIPHER_MESSAGE_SIGNATURE_3_BYTES = "C1C2C3";
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
  private static final String C_DATA_CIPHER_DEFAULT = "801C40000A0102" + CIPHER_MESSAGE;
  private static final String R_DATA_CIPHER_DEFAULT = CIPHER_MESSAGE_SIGNATURE + R_9000;

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
      prepareComputeSignature_whenDataIsNotInstanceOfBasicSignatureComputationDataAdapterOrTraceableSignatureComputationDataAdapter_shouldThrowIAE() {
    TraceableSignatureComputationData data = mock(TraceableSignatureComputationData.class);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenMessageIsNull_shouldThrowIAE() {
    BasicSignatureComputationData data = new BasicSignatureComputationDataAdapter();
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenMessageIsNull_shouldThrowIAE() {
    TraceableSignatureComputationData data = new TraceableSignatureComputationDataAdapter();
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenMessageIsEmpty_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter().setData(new byte[0], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenMessageIsEmpty_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter().setData(new byte[0], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenMessageLengthIsGreaterThan208_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter().setData(new byte[209], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_PSO_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[207], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, true);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_PSO_whenNotTraceabilityModeAndMessageLengthIsGreaterThan208_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter().setData(new byte[209], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenMessageLengthIsNotMultipleOf8_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter().setData(new byte[15], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void prepareComputeSignature_Basic_whenMessageLengthIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter().setData(new byte[208], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);

    data.setData(new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);

    data.setData(new byte[16], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void prepareComputeSignature_PSO_whenMessageLengthIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter().setData(new byte[1], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);

    data.setData(new byte[208], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);

    data.setData(new byte[206], (byte) 1, (byte) 2).withSamTraceabilityMode(0, true);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenSignatureSizeIsLessThan1_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(0);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenSignatureSizeIsLessThan1_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(0);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenSignatureSizeIsGreaterThan8_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(9);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenSignatureSizeIsGreaterThan8_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(9);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void prepareComputeSignature_Basic_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[8], (byte) 1, (byte) 2)
            .setSignatureSize(1);
    samTransactionManager.prepareComputeSignature(data);

    data.setSignatureSize(8);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void prepareComputeSignature_PSO_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setSignatureSize(1);
    samTransactionManager.prepareComputeSignature(data);

    data.setSignatureSize(8);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenTraceabilityOffsetIsNegative_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(-1, true);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_PSO_whenPartialSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(3 * 8 + 1, true);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareComputeSignature_PSO_whenFullSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(2 * 8 + 1, false);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenTraceabilityOffsetIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, true);
    samTransactionManager.prepareComputeSignature(data);

    data.withSamTraceabilityMode(3 * 8, true);
    samTransactionManager.prepareComputeSignature(data);

    data.withSamTraceabilityMode(2 * 8, false);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenKeyDiversifierSizeIs0_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[0]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenKeyDiversifierSizeIs0_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[0]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_Basic_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[9]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareComputeSignature_PSO_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[9]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void
      prepareComputeSignature_Basic_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[1]);
    samTransactionManager.prepareComputeSignature(data);

    data.setKeyDiversifier(new byte[8]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
            .setData(new byte[10], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[1]);
    samTransactionManager.prepareComputeSignature(data);

    data.setKeyDiversifier(new byte[8]);
    samTransactionManager.prepareComputeSignature(data);
  }

  @Test(expected = IllegalStateException.class)
  public void prepareComputeSignature_Basic_whenTryToGetSignatureButNotProcessed_shouldThrowISE() {
    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter().setData(new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
    data.getSignature();
  }

  @Test(expected = IllegalStateException.class)
  public void prepareComputeSignature_PSO_whenTryToGetSignatureButNotProcessed_shouldThrowISE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter().setData(new byte[10], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
    data.getSignature();
  }

  @Test(expected = IllegalStateException.class)
  public void prepareComputeSignature_PSO_whenTryToGetSignedDataButNotProcessed_shouldThrowISE() {
    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter().setData(new byte[10], (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data);
    data.getSignedData();
  }

  @Test
  public void
      prepareComputeSignature_Basic_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier()
          throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureComputationData data =
        new TraceableSignatureComputationDataAdapter()
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
      prepareComputeSignature_Basic_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureComputationData data1 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2);
    BasicSignatureComputationData data2 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2);
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

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice()
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

    TraceableSignatureComputationData data1 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
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
      prepareComputeSignature_Basic_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_DATA_CIPHER_DEFAULT,
            C_SELECT_DIVERSIFIER,
            C_DATA_CIPHER_DEFAULT,
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000,
            R_DATA_CIPHER_DEFAULT,
            R_9000,
            R_DATA_CIPHER_DEFAULT,
            R_9000,
            R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureComputationData data1 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    BasicSignatureComputationData data2 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2);
    BasicSignatureComputationData data3 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2)
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

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
    assertThat(data3.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier()
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

    TraceableSignatureComputationData data1 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    TraceableSignatureComputationData data3 =
        new TraceableSignatureComputationDataAdapter()
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
      prepareComputeSignature_Basic_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureComputationData data1 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    BasicSignatureComputationData data2 =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2)
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

    assertThat(data1.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
    assertThat(data2.getSignature()).isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE));
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice()
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

    TraceableSignatureComputationData data1 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
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
  public void prepareComputeSignature_Basic_whenSignatureSizeIsLessThan8_shouldBeSuccessful()
      throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureComputationData data =
        new BasicSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(CIPHER_MESSAGE), (byte) 1, (byte) 2)
            .setSignatureSize(3); // Signature size = 3
    samTransactionManager.prepareComputeSignature(data).processCommands();

    InOrder inOrder = inOrder(samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(data.getSignature())
        .isEqualTo(HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE_3_BYTES));
  }

  @Test
  public void
      prepareComputeSignature_PSO_whenSamTraceabilityModePartialAndNotBusy_shouldBeSuccessful()
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

    TraceableSignatureComputationData data1 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2)
            .withSamTraceabilityMode(1, true)
            .withoutBusyMode();
    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
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
      prepareVerifySignature_whenDataIsNotInstanceOfBasicSignatureVerificationDataAdapterOrTraceableSignatureVerificationDataAdapter_shouldThrowIAE() {
    TraceableSignatureVerificationData data = mock(TraceableSignatureVerificationData.class);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenMessageIsNull_shouldThrowIAE() {
    BasicSignatureVerificationData data = new BasicSignatureVerificationDataAdapter();
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenMessageIsNull_shouldThrowIAE() {
    TraceableSignatureVerificationData data = new TraceableSignatureVerificationDataAdapter();
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenMessageIsEmpty_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[0], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenMessageIsEmpty_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[0], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenMessageLengthIsGreaterThan208_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[209], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_PSO_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[207], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, true, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_PSO_whenNotTraceabilityModeAndMessageLengthIsGreaterThan208_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[209], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenMessageLengthIsNotMultipleOf8_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[209], new byte[15], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_Basic_whenMessageLengthIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[208], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[8], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[16], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_PSO_whenMessageLengthIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[1], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[208], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[206], new byte[8], (byte) 1, (byte) 2)
        .withSamTraceabilityMode(0, true, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenSignatureIsNull_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter().setData(new byte[10], null, (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenSignatureIsNull_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], null, (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenSignatureSizeIsLessThan1_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[0], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenSignatureSizeIsLessThan1_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[0], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenSignatureSizeIsGreaterThan8_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[9], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenSignatureSizeIsGreaterThan8_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[9], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_Basic_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[8], new byte[1], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[8], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_PSO_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[1], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);

    data.setData(new byte[10], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenTraceabilityOffsetIsNegative_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(-1, true, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_PSO_whenPartialSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(3 * 8 + 1, true, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_PSO_whenFullSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(2 * 8 + 1, false, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void
      prepareVerifySignature_PSO_whenTraceabilityOffsetIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, true, false);
    samTransactionManager.prepareVerifySignature(data);

    data.withSamTraceabilityMode(3 * 8, true, false);
    samTransactionManager.prepareVerifySignature(data);

    data.withSamTraceabilityMode(2 * 8, false, false);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenKeyDiversifierSizeIs0_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[0]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenKeyDiversifierSizeIs0_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[0]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_Basic_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[9]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifySignature_PSO_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[9]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void
      prepareVerifySignature_Basic_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful() {

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[8], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[1]);
    samTransactionManager.prepareVerifySignature(data);

    data.setKeyDiversifier(new byte[8]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void
      prepareVerifySignature_PSO_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful() {

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .setKeyDiversifier(new byte[1]);
    samTransactionManager.prepareVerifySignature(data);

    data.setKeyDiversifier(new byte[8]);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = IllegalStateException.class)
  public void
      prepareVerifySignature_Basic_whenTryToCheckIfSignatureIsValidButNotAlreadyProcessed_shouldThrowISE() {
    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(new byte[8], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
    data.isSignatureValid();
  }

  @Test(expected = IllegalStateException.class)
  public void
      prepareVerifySignature_PSO_whenTryToCheckIfSignatureIsValidButNotAlreadyProcessed_shouldThrowISE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2);
    samTransactionManager.prepareVerifySignature(data);
    data.isSignatureValid();
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareVerifySignature_PSO_whenCheckSamRevocationStatusButNoServiceAvailable_shouldThrowIAE() {
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(new byte[10], new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(0, true, true);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void prepareVerifySignature_PSO_whenCheckSamRevocationStatusOK_shouldBeSuccessful() {
    SamRevocationServiceSpi samRevocationServiceSpi = mock(SamRevocationServiceSpi.class);
    when(samRevocationServiceSpi.isSamRevoked(HexUtil.toByteArray("B2B3B4"), 0xC5C6C7))
        .thenReturn(false);
    samSecuritySetting.setSamRevocationService(samRevocationServiceSpi);
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(8, true, true);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = SamRevokedException.class)
  public void prepareVerifySignature_PSO_whenCheckSamRevocationStatusKOPartial_shouldThrowSRE() {
    SamRevocationServiceSpi samRevocationServiceSpi = mock(SamRevocationServiceSpi.class);
    when(samRevocationServiceSpi.isSamRevoked(HexUtil.toByteArray("B2B3B4"), 0xB5B6B7))
        .thenReturn(true);
    samSecuritySetting.setSamRevocationService(samRevocationServiceSpi);
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(8, true, true);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test(expected = SamRevokedException.class)
  public void prepareVerifySignature_PSO_whenCheckSamRevocationStatusKOFull_shouldThrowSRE() {
    SamRevocationServiceSpi samRevocationServiceSpi = mock(SamRevocationServiceSpi.class);
    when(samRevocationServiceSpi.isSamRevoked(HexUtil.toByteArray("B2B3B4B5"), 0xB6B7B8))
        .thenReturn(true);
    samSecuritySetting.setSamRevocationService(samRevocationServiceSpi);
    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), new byte[8], (byte) 1, (byte) 2)
            .withSamTraceabilityMode(8, false, true);
    samTransactionManager.prepareVerifySignature(data);
  }

  @Test
  public void
      prepareVerifySignature_Basic_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier()
          throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
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
  public void
      prepareVerifySignature_PSO_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
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
  public void
      prepareVerifySignature_Basic_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data1 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    BasicSignatureVerificationData data2 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
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
      prepareVerifySignature_PSO_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureVerificationData data1 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    TraceableSignatureVerificationData data2 =
        new TraceableSignatureVerificationDataAdapter()
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
      prepareVerifySignature_Basic_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_DATA_CIPHER_DEFAULT,
            C_SELECT_DIVERSIFIER,
            C_DATA_CIPHER_DEFAULT,
            C_SELECT_DIVERSIFIER_SPECIFIC,
            C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(
            R_9000,
            R_DATA_CIPHER_DEFAULT,
            R_9000,
            R_DATA_CIPHER_DEFAULT,
            R_9000,
            R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data1 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    BasicSignatureVerificationData data2 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    BasicSignatureVerificationData data3 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
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
      prepareVerifySignature_PSO_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier()
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

    TraceableSignatureVerificationData data1 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    TraceableSignatureVerificationData data2 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    TraceableSignatureVerificationData data3 =
        new TraceableSignatureVerificationDataAdapter()
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
      prepareVerifySignature_Basic_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice()
          throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(
            C_SELECT_DIVERSIFIER_SPECIFIC, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse =
        createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data1 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    BasicSignatureVerificationData data2 =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
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
  public void
      prepareVerifySignature_PSO_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice()
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

    TraceableSignatureVerificationData data1 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .setKeyDiversifier(HexUtil.toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    TraceableSignatureVerificationData data2 =
        new TraceableSignatureVerificationDataAdapter()
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
  public void
      prepareVerifySignature_PSO_whenSamTraceabilityModePartialAndNotBusy_shouldBeSuccessful()
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

    TraceableSignatureVerificationData data1 =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2)
            .withSamTraceabilityMode(1, true, false)
            .withoutBusyMode();
    TraceableSignatureVerificationData data2 =
        new TraceableSignatureVerificationDataAdapter()
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
  public void prepareVerifySignature_Basic_whenSignatureIsValid_shouldUpdateOutputData()
      throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    samTransactionManager.prepareVerifySignature(data).processCommands();

    assertThat(data.isSignatureValid()).isTrue();
  }

  @Test
  public void
      prepareVerifySignature_Basic_whenSignatureIsValidWithSizeLessThan8_shouldUpdateOutputData()
          throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_SIGNATURE_3_BYTES),
                (byte) 1,
                (byte) 2);
    samTransactionManager.prepareVerifySignature(data).processCommands();

    assertThat(data.isSignatureValid()).isTrue();
  }

  @Test
  public void prepareVerifySignature_PSO_whenSignatureIsValid_shouldUpdateOutputData()
      throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_9000);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    samTransactionManager.prepareVerifySignature(data).processCommands();

    assertThat(data.isSignatureValid()).isTrue();
  }

  @Test
  public void
      prepareVerifySignature_Basic_whenSignatureIsInvalid_shouldThrowISEAndUpdateOutputData()
          throws Exception {

    CardRequestSpi cardRequest = createCardRequest(C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_DATA_CIPHER_DEFAULT);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    BasicSignatureVerificationData data =
        new BasicSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(CIPHER_MESSAGE),
                HexUtil.toByteArray(CIPHER_MESSAGE_INCORRECT_SIGNATURE),
                (byte) 1,
                (byte) 2);
    try {
      samTransactionManager.prepareVerifySignature(data).processCommands();
      shouldHaveThrown(InvalidSignatureException.class);
    } catch (InvalidSignatureException e) {
    }
    assertThat(data.isSignatureValid()).isFalse();
  }

  @Test
  public void prepareVerifySignature_PSO_whenSignatureIsInvalid_shouldThrowISEAndUpdateOutputData()
      throws Exception {

    CardRequestSpi cardRequest =
        createCardRequest(C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT);
    CardResponseApi cardResponse = createCardResponse(R_9000, R_INCORRECT_SIGNATURE);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    TraceableSignatureVerificationData data =
        new TraceableSignatureVerificationDataAdapter()
            .setData(
                HexUtil.toByteArray(PSO_MESSAGE),
                HexUtil.toByteArray(PSO_MESSAGE_SIGNATURE),
                (byte) 1,
                (byte) 2);
    try {
      samTransactionManager.prepareVerifySignature(data).processCommands();
      shouldHaveThrown(InvalidSignatureException.class);
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

    TraceableSignatureComputationData data1 =
        new TraceableSignatureComputationDataAdapter()
            .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
    samTransactionManager.prepareComputeSignature(data1).processCommands();

    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
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
      TraceableSignatureComputationData data1 =
          new TraceableSignatureComputationDataAdapter()
              .setData(HexUtil.toByteArray(PSO_MESSAGE), (byte) 1, (byte) 2);
      samTransactionManager.prepareComputeSignature(data1).processCommands();
      shouldHaveThrown(UnexpectedCommandStatusException.class);
    } catch (UnexpectedCommandStatusException e) {
    }

    TraceableSignatureComputationData data2 =
        new TraceableSignatureComputationDataAdapter()
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
