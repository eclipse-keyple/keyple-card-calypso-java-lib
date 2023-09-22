/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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
import static org.eclipse.keyple.card.calypso.TestDtoAdapters.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.util.*;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.GetDataTag;
import org.eclipse.keypop.calypso.card.SelectFileControl;
import org.eclipse.keypop.calypso.card.WriteAccessLevel;
import org.eclipse.keypop.calypso.card.card.CalypsoCard;
import org.eclipse.keypop.calypso.card.card.ElementaryFile;
import org.eclipse.keypop.calypso.card.card.FileHeader;
import org.eclipse.keypop.calypso.card.transaction.*;
import org.eclipse.keypop.calypso.card.transaction.spi.CardTransactionCryptoExtension;
import org.eclipse.keypop.calypso.card.transaction.spi.SymmetricCryptoTransactionManagerFactory;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoIOException;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoTransactionManagerFactorySpi;
import org.eclipse.keypop.calypso.crypto.symmetric.spi.SymmetricCryptoTransactionManagerSpi;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.card.ChannelControl;
import org.eclipse.keypop.card.spi.CardRequestSpi;
import org.eclipse.keypop.reader.CardReader;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.InOrder;

public class SecureExtendedModeTransactionManagerAdapterTest extends AbstractTransactionManager {

  private SecureExtendedModeTransactionManager cardTransactionManager;
  private ReaderMock cardReader;
  private CalypsoCardAdapter calypsoCard;
  private SymmetricCryptoSecuritySetting cardSecuritySetting;
  private SymmetricCryptoTransactionManagerFactoryMock symmetricCryptoTransactionManagerFactory;
  private SymmetricCryptoTransactionManagerMock symmetricCryptoTransactionManager;

  interface ReaderMock extends CardReader, ProxyReaderApi {}

  interface SymmetricCryptoTransactionManagerFactoryMock
      extends SymmetricCryptoTransactionManagerFactory,
          SymmetricCryptoTransactionManagerFactorySpi {}

  interface SymmetricCryptoTransactionManagerMock
      extends SymmetricCryptoTransactionManagerSpi, CardTransactionCryptoExtension {}

  private void initCalypsoCard(String selectApplicationResponse) throws Exception {
    calypsoCard =
        spy(
            new CalypsoCardAdapter(
                new CardSelectionResponseAdapter(
                    new ApduResponseAdapter(HexUtil.toByteArray(selectApplicationResponse)))));
    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);
  }

  private void initCalypsoCard(String selectApplicationResponse, int modificationsCounter)
      throws Exception {
    calypsoCard =
        spy(
            new CalypsoCardAdapter(
                new CardSelectionResponseAdapter(
                    new ApduResponseAdapter(HexUtil.toByteArray(selectApplicationResponse)))));
    when(calypsoCard.getModificationsCounter()).thenReturn(modificationsCounter);
    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);
  }

  private void verifyInteractionsForSingleCardCommand(CardRequestSpi cardCardRequest)
      throws ReaderBrokenCommunicationException, CardBrokenCommunicationException,
          UnexpectedStatusWordException, SymmetricCryptoException, SymmetricCryptoIOException {
    InOrder inOrder = inOrder(cardReader, symmetricCryptoTransactionManager);
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Before
  public void setUp() throws Exception {
    cardReader = mock(ReaderMock.class);

    symmetricCryptoTransactionManager = mock(SymmetricCryptoTransactionManagerMock.class);

    symmetricCryptoTransactionManagerFactory =
        mock(SymmetricCryptoTransactionManagerFactoryMock.class);

    when(symmetricCryptoTransactionManagerFactory.getMaxCardApduLengthSupported()).thenReturn(250);
    when(symmetricCryptoTransactionManagerFactory.isExtendedModeSupported()).thenReturn(true);
    when(symmetricCryptoTransactionManagerFactory.createTransactionManager(
            eq(CARD_SERIAL_NUMBER), eq(false), ArgumentMatchers.<byte[]>anyList()))
        .thenReturn(symmetricCryptoTransactionManager);

    cardSecuritySetting =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSymmetricCryptoSecuritySetting(symmetricCryptoTransactionManagerFactory);

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3);
  }

  @Test
  public void
      prepareSelectFile_whenLidIs1234AndCardIsPrimeRevision3_shouldPrepareSelectFileApduWith1234()
          throws Exception {
    short lid = 0x1234;
    CardRequestSpi cardCardRequest = createCardRequest(CARD_SELECT_FILE_1234_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SELECT_FILE_1234_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSelectFile(lid);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test
  public void
      prepareSelectFile_whenLidIs1234AndCardIsPrimeRevision2_shouldPrepareSelectFileApduWith1234()
          throws Exception {
    short lid = 0x1234;
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_SELECT_FILE_1234_CMD_PRIME_REV2);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SELECT_FILE_1234_RSP_PRIME_REV2);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSelectFile(lid);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test
  public void
      prepareSelectFile_whenSelectFileControlIsFirstEF_shouldPrepareSelectFileApduWithP2_02_P1_00()
          throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_SELECT_FILE_FIRST_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SELECT_FILE_1234_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSelectFile(SelectFileControl.FIRST_EF);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test
  public void
      prepareSelectFile_whenSelectFileControlIsNextEF_shouldPrepareSelectFileApduWithP2_02_P1_02()
          throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_SELECT_FILE_NEXT_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SELECT_FILE_1234_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSelectFile(SelectFileControl.NEXT_EF);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test
  public void
      prepareSelectFile_whenSelectFileControlIsCurrentEF_shouldPrepareSelectFileApduWithP2_09_P1_00()
          throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_SELECT_FILE_CURRENT_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SELECT_FILE_1234_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSelectFile(SelectFileControl.CURRENT_DF);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareGetData_whenGetDataTagIsNull_shouldThrowIAE() {
    cardTransactionManager.prepareGetData(null);
  }

  @Test
  public void prepareGetData_whenGetDataTagIsFCP_shouldPrepareSelectFileApduWithTagFCP()
      throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_GET_DATA_FCP_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_GET_DATA_FCP_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareGetData(GetDataTag.FCP_FOR_CURRENT_FILE);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test
  public void prepareGetData_whenGetDataTagIsEF_LIST_shouldPopulateCalypsoCard() throws Exception {
    // EF LIST
    // C028
    // C106 2001 07 02 1D 01
    // C106 20FF 09 01 1D 04
    // C106 F123 10 04 F3 F4
    // C106 F124 11 08 F3 F4
    // C106 F125 1F 09 F3 F4
    CardRequestSpi cardCardRequest = createCardRequest(CARD_GET_DATA_EF_LIST_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_GET_DATA_EF_LIST_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    assertThat(calypsoCard.getFiles()).isEmpty();

    cardTransactionManager.prepareGetData(GetDataTag.EF_LIST);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFiles()).hasSize(5);

    FileHeader fileHeader07 = calypsoCard.getFileBySfi((byte) 0x07).getHeader();
    assertThat(fileHeader07.getLid()).isEqualTo((short) 0x2001);
    assertThat(fileHeader07.getEfType()).isEqualTo(ElementaryFile.Type.LINEAR);
    assertThat(fileHeader07.getRecordSize()).isEqualTo(0x1D);
    assertThat(fileHeader07.getRecordsNumber()).isEqualTo(0x01);

    FileHeader fileHeader09 = calypsoCard.getFileBySfi((byte) 0x09).getHeader();
    assertThat(fileHeader09.getLid()).isEqualTo((short) 0x20FF);
    assertThat(fileHeader09.getEfType()).isEqualTo(ElementaryFile.Type.BINARY);
    assertThat(fileHeader09.getRecordSize()).isEqualTo(0x1D);
    assertThat(fileHeader09.getRecordsNumber()).isEqualTo(0x04);

    FileHeader fileHeader10 = calypsoCard.getFileBySfi((byte) 0x10).getHeader();
    assertThat(fileHeader10.getLid()).isEqualTo((short) 0xF123);
    assertThat(fileHeader10.getEfType()).isEqualTo(ElementaryFile.Type.CYCLIC);
    assertThat(fileHeader10.getRecordSize()).isEqualTo((byte) 0xF3);
    assertThat(fileHeader10.getRecordsNumber()).isEqualTo((byte) 0xF4);

    FileHeader fileHeader11 = calypsoCard.getFileBySfi((byte) 0x11).getHeader();
    assertThat(fileHeader11.getLid()).isEqualTo((short) 0xF124);
    assertThat(fileHeader11.getEfType()).isEqualTo(ElementaryFile.Type.SIMULATED_COUNTERS);
    assertThat(fileHeader11.getRecordSize()).isEqualTo((byte) 0xF3);
    assertThat(fileHeader11.getRecordsNumber()).isEqualTo((byte) 0xF4);

    FileHeader fileHeader1F = calypsoCard.getFileBySfi((byte) 0x1F).getHeader();
    assertThat(fileHeader1F.getLid()).isEqualTo((short) 0xF125);
    assertThat(fileHeader1F.getEfType()).isEqualTo(ElementaryFile.Type.COUNTERS);
    assertThat(fileHeader1F.getRecordSize()).isEqualTo((byte) 0xF3);
    assertThat(fileHeader1F.getRecordsNumber()).isEqualTo((byte) 0xF4);

    assertThat(calypsoCard.getFileByLid((short) 0x20FF))
        .isEqualTo(calypsoCard.getFileBySfi((byte) 0x09));
  }

  @Test
  public void prepareGetData_whenGetDataTagIsTRACEABILITY_INFORMATION_shouldPopulateCalypsoCard()
      throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_GET_DATA_TRACEABILITY_INFORMATION_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_GET_DATA_TRACEABILITY_INFORMATION_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareGetData(GetDataTag.TRACEABILITY_INFORMATION);

    assertThat(calypsoCard.getTraceabilityInformation()).isEmpty();

    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getTraceabilityInformation())
        .isEqualTo(HexUtil.toByteArray("00112233445566778899"));
  }

  @Test
  public void prepareGetData_whenGetDataTagIsFCI_shouldPrepareSelectFileApduWithTagFCI()
      throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_GET_DATA_FCI_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_GET_DATA_FCI_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareGetData(GetDataTag.FCI_FOR_CURRENT_DF);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecord_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecord((byte) 31, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecord_whenRecordNumberIsLessThan0_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecord(FILE7, -1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecord_whenRecordNumberIsMoreThan250_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecord(FILE7, 251);
  }

  @Test
  public void prepareReadRecord_whenSfi07RecNumber1_shouldPrepareReadRecordApduWithSfi07RecNumber1()
      throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_READ_REC_SFI7_REC1_CMD_HEX);
    CardResponseApi cardCardResponse = createCardResponse(CARD_READ_REC_SFI7_REC1_RSP_HEX);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareReadRecord(FILE7, 1);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecords_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecords((byte) 31, 1, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecords_whenFromRecordNumberIs0_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecords(FILE7, 0, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecords_whenFromRecordNumberIsGreaterThan250_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecords(FILE7, 251, 251, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecords_whenToRecordNumberIsLessThanFromRecordNumber_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecords(FILE7, 2, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecords_whenToRecordNumberIsGreaterThan250_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecords(FILE7, 1, 251, 1);
  }

  @Test
  public void
      prepareReadRecords_whenNbRecordsToReadMultipliedByRecSize2IsLessThanPayLoad_shouldPrepareOneCommand()
          throws Exception {

    CardRequestSpi cardCardRequest = createCardRequest(CARD_READ_RECORDS_FROM1_TO2_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_READ_RECORDS_FROM1_TO2_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(7);

    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareReadRecords((byte) 1, 1, 2, 1);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(1))
        .isEqualTo(HexUtil.toByteArray("11"));
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(2))
        .isEqualTo(HexUtil.toByteArray("22"));
  }

  @Test
  public void
      prepareReadRecords_whenNbRecordsToReadMultipliedByRecSize2IsGreaterThanPayLoad_shouldPrepareMultipleCommands()
          throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_READ_RECORDS_FROM1_TO2_CMD,
            CARD_READ_RECORDS_FROM3_TO4_CMD,
            CARD_READ_RECORDS_FROM5_TO5_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(
            CARD_READ_RECORDS_FROM1_TO2_RSP,
            CARD_READ_RECORDS_FROM3_TO4_RSP,
            CARD_READ_RECORDS_FROM5_TO5_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(7);

    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareReadRecords((byte) 1, 1, 5, 1);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(1))
        .isEqualTo(HexUtil.toByteArray("11"));
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(2))
        .isEqualTo(HexUtil.toByteArray("22"));
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(3))
        .isEqualTo(HexUtil.toByteArray("33"));
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(4))
        .isEqualTo(HexUtil.toByteArray("44"));
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(5))
        .isEqualTo(HexUtil.toByteArray("55"));
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareReadRecordsPartially_whenProductTypeIsNotPrimeRev3OrLight_shouldThrowUOE()
      throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2);
    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 1, 1, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordsPartially_whenSfiIsNegative_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordsPartially((byte) -1, 1, 1, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordsPartially_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordsPartially((byte) 31, 1, 1, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordsPartially_whenFromRecordNumberIsZero_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 0, 1, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordsPartially_whenFromRecordNumberGreaterThan250_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 251, 251, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareReadRecordsPartially_whenToRecordNumberLessThanFromRecordNumber_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 2, 1, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareReadRecordsPartially_whenToRecordNumberGreaterThan250MinusFromRecordNumber_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 1, 251, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordsPartially_whenOffsetIsNegative_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 1, 1, -1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordsPartially_whenOffsetGreaterThan249_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 1, 1, 250, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordsPartially_whenNbBytesToReadIsZero_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 1, 1, 1, 0);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareReadRecordsPartially_whenNbBytesToReadIsGreaterThan250MinusOffset_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 1, 1, 3, 248);
  }

  @Test
  public void
      prepareReadRecordsPartially_whenNbRecordsToReadMultipliedByNbBytesToReadIsLessThanPayLoad_shouldPrepareOneCommand()
          throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(3);

    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 1, 2, 3, 1);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(1))
        .isEqualTo(HexUtil.toByteArray("00000011"));
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(2))
        .isEqualTo(HexUtil.toByteArray("00000022"));
  }

  @Test
  public void
      prepareReadRecordsPartially_whenNbRecordsToReadMultipliedByNbBytesToReadIsGreaterThanPayLoad_shouldPrepareMultipleCommands()
          throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_CMD,
            CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NBBYTE1_CMD,
            CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NBBYTE1_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(
            CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_RSP,
            CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NBBYTE1_RSP,
            CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NBBYTE1_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(2);

    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 1, 5, 3, 1);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(1))
        .isEqualTo(HexUtil.toByteArray("00000011"));
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(2))
        .isEqualTo(HexUtil.toByteArray("00000022"));
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(3))
        .isEqualTo(HexUtil.toByteArray("00000033"));
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(4))
        .isEqualTo(HexUtil.toByteArray("00000044"));
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent(5))
        .isEqualTo(HexUtil.toByteArray("00000055"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenSfiIsNegative_shouldThrowIAE() {
    cardTransactionManager.prepareReadBinary((byte) -1, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareReadBinary((byte) 31, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenOffsetIsNegative_shouldThrowIAE() {
    cardTransactionManager.prepareReadBinary((byte) 1, -1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE() {
    cardTransactionManager.prepareReadBinary((byte) 1, 32768, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenNbBytesToReadIsLessThan1_shouldThrowIAE() {
    cardTransactionManager.prepareReadBinary((byte) 1, 1, 0);
  }

  @Test
  public void
      prepareReadBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand()
          throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD, CARD_READ_BINARY_SFI0_OFFSET256_1B_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(
            CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP, CARD_READ_BINARY_SFI0_OFFSET256_1B_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.prepareReadBinary((byte) 1, 256, 1);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent())
        .startsWith(HexUtil.toByteArray("1100"))
        .endsWith(HexUtil.toByteArray("0066"))
        .hasSize(257);
  }

  @Test
  public void prepareReadBinary_whenNbBytesToReadIsLessThanPayLoad_shouldPrepareOneCommand()
      throws Exception {

    CardRequestSpi cardCardRequest = createCardRequest(CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(2);

    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);
    cardTransactionManager.prepareReadBinary((byte) 1, 0, 1);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent())
        .isEqualTo(HexUtil.toByteArray("11"));
  }

  @Test
  public void
      prepareReadBinary_whenNbBytesToReadIsGreaterThanPayLoad_shouldPrepareMultipleCommands()
          throws Exception {

    CardRequestSpi cardCardRequest = createCardRequest(CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(2);

    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareReadBinary((byte) 1, 0, 1);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent())
        .isEqualTo(HexUtil.toByteArray("11"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadCounter_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareReadCounter((byte) 31, 1);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareSearchRecords_whenProductTypeIsNotPrimeRev3_shouldThrowUOE() throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2);
    cardTransactionManager.prepareSearchRecords(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenDataIsNull_shouldThrowIAE() {
    cardTransactionManager.prepareSearchRecords(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenDataIsNotInstanceOfInternalAdapter_shouldThrowIAE() {
    cardTransactionManager.prepareSearchRecords(
        new SearchCommandData() {
          @Override
          public SearchCommandData setSfi(byte sfi) {
            return null;
          }

          @Override
          public SearchCommandData startAtRecord(int recordNumber) {
            return null;
          }

          @Override
          public SearchCommandData setOffset(int offset) {
            return null;
          }

          @Override
          public SearchCommandData enableRepeatedOffset() {
            return null;
          }

          @Override
          public SearchCommandData setSearchData(byte[] data) {
            return null;
          }

          @Override
          public SearchCommandData setMask(byte[] mask) {
            return null;
          }

          @Override
          public SearchCommandData fetchFirstMatchingResult() {
            return null;
          }

          @Override
          public List<Integer> getMatchingRecordNumbers() {
            return null;
          }
        });
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenSfiIsNegative_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setSfi((byte) -1)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenSfiGreaterThanSfiMax_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setSfi((byte) 31)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenRecordNumberIs0_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .startAtRecord(0)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenRecordNumberIsGreaterThan250_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .startAtRecord(251)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenOffsetIsNegative_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setOffset(-1)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenOffsetIsGreaterThan249_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setOffset(250)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenSearchDataIsNotSet_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance().getCalypsoCardApiFactory().createSearchCommandData();
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenSearchDataIsNull_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setSearchData(null);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenSearchDataIsEmpty_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setSearchData(new byte[0]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareSearchRecords_whenSearchDataLengthIsGreaterThan250MinusOffset0_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setSearchData(new byte[251]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareSearchRecords_whenSearchDataLengthIsGreaterThan249MinusOffset1_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setOffset(1)
            .setSearchData(new byte[250]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenMaskLengthIsGreaterThanSearchDataLength_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setSearchData(new byte[1])
            .setMask(new byte[2]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test
  public void prepareSearchRecords_whenUsingDefaultParameters_shouldPrepareDefaultCommand()
      throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setSearchData(new byte[] {0x12, 0x34});
    cardTransactionManager.prepareSearchRecords(data);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(data.getMatchingRecordNumbers()).containsExactly(4, 6);
  }

  @Test
  public void prepareSearchRecords_whenSetAllParameters_shouldPrepareCustomCommand()
      throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setSfi((byte) 4)
            .startAtRecord(2)
            .setOffset(3)
            .enableRepeatedOffset()
            .setSearchData(new byte[] {0x12, 0x34})
            .fetchFirstMatchingResult();
    cardTransactionManager.prepareSearchRecords(data);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(data.getMatchingRecordNumbers()).containsExactly(4, 6);
    assertThat(calypsoCard.getFileBySfi((byte) 4).getData().getContent(4))
        .isEqualTo(HexUtil.toByteArray("112233123456"));
  }

  @Test
  public void prepareSearchRecords_whenNoMask_shouldFillMaskWithFFh() throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setSearchData(new byte[] {0x12, 0x34});
    cardTransactionManager.prepareSearchRecords(data);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(data.getMatchingRecordNumbers()).containsExactly(4, 6);
  }

  @Test
  public void prepareSearchRecords_whenPartialMask_shouldRightPadMaskWithFFh() throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_56FF_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_56FF_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setSearchData(new byte[] {0x12, 0x34})
            .setMask(new byte[] {0x56});
    cardTransactionManager.prepareSearchRecords(data);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(data.getMatchingRecordNumbers()).containsExactly(4, 6);
  }

  @Test
  public void prepareSearchRecords_whenFullMask_shouldUseCompleteMask() throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_5677_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_5677_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSearchCommandData()
            .setSearchData(new byte[] {0x12, 0x34})
            .setMask(new byte[] {0x56, 0x77});
    cardTransactionManager.prepareSearchRecords(data);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(data.getMatchingRecordNumbers()).containsExactly(4, 6);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareCheckPinStatus_whenPinFeatureIsNotAvailable_shouldThrowISE() {
    cardTransactionManager.prepareCheckPinStatus();
  }

  @Test
  public void prepareCheckPinStatus_whenPinFeatureIsAvailable_shouldPrepareCheckPinStatusApdu()
      throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_CHECK_PIN_CMD);
    CardResponseApi cardCardResponse = createCardResponse(SW1SW2_OK);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareCheckPinStatus();
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareAppendRecord_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareAppendRecord((byte) 31, new byte[3]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareAppendRecord_whenRecordDataIsNull_shouldThrowIAE() {
    cardTransactionManager.prepareAppendRecord(FILE7, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateRecord_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateRecord((byte) 31, 1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateRecord_whenRecordNumberIsGreaterThan250_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateRecord(FILE7, 251, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateRecord_whenRecordDataIsNull_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateRecord(FILE7, 1, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteRecord_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareWriteRecord((byte) 31, 1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteRecord_whenRecordNumberIsGreaterThan250_shouldThrowIAE() {
    cardTransactionManager.prepareWriteRecord(FILE7, 251, new byte[1]);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareUpdateBinary_whenProductTypeIsNotPrimeRev2OrRev3_shouldThrowUOE()
      throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_LIGHT);
    cardTransactionManager.prepareUpdateBinary((byte) 1, 1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateBinary_whenSfiIsNegative_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateBinary((byte) -1, 1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateBinary_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateBinary((byte) 31, 1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateBinary_whenOffsetIsNegative_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateBinary((byte) 1, -1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateBinary((byte) 1, 32768, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateBinary_whenDataIsNull_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateBinary((byte) 1, 1, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateBinary_whenDataIsEmpty_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateBinary((byte) 1, 1, new byte[0]);
  }

  @Test
  public void
      prepareUpdateBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand()
          throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD, CARD_UPDATE_BINARY_SFI0_OFFSET256_1B_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP, SW1SW2_OK_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.prepareUpdateBinary((byte) 1, 256, HexUtil.toByteArray("66"));
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test
  public void prepareUpdateBinary_whenDataLengthIsLessThanPayLoad_shouldPrepareOneCommand()
      throws Exception {

    CardRequestSpi cardCardRequest = createCardRequest(CARD_UPDATE_BINARY_SFI1_OFFSET4_1B_CMD);
    CardResponseApi cardCardResponse = createCardResponse(SW1SW2_OK_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(2);

    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareUpdateBinary((byte) 1, 4, HexUtil.toByteArray("55"));
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent())
        .isEqualTo(HexUtil.toByteArray("0000000055"));
  }

  @Test
  public void prepareUpdateBinary_whenDataLengthIsGreaterThanPayLoad_shouldPrepareMultipleCommands()
      throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_UPDATE_BINARY_SFI1_OFFSET0_2B_CMD,
            CARD_UPDATE_BINARY_SFI1_OFFSET2_2B_CMD,
            CARD_UPDATE_BINARY_SFI1_OFFSET4_1B_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(SW1SW2_OK_RSP, SW1SW2_OK_RSP, SW1SW2_OK_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(2);

    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareUpdateBinary((byte) 1, 0, HexUtil.toByteArray("1122334455"));
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent())
        .isEqualTo(HexUtil.toByteArray("1122334455"));
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareWriteBinary_whenProductTypeIsNotPrimeRev2OrRev3_shouldThrowUOE()
      throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_LIGHT);
    cardTransactionManager.prepareWriteBinary((byte) 1, 1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteBinary_whenSfiIsNegative_shouldThrowIAE() {
    cardTransactionManager.prepareWriteBinary((byte) -1, 1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteBinary_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareWriteBinary((byte) 31, 1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteBinary_whenOffsetIsNegative_shouldThrowIAE() {
    cardTransactionManager.prepareWriteBinary((byte) 1, -1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE() {
    cardTransactionManager.prepareWriteBinary((byte) 1, 32768, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteBinary_whenDataIsNull_shouldThrowIAE() {
    cardTransactionManager.prepareWriteBinary((byte) 1, 1, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteBinary_whenDataIsEmpty_shouldThrowIAE() {
    cardTransactionManager.prepareWriteBinary((byte) 1, 1, new byte[0]);
  }

  @Test
  public void
      prepareWriteBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand()
          throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD, CARD_WRITE_BINARY_SFI0_OFFSET256_1B_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP, SW1SW2_OK_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.prepareWriteBinary((byte) 1, 256, HexUtil.toByteArray("66"));
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test
  public void prepareWriteBinary_whenDataLengthIsLessThanPayLoad_shouldPrepareOneCommand()
      throws Exception {

    CardRequestSpi cardCardRequest = createCardRequest(CARD_WRITE_BINARY_SFI1_OFFSET4_1B_CMD);
    CardResponseApi cardCardResponse = createCardResponse(SW1SW2_OK_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(2);

    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareWriteBinary((byte) 1, 4, HexUtil.toByteArray("55"));
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent())
        .isEqualTo(HexUtil.toByteArray("0000000055"));
  }

  @Test
  public void prepareWriteBinary_whenDataLengthIsGreaterThanPayLoad_shouldPrepareMultipleCommands()
      throws Exception {

    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_WRITE_BINARY_SFI1_OFFSET0_2B_CMD,
            CARD_WRITE_BINARY_SFI1_OFFSET2_2B_CMD,
            CARD_WRITE_BINARY_SFI1_OFFSET4_1B_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(SW1SW2_OK_RSP, SW1SW2_OK_RSP, SW1SW2_OK_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(2);

    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareWriteBinary((byte) 1, 0, HexUtil.toByteArray("1122334455"));
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent())
        .isEqualTo(HexUtil.toByteArray("1122334455"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounter_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareIncreaseCounter((byte) 31, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounter_whenValueIsLessThan0_shouldThrowIAE() {
    cardTransactionManager.prepareIncreaseCounter(FILE7, 1, -1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounter_whenValueIsGreaterThan16777215_shouldThrowIAE() {
    cardTransactionManager.prepareIncreaseCounter(FILE7, 1, 16777216);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounter_whenCounterNumberIsGreaterThan83_shouldThrowIAE() {
    cardTransactionManager.prepareIncreaseCounter(FILE7, 84, 1);
  }

  @Test
  public void prepareIncreaseCounter_whenParametersAreCorrect_shouldAddDecreaseCommand()
      throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_INCREASE_SFI11_CNT1_100U_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_INCREASE_SFI11_CNT1_8821U_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.prepareIncreaseCounter((byte) 1, 1, 100);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(1))
        .isEqualTo(8821);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounter_whenCounterNumberIsLessThan0_shouldThrowIAE() {
    cardTransactionManager.prepareIncreaseCounter(FILE7, -1, 1);
  }

  @Test
  public void prepareIncreaseCounter_whenCounterNumberIs0_shouldNotThrowException() {
    SecureExtendedModeTransactionManager tm =
        cardTransactionManager.prepareIncreaseCounter(FILE7, 0, 1);
    assertThat(tm).isNotNull();
  }

  @Test
  public void prepareIncreaseCounters_whenCardIsLowerThanPrime3__shouldAddMultipleIncreaseCommands()
      throws Exception {
    when(calypsoCard.getProductType()).thenReturn(CalypsoCard.ProductType.BASIC);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_INCREASE_SFI11_CNT1_100U_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_INCREASE_SFI11_CNT1_8821U_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToIncValueMap.put(1, 100);

    cardTransactionManager.prepareIncreaseCounters((byte) 1, counterNumberToIncValueMap);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(1))
        .isEqualTo(8821);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounters_whenSfiIsGreaterThan30_shouldThrowIAE() {
    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToIncValueMap.put(1, 1);
    cardTransactionManager.prepareIncreaseCounters((byte) 31, counterNumberToIncValueMap);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounters_whenValueIsLessThan0_shouldThrowIAE() {
    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToIncValueMap.put(1, -1);
    cardTransactionManager.prepareIncreaseCounters(FILE7, counterNumberToIncValueMap);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounters_whenValueIsGreaterThan16777215_shouldThrowIAE() {
    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToIncValueMap.put(84, 1);
    cardTransactionManager.prepareIncreaseCounters(FILE7, counterNumberToIncValueMap);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounters_whenCounterNumberIsGreaterThan83_shouldThrowIAE() {
    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToIncValueMap.put(1, 16777216);
    cardTransactionManager.prepareIncreaseCounters(FILE7, counterNumberToIncValueMap);
  }

  @Test
  public void prepareIncreaseCounters_whenParametersAreCorrect_shouldAddIncreaseMultipleCommand()
      throws Exception {
    CardRequestSpi cardCardRequest =
        createCardRequest(CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_C3_3_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_C3_33_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(3);
    counterNumberToIncValueMap.put(3, 3);
    counterNumberToIncValueMap.put(1, 1);
    counterNumberToIncValueMap.put(2, 2);
    cardTransactionManager.prepareIncreaseCounters((byte) 1, counterNumberToIncValueMap);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(1))
        .isEqualTo(0x11);
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(2))
        .isEqualTo(0x22);
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(3))
        .isEqualTo(0x33);
  }

  @Test
  public void
      prepareIncreaseCounters_whenDataLengthIsGreaterThanPayLoad_shouldPrepareMultipleCommands()
          throws Exception {
    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_CMD, CARD_INCREASE_MULTIPLE_SFI1_C3_3_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(
            CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_RSP, CARD_INCREASE_MULTIPLE_SFI1_C3_33_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(9);

    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .getCalypsoCardApiFactory()
            .createSecureExtendedModeTransactionManager(
                cardReader, calypsoCard, cardSecuritySetting);

    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(3);
    counterNumberToIncValueMap.put(1, 1);
    counterNumberToIncValueMap.put(2, 2);
    counterNumberToIncValueMap.put(3, 3);
    cardTransactionManager.prepareIncreaseCounters((byte) 1, counterNumberToIncValueMap);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(1))
        .isEqualTo(0x11);
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(2))
        .isEqualTo(0x22);
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(3))
        .isEqualTo(0x33);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounter_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareDecreaseCounter((byte) 31, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounter_whenValueIsLessThan0_shouldThrowIAE() {
    cardTransactionManager.prepareDecreaseCounter(FILE7, 1, -1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounter_whenValueIsGreaterThan16777215_shouldThrowIAE() {
    cardTransactionManager.prepareDecreaseCounter(FILE7, 1, 16777216);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounter_whenCounterNumberIsGreaterThan83_shouldThrowIAE() {
    cardTransactionManager.prepareDecreaseCounter(FILE7, 84, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounter_whenCounterNumberIsLessThan0_shouldThrowIAE() {
    cardTransactionManager.prepareDecreaseCounter(FILE7, -1, 1);
  }

  @Test
  public void prepareDecreaseCounter_whenCounterNumberIs0_shouldNotThrowException() {
    SecureExtendedModeTransactionManager tm =
        cardTransactionManager.prepareDecreaseCounter(FILE7, 0, 1);
    assertThat(tm).isNotNull();
  }

  @Test
  public void prepareDecreaseCounter_whenParametersAreCorrect_shouldAddDecreaseMultipleCommand()
      throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_DECREASE_SFI10_CNT1_100U_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_DECREASE_SFI10_CNT1_4286U_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.prepareDecreaseCounter((byte) 1, 1, 100);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(1))
        .isEqualTo(4286);
  }

  @Test
  public void prepareDecreaseCounters_whenCardIsLowerThanPrime3_shouldThrowUOE() throws Exception {
    when(calypsoCard.getProductType()).thenReturn(CalypsoCard.ProductType.BASIC);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_DECREASE_SFI10_CNT1_100U_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_DECREASE_SFI10_CNT1_4286U_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    Map<Integer, Integer> counterNumberToDecValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToDecValueMap.put(1, 100);

    cardTransactionManager.prepareDecreaseCounters((byte) 1, counterNumberToDecValueMap);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(1))
        .isEqualTo(4286);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounters_whenSfiIsGreaterThan30_shouldThrowIAE() {
    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToIncValueMap.put(1, 1);
    cardTransactionManager.prepareDecreaseCounters((byte) 31, counterNumberToIncValueMap);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounters_whenValueIsLessThan0_shouldThrowIAE() {
    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToIncValueMap.put(1, -1);
    cardTransactionManager.prepareDecreaseCounters(FILE7, counterNumberToIncValueMap);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounters_whenValueIsGreaterThan16777215_shouldThrowIAE() {
    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToIncValueMap.put(84, 1);
    cardTransactionManager.prepareDecreaseCounters(FILE7, counterNumberToIncValueMap);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounters_whenCounterNumberIsGreaterThan83_shouldThrowIAE() {
    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToIncValueMap.put(1, 16777216);
    cardTransactionManager.prepareDecreaseCounters(FILE7, counterNumberToIncValueMap);
  }

  @Test
  public void prepareDecreaseCounters_whenParametersAreCorrect_shouldAddDecreaseMultipleCommand()
      throws Exception {
    CardRequestSpi cardCardRequest =
        createCardRequest(CARD_DECREASE_MULTIPLE_SFI1_C1_11_C2_22_C8_88_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_DECREASE_MULTIPLE_SFI1_C1_111_C2_222_C8_888_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(3);
    counterNumberToIncValueMap.put(2, 0x22);
    counterNumberToIncValueMap.put(8, 0x88);
    counterNumberToIncValueMap.put(1, 0x11);
    cardTransactionManager.prepareDecreaseCounters((byte) 1, counterNumberToIncValueMap);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(1))
        .isEqualTo(0x111);
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(2))
        .isEqualTo(0x222);
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(8))
        .isEqualTo(0x888);
  }

  @Test(expected = IllegalStateException.class)
  public void prepareSetCounter_whenCounterNotPreviouslyRead_shouldThrowISE() {
    cardTransactionManager.prepareSetCounter(FILE7, 1, 1);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareSvReadAllLogs_whenPinFeatureIsNotAvailable_shouldThrowISE() {
    cardTransactionManager.prepareSvReadAllLogs();
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareSvReadAllLogs_whenNotAnSVApplication_shouldThrowISE() throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);
    cardTransactionManager.prepareSvReadAllLogs();
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifyPin_whenPINIsNull_shouldThrowIAE() {
    cardTransactionManager.prepareVerifyPin(null).processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareVerifyPin_whenPINIsNot4Digits_shouldThrowIAE() {
    cardTransactionManager
        .prepareVerifyPin(PIN_5_DIGITS.getBytes())
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareVerifyPin_whenPINNotAvailable_shouldThrowUOE() {
    cardTransactionManager
        .prepareVerifyPin(PIN_OK.getBytes())
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }

  @Test
  public void prepareVerifyPin_whenPINTransmittedInPlainText_shouldSendApduVerifyPIN()
      throws Exception {
    cardSecuritySetting.enablePinPlainTransmission();
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_VERIFY_PIN_PLAIN_OK_CMD);
    CardResponseApi cardCardResponse = createCardResponse(SW1SW2_OK);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager
        .prepareVerifyPin(PIN_OK.getBytes())
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test
  public void prepareChangePin_whenTransmissionIsPlain_shouldSendApdusToTheCardAndTheSAM()
      throws Exception {
    cardSecuritySetting.enablePinPlainTransmission();
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    calypsoCard.setPinAttemptRemaining(3);

    CardRequestSpi cardChangePinCardRequest = createCardRequest(CARD_CHANGE_PIN_PLAIN_CMD);
    CardResponseApi cardChangePinCardResponse = createCardResponse(CARD_CHANGE_PIN_PLAIN_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardChangePinCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardChangePinCardResponse);

    cardTransactionManager
        .prepareChangePin(NEW_PIN.getBytes())
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardChangePinCardRequest);
  }

  @Test
  public void prepareChangePin_whenTransmissionIsEncrypted_shouldSendApdusToTheCardAndTheSAM()
      throws Exception {
    cardSecuritySetting.setPinModificationCipheringKey(
        PIN_CIPHERING_KEY_KIF, PIN_CIPHERING_KEY_KVC);
    ;
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    CardRequestSpi cardGetChallengeCardRequest = createCardRequest(CARD_GET_CHALLENGE_CMD);
    CardResponseApi cardGetChallengeCardResponse = createCardResponse(CARD_GET_CHALLENGE_RSP);

    when(symmetricCryptoTransactionManager.cipherPinForModification(
            CARD_CHALLENGE,
            new byte[4],
            NEW_PIN.getBytes(),
            PIN_CIPHERING_KEY_KIF,
            PIN_CIPHERING_KEY_KVC))
        .thenReturn(CIPHER_PIN_UPDATE_OK);

    CardRequestSpi samCardRequest =
        createCardRequest(
            SAM_SELECT_DIVERSIFIER_CMD, SAM_GIVE_RANDOM_CMD, SAM_CARD_CIPHER_PIN_UPDATE_CMD);
    CardResponseApi samCardResponse =
        createCardResponse(SW1SW2_OK, SW1SW2_OK, SAM_CARD_CIPHER_PIN_UPDATE_RSP);

    CardRequestSpi cardChangePinCardRequest = createCardRequest(CARD_CHANGE_PIN_CMD);
    CardResponseApi cardChangePinCardResponse = createCardResponse(CARD_CHANGE_PIN_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardGetChallengeCardRequest)),
            any(ChannelControl.class)))
        .thenReturn(cardGetChallengeCardResponse);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardChangePinCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardChangePinCardResponse);

    cardTransactionManager
        .prepareChangePin(NEW_PIN.getBytes())
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(cardReader, symmetricCryptoTransactionManager);

    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardGetChallengeCardRequest)),
            any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .cipherPinForModification(
            CARD_CHALLENGE,
            new byte[4],
            NEW_PIN.getBytes(),
            PIN_CIPHERING_KEY_KIF,
            PIN_CIPHERING_KEY_KVC);
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardChangePinCardRequest)), any(ChannelControl.class));

    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Test
  public void processCommands_whenOutOfSession_shouldInteractWithCardOnly() throws Exception {
    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_READ_REC_SFI7_REC1_CMD_HEX,
            CARD_READ_REC_SFI8_REC1_CMD_HEX,
            CARD_READ_REC_SFI10_REC1_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(
            CARD_READ_REC_SFI7_REC1_RSP_HEX,
            CARD_READ_REC_SFI8_REC1_RSP_HEX,
            CARD_READ_REC_SFI10_REC1_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.prepareReadRecord(FILE7, 1);
    cardTransactionManager.prepareReadRecord(FILE8, 1);
    cardTransactionManager.prepareReadRecord(FILE10, 1);
    cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verifyInteractionsForSingleCardCommand(cardCardRequest);
  }

  @Test
  public void getCryptoExtension_shouldReturnANonNullReference() throws Exception {
    SymmetricCryptoTransactionManagerMock cryptoExtension =
        cardTransactionManager.getCryptoExtension(SymmetricCryptoTransactionManagerMock.class);
    assertThat(cryptoExtension).isNotNull();
  }

  @Test(expected = IllegalStateException.class)
  public void prepareCloseSecureSession_whenNoSessionIsOpen_shouldThrowISE() {
    cardTransactionManager.prepareCloseSecureSession().processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }

  @Test
  public void prepareCloseSecureSession_whenASessionIsOpen_shouldInteractWithCardAndCryptoManager()
      throws Exception {
    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE);
    when(symmetricCryptoTransactionManager.finalizeTerminalSessionMac()).thenReturn(SAM_SIGNATURE);
    when(symmetricCryptoTransactionManager.isCardSessionMacValid(CARD_SIGNATURE)).thenReturn(true);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    CardRequestSpi cardCardRequestRead = createCardRequest(CARD_READ_REC_SFI7_REC1_L29_CMD_HEX);
    CardResponseApi cardCardResponseRead = createCardResponse(CARD_READ_REC_SFI7_REC1_RSP_HEX);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequestRead)), any(ChannelControl.class)))
        .thenReturn(cardCardResponseRead);

    CardRequestSpi cardCardRequestClose = createCardRequest(CARD_CLOSE_SECURE_SESSION_CMD);
    CardResponseApi cardCardResponseClose = createCardResponse(CARD_CLOSE_SECURE_SESSION_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequestClose)), any(ChannelControl.class)))
        .thenReturn(cardCardResponseClose);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    cardTransactionManager
        .prepareReadRecords(FILE7, 1, 1, 29)
        .prepareCloseSecureSession()
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(symmetricCryptoTransactionManager, cardReader);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .initTerminalSessionMac(CARD_OPEN_SECURE_SESSION_DATA_OUT, KIF, KVC);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequestRead)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI7_REC1_L29_CMD);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI7_REC1_RSP);
    inOrder.verify(symmetricCryptoTransactionManager).finalizeTerminalSessionMac();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequestClose)), any(ChannelControl.class));
    inOrder.verify(symmetricCryptoTransactionManager).isCardSessionMacValid(CARD_SIGNATURE);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Test(expected = UnexpectedCommandStatusException.class)
  public void prepareCloseSecureSession_whenCloseSessionFails_shouldThrowUCSE() throws Exception {
    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE);
    when(symmetricCryptoTransactionManager.finalizeTerminalSessionMac()).thenReturn(SAM_SIGNATURE);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(symmetricCryptoTransactionManager, cardReader);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));

    cardCardRequest = createCardRequest(CARD_CLOSE_SECURE_SESSION_CMD);
    cardCardResponse = createCardResponse(SW1SW2_INCORRECT_SIGNATURE);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.prepareCloseSecureSession().processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }

  @Test(expected = InvalidCardMacException.class)
  public void prepareCloseSecureSession_whenCardAuthenticationFails_shouldThrowICME()
      throws Exception {
    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE);
    when(symmetricCryptoTransactionManager.finalizeTerminalSessionMac()).thenReturn(SAM_SIGNATURE);
    when(symmetricCryptoTransactionManager.isCardSessionMacValid(CARD_SIGNATURE)).thenReturn(false);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(symmetricCryptoTransactionManager, cardReader);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));

    cardCardRequest = createCardRequest(CARD_CLOSE_SECURE_SESSION_CMD);
    cardCardResponse = createCardResponse(CARD_CLOSE_SECURE_SESSION_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.prepareCloseSecureSession().processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }

  @Test
  public void prepareCancelSecureSession_whenNoSessionIsOpen_shouldDoBestEffortMode()
      throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_ABORT_SECURE_SESSION_CMD);
    CardResponseApi cardCardResponse = createCardResponse(SW1SW2_OK);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.prepareCancelSecureSession().processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
  }

  @Test
  public void prepareCancelSecureSession_whenASessionIsOpen_shouldSendCancelApduToCard()
      throws Exception {
    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(symmetricCryptoTransactionManager, cardReader);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .initTerminalSessionMac(CARD_OPEN_SECURE_SESSION_DATA_OUT, KIF, KVC);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();

    cardCardRequest = createCardRequest(CARD_ABORT_SECURE_SESSION_CMD);
    cardCardResponse = createCardResponse(SW1SW2_OK);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.prepareCancelSecureSession().processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    inOrder = inOrder(symmetricCryptoTransactionManager, cardReader);
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Test
  public void
      prepareOpenSecureSession_whenNoCommandsArePrepared_shouldInteractWithCardAndCryptoManager()
          throws Exception {

    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(cardReader, symmetricCryptoTransactionManager);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .initTerminalSessionMac(CARD_OPEN_SECURE_SESSION_DATA_OUT, KIF, KVC);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Test
  public void
      prepareOpenSecureSession_whenSuccessful_shouldUpdateTransactionCounterAndRatificationStatus()
          throws Exception {

    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    assertThat(calypsoCard.isDfRatified()).isTrue();
    assertThat(calypsoCard.getTransactionCounter()).isEqualTo(0x030490);
  }

  @Test
  public void
      prepareOpenSecureSession_whenOneReadRecordIsPrepared_shouldInteractWithCardAndCryptoManager()
          throws Exception {

    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .prepareReadRecord(FILE7, 1)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(cardReader, symmetricCryptoTransactionManager);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .initTerminalSessionMac(CARD_OPEN_SECURE_SESSION_SFI7_REC1_DATA_OUT, KIF, KVC);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Test
  public void
      prepareOpenSecureSession_whenTwoReadRecordArePreparedAndNoRestrictions_shouldMergeFirstReadRecord()
          throws Exception {

    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE);

    CardRequestSpi cardCardRequest =
        createCardRequest(CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD, CARD_READ_REC_SFI8_REC1_CMD_HEX);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP, CARD_READ_REC_SFI8_REC1_RSP_HEX);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .prepareReadRecord(FILE7, 1)
        .prepareReadRecords(FILE8, 1, 1, 0)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(cardReader, symmetricCryptoTransactionManager);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .initTerminalSessionMac(CARD_OPEN_SECURE_SESSION_SFI7_REC1_DATA_OUT, KIF, KVC);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI8_REC1_CMD);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI8_REC1_RSP);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Test
  public void
      prepareOpenSecureSession_whenTwoReadRecordArePreparedAndReadOnSessionOpeningIsDisabled_shouldNotMergeFirstReadRecord()
          throws Exception {

    cardSecuritySetting.disableReadOnSessionOpening();

    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE);

    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_OPEN_SECURE_SESSION_CMD,
            CARD_READ_REC_SFI7_REC1_CMD_HEX,
            CARD_READ_REC_SFI8_REC1_CMD_HEX);
    CardResponseApi cardCardResponse =
        createCardResponse(
            CARD_OPEN_SECURE_SESSION_RSP,
            CARD_READ_REC_SFI7_REC1_RSP_HEX,
            CARD_READ_REC_SFI8_REC1_RSP_HEX);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .prepareReadRecords(FILE7, 1, 1, 0)
        .prepareReadRecords(FILE8, 1, 1, 0)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(cardReader, symmetricCryptoTransactionManager);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .initTerminalSessionMac(CARD_OPEN_SECURE_SESSION_DATA_OUT, KIF, KVC);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI7_REC1_CMD);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI7_REC1_RSP);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI8_REC1_CMD);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI8_REC1_RSP);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Test
  public void
      prepareOpenSecureSession_whenTwoReadRecordArePreparedAndPreOpenVariant_shouldNotMergeFirstReadRecord()
          throws Exception {

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);

    calypsoCard.setPreOpenWriteAccessLevel(WriteAccessLevel.DEBIT);
    calypsoCard.setPreOpenDataOut(HexUtil.toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_RSP));

    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE_EXTENDED);

    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
            CARD_READ_REC_SFI7_REC1_CMD_HEX,
            CARD_READ_REC_SFI8_REC1_CMD_HEX);
    CardResponseApi cardCardResponse =
        createCardResponse(
            CARD_OPEN_SECURE_SESSION_EXTENDED_RSP,
            CARD_READ_REC_SFI7_REC1_RSP_HEX,
            CARD_READ_REC_SFI8_REC1_RSP_HEX);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .prepareReadRecords(FILE7, 1, 1, 0)
        .prepareReadRecords(FILE8, 1, 1, 0)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(cardReader, symmetricCryptoTransactionManager);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .initTerminalSessionMac(CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT, KIF, KVC);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI7_REC1_CMD);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI7_REC1_RSP);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI8_REC1_CMD);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI8_REC1_RSP);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Test
  public void
      prepareOpenSecureSession_whenPreOpenVariantWithDifferentWriteAccessLevel_shouldIgnoreThePreopenMode()
          throws Exception {

    calypsoCard.setPreOpenWriteAccessLevel(WriteAccessLevel.LOAD);
    calypsoCard.setPreOpenDataOut(HexUtil.toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_RSP));

    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .prepareReadRecord(FILE7, 1)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(cardReader, symmetricCryptoTransactionManager);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .initTerminalSessionMac(CARD_OPEN_SECURE_SESSION_SFI7_REC1_DATA_OUT, KIF, KVC);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Test
  public void
      prepareOpenSecureSession_whenPreOpenVariantButNotAtomicSession_shouldNotAnticipateDataOut()
          throws Exception {

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);

    calypsoCard.setPreOpenWriteAccessLevel(WriteAccessLevel.DEBIT);
    calypsoCard.setPreOpenDataOut(HexUtil.toByteArray(CARD_OPEN_SECURE_SESSION_RSP));

    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE_EXTENDED);

    CardRequestSpi cardCardRequest =
        createCardRequest(CARD_OPEN_SECURE_SESSION_EXTENDED_CMD, CARD_READ_REC_SFI7_REC1_CMD_HEX);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_OPEN_SECURE_SESSION_EXTENDED_RSP, CARD_READ_REC_SFI7_REC1_RSP_HEX);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .prepareReadRecords(FILE7, 1, 1, 0)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(cardReader, symmetricCryptoTransactionManager);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .initTerminalSessionMac(CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT, KIF, KVC);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI7_REC1_CMD);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI7_REC1_RSP);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Test
  public void
      prepareOpenSecureSession_whenPreOpenVariantButExtendedModeNotSupported_shouldProcessInRegularMode()
          throws Exception {

    calypsoCard.setPreOpenWriteAccessLevel(WriteAccessLevel.DEBIT);
    calypsoCard.setPreOpenDataOut(HexUtil.toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_RSP));

    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .prepareReadRecords(FILE7, 1, 1, 0)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(cardReader, symmetricCryptoTransactionManager);
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .initTerminalSessionMac(CARD_OPEN_SECURE_SESSION_SFI7_REC1_DATA_OUT, KIF, KVC);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }

  @Test
  public void prepareOpenSecureSession_whenPreOpenVariant_shouldBeSuccessful() throws Exception {

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);

    calypsoCard.setPreOpenWriteAccessLevel(WriteAccessLevel.DEBIT);
    calypsoCard.setPreOpenDataOut(
        HexUtil.toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_DATAOUT_HEX));
    calypsoCard.setContent(FILE7, 1, HexUtil.toByteArray(FILE7_REC1_29B));

    when(symmetricCryptoTransactionManager.initTerminalSecureSessionContext())
        .thenReturn(SAM_CHALLENGE_EXTENDED);
    when(symmetricCryptoTransactionManager.finalizeTerminalSessionMac())
        .thenReturn(SAM_SIGNATURE_EXTENDED);
    when(symmetricCryptoTransactionManager.isCardSessionMacValid(CARD_SIGNATURE_EXTENDED))
        .thenReturn(true);

    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
            CARD_READ_REC_SFI7_REC1_L29_CMD_HEX,
            CARD_CLOSE_SECURE_SESSION_EXTENDED_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(
            CARD_OPEN_SECURE_SESSION_EXTENDED_RSP,
            CARD_READ_REC_SFI7_REC1_RSP_HEX,
            CARD_CLOSE_SECURE_SESSION_EXTENDED_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager
        .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
        .prepareReadRecords(FILE7, 1, 1, 29)
        .prepareCloseSecureSession()
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(symmetricCryptoTransactionManager, cardReader);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    inOrder.verify(symmetricCryptoTransactionManager).initTerminalSecureSessionContext();
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .initTerminalSessionMac(CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT, KIF, KVC);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI7_REC1_L29_CMD);
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .updateTerminalSessionMac(CARD_READ_REC_SFI7_REC1_RSP);
    inOrder.verify(symmetricCryptoTransactionManager).finalizeTerminalSessionMac();
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(symmetricCryptoTransactionManager)
        .isCardSessionMacValid(CARD_SIGNATURE_EXTENDED);
    inOrder.verify(symmetricCryptoTransactionManager).synchronize();
    verifyNoMoreInteractions(symmetricCryptoTransactionManager, cardReader);
  }























  @Test(expected = UnexpectedCommandStatusException.class)
  public void prepareOpenSecureSession_whenPreOpenVariantWithDifferentDataOut_shouldThrowUCSE()
          throws Exception {

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);

    calypsoCard.setPreOpenWriteAccessLevel(WriteAccessLevel.DEBIT);
    calypsoCard.setPreOpenDataOut(HexUtil.toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_DATAOUT_2));
    calypsoCard.setContent(FILE7, 1, HexUtil.toByteArray(FILE7_REC1_29B));

    cardTransactionManager =
            CalypsoExtensionService.getInstance()
                    .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);

    CardRequestSpi samCardRequest1 = createCardRequest(SAM_GET_CHALLENGE_EXTENDED_CMD);
    CardResponseApi samCardResponse1 = createCardResponse(SAM_GET_CHALLENGE_EXTENDED_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest1)), any(ChannelControl.class)))
            .thenReturn(samCardResponse1);

    CardRequestSpi samCardRequest2 =
            createCardRequest(
                    SAM_SELECT_DIVERSIFIER_CMD,
                    SAM_DIGEST_INIT_EXTENDED_OPEN_SECURE_SESSION_CMD_2,
                    SAM_DIGEST_UPDATE_MULTIPLE_READ_REC_SFI7_REC1_L29_CMD,
                    SAM_DIGEST_CLOSE_EXTENDED_CMD);
    CardResponseApi samCardResponse2 =
            createCardResponse(
                    SW1SW2_OK_RSP, SW1SW2_OK_RSP, SW1SW2_OK_RSP, SAM_DIGEST_CLOSE_EXTENDED_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class)))
            .thenReturn(samCardResponse2);

    CardRequestSpi samCardRequest3 = createCardRequest(SAM_DIGEST_AUTHENTICATE_EXTENDED_CMD);
    CardResponseApi samCardResponse3 = createCardResponse(SW1SW2_OK_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest3)), any(ChannelControl.class)))
            .thenReturn(samCardResponse3);

    CardRequestSpi cardCardRequest =
            createCardRequest(
                    CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
                    CARD_READ_REC_SFI7_REC1_L29_CMD_HEX,
                    CARD_CLOSE_SECURE_SESSION_EXTENDED_CMD);
    CardResponseApi cardCardResponse =
            createCardResponse(
                    CARD_OPEN_SECURE_SESSION_EXTENDED_RSP,
                    CARD_READ_REC_SFI7_REC1_RSP_HEX,
                    CARD_CLOSE_SECURE_SESSION_EXTENDED_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse);

    cardTransactionManager.prepareOpenSecureSession(WriteAccessLevel.DEBIT);
    cardTransactionManager.prepareReadRecords(FILE7, 1, 1, 29);
    cardTransactionManager.prepareCloseSecureSession();
    cardTransactionManager. processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }

  @Test(expected = UnexpectedCommandStatusException.class)
  public void
  prepareOpenSecureSession_whenPreOpenVariantWithDifferentRecordContent_shouldThrowUCSE()
          throws Exception {

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);

    calypsoCard.setPreOpenWriteAccessLevel(WriteAccessLevel.DEBIT);
    calypsoCard.setPreOpenDataOut(HexUtil.toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_DATAOUT_2));
    calypsoCard.setContent(FILE7, 1, HexUtil.toByteArray(FILE7_REC2_29B));

    cardTransactionManager =
            CalypsoExtensionService.getInstance()
                    .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);

    CardRequestSpi samCardRequest1 = createCardRequest(SAM_GET_CHALLENGE_EXTENDED_CMD);
    CardResponseApi samCardResponse1 = createCardResponse(SAM_GET_CHALLENGE_EXTENDED_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest1)), any(ChannelControl.class)))
            .thenReturn(samCardResponse1);

    CardRequestSpi samCardRequest2 =
            createCardRequest(
                    SAM_SELECT_DIVERSIFIER_CMD,
                    SAM_DIGEST_INIT_EXTENDED_OPEN_SECURE_SESSION_CMD_2,
                    SAM_DIGEST_UPDATE_MULTIPLE_READ_REC_SFI7_REC2_L29_CMD,
                    SAM_DIGEST_CLOSE_EXTENDED_CMD);
    CardResponseApi samCardResponse2 =
            createCardResponse(
                    SW1SW2_OK_RSP, SW1SW2_OK_RSP, SW1SW2_OK_RSP, SAM_DIGEST_CLOSE_EXTENDED_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class)))
            .thenReturn(samCardResponse2);

    CardRequestSpi samCardRequest3 = createCardRequest(SAM_DIGEST_AUTHENTICATE_EXTENDED_CMD);
    CardResponseApi samCardResponse3 = createCardResponse(SW1SW2_OK_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest3)), any(ChannelControl.class)))
            .thenReturn(samCardResponse3);

    CardRequestSpi cardCardRequest =
            createCardRequest(
                    CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
                    CARD_READ_REC_SFI7_REC1_L29_CMD_HEX,
                    CARD_CLOSE_SECURE_SESSION_EXTENDED_CMD);
    CardResponseApi cardCardResponse =
            createCardResponse(
                    CARD_OPEN_SECURE_SESSION_EXTENDED_RSP,
                    CARD_READ_REC_SFI7_REC1_RSP_HEX,
                    CARD_CLOSE_SECURE_SESSION_EXTENDED_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse);

    cardTransactionManager.prepareOpenSecureSession(WriteAccessLevel.DEBIT);
    cardTransactionManager.prepareReadRecords(FILE7, 1, 1, 29);
    cardTransactionManager.prepareCloseSecureSession();
    cardTransactionManager. processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }

  @Test(expected = UnauthorizedKeyException.class)
  public void prepareOpenSecureSession_whenKeyNotAuthorized_shouldThrowUnauthorizedKeyException()
          throws Exception {
    // force the checking of the session key to fail
    cardSecuritySetting =
            CalypsoExtensionService.getInstance()
                    .createCardSecuritySetting()
                    .setControlSamResource(samReader, calypsoSam)
                    .addAuthorizedSessionKey((byte) 0x00, (byte) 0x00);
    cardTransactionManager =
            CalypsoExtensionService.getInstance()
                    .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);
    CardRequestSpi samCardRequest = createCardRequest(SAM_GET_CHALLENGE_CMD);
    CardResponseApi samCardResponse = createCardResponse(SAM_GET_CHALLENGE_RSP);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
            .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse);
    cardTransactionManager.prepareOpenSecureSession(WriteAccessLevel.DEBIT). processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }


  @Test
  public void prepareChangeKey_shouldSendApdusToTheCardAndTheSAM() throws Exception {
    cardSecuritySetting =
            CalypsoExtensionService.getInstance()
                    .createCardSecuritySetting()
                    .setControlSamResource(samReader, calypsoSam)
                    .enablePinPlainTransmission();
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    CardRequestSpi cardGetChallengeCardRequest = createCardRequest(CARD_GET_CHALLENGE_CMD);
    CardResponseApi cardGetChallengeCardResponse = createCardResponse(CARD_GET_CHALLENGE_RSP);

    CardRequestSpi samCardRequest =
            createCardRequest(
                    SAM_SELECT_DIVERSIFIER_CMD, SAM_GIVE_RANDOM_CMD, SAM_CARD_GENERATE_KEY_CMD);
    CardResponseApi samCardResponse =
            createCardResponse(SW1SW2_OK, SW1SW2_OK, SAM_CARD_GENERATE_KEY_RSP);

    CardRequestSpi cardChangeKeyCardRequest = createCardRequest(CARD_CHANGE_KEY_CMD);
    CardResponseApi cardChangeKeyCardResponse = createCardResponse(SW1SW2_OK);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardGetChallengeCardRequest)),
            any(ChannelControl.class)))
            .thenReturn(cardGetChallengeCardResponse);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
            .thenReturn(samCardResponse);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardChangeKeyCardRequest)), any(ChannelControl.class)))
            .thenReturn(cardChangeKeyCardResponse);

    cardTransactionManager
            .prepareChangeKey(1, (byte) 2, (byte) 3, (byte) 4, (byte) 5)
            . processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(cardReader, samReader);

    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardGetChallengeCardRequest)),
                    any(ChannelControl.class));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardChangeKeyCardRequest)), any(ChannelControl.class));

    verifyNoMoreInteractions(samReader, cardReader);
  }


  @Test(expected = IllegalArgumentException.class)
  public void prepareSvGet_whenSvOperationNull_shouldThrowIAE() {
    cardTransactionManager.prepareSvGet(null, SvAction.DO);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSvGet_whenSvActionNull_shouldThrowIAE() {
    cardTransactionManager.prepareSvGet(SvOperation.DEBIT, null);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareSvGet_whenSvOperationNotAvailable_shouldThrowUOE() {
    cardTransactionManager.prepareSvGet(SvOperation.DEBIT, SvAction.DO);
  }

  @Test
  public void prepareSvGet_whenSvOperationDebit_shouldPrepareSvGetDebitApdu() throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_SV_GET_DEBIT_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SV_GET_DEBIT_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSvGet(SvOperation.DEBIT, SvAction.DO);
    cardTransactionManager. processCommands(CHANNEL_CONTROL_KEEP_OPEN);
    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test
  public void prepareSvGet_whenSvOperationReload_shouldPrepareSvGetReloadApdu() throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_SV_GET_RELOAD_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SV_GET_RELOAD_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSvGet(SvOperation.RELOAD, SvAction.DO);
    cardTransactionManager. processCommands(CHANNEL_CONTROL_KEEP_OPEN);
    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test
  public void prepareSvGet_whenSvOperationReloadWithPrimeRev2_shouldPrepareSvGetReloadApdu()
          throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2_WITH_STORED_VALUE);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_PRIME_REV2_SV_GET_RELOAD_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SV_GET_RELOAD_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSvGet(SvOperation.RELOAD, SvAction.DO);
    cardTransactionManager. processCommands(CHANNEL_CONTROL_KEEP_OPEN);
    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test(expected = IllegalStateException.class)
  public void prepareSvReload_whenNoSvGetPreviouslyExecuted_shouldThrowISE() throws Exception {
    CardRequestSpi samCardRequest = createCardRequest(SAM_SV_CHECK_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
            .thenReturn(samCardResponse);
    cardTransactionManager.prepareSvReload(1);
  }

  @Test
  public void prepareSvReload_whenOutOfSession_InRegularMode_shouldUpdateReloadLog()
          throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);

    CardRequestSpi cardCardRequest1 = createCardRequest(CARD_SV_GET_RELOAD_CMD);
    CardResponseApi cardCardResponse1 = createCardResponse(CARD_SV_GET_RELOAD_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest1)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse1);

    CardRequestSpi cardCardRequest2 = createCardRequest(CARD_SV_RELOAD_CMD);
    CardResponseApi cardCardResponse2 = createCardResponse(CARD_SV_RELOAD_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest2)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse2);

    CardRequestSpi samCardRequest1 =
            createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_PREPARE_LOAD_CMD);
    CardResponseApi samCardResponse1 = createCardResponse(SW1SW2_OK, SAM_PREPARE_LOAD_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest1)), any(ChannelControl.class)))
            .thenReturn(samCardResponse1);

    CardRequestSpi samCardRequest2 = createCardRequest(SAM_SV_CHECK_CMD);
    CardResponseApi samCardResponse2 = createCardResponse(SW1SW2_OK);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class)))
            .thenReturn(samCardResponse2);

    cardTransactionManager.prepareSvGet(SvOperation.RELOAD, SvAction.DO). processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    assertThat(calypsoCard.getSvBalance()).isEqualTo(HexUtil.toInt(SV_R_BALANCE));
    assertThat(calypsoCard.getSvLastTNum()).isEqualTo(HexUtil.toShort(SV_R_TNUM));
    SvLoadLogRecord loadLog1 = calypsoCard.getSvLoadLogRecord();
    assertThat(loadLog1.getLoadDate()).isEqualTo(HexUtil.toByteArray(SV_R_LOG_DATE));
    assertThat(loadLog1.getLoadTime()).isEqualTo(HexUtil.toByteArray(SV_R_LOG_TIME));
    assertThat(loadLog1.getBalance()).isEqualTo(HexUtil.toInt(SV_R_LOG_BALANCE));
    assertThat(loadLog1.getAmount()).isEqualTo(HexUtil.toInt(SV_R_LOG_AMOUNT));
    assertThat(loadLog1.getFreeData())
            .isEqualTo(HexUtil.toByteArray(SV_R_LOG_FREE1 + SV_R_LOG_FREE2));
    assertThat(loadLog1.getKvc()).isEqualTo(HexUtil.toByte(SV_R_LOG_KVC));
    assertThat(loadLog1.getSamId()).isEqualTo(HexUtil.toByteArray(SV_R_LOG_SAM_ID));
    assertThat(loadLog1.getSamTNum()).isEqualTo(HexUtil.toInt(SV_R_LOG_SAM_TNUM));
    assertThat(loadLog1.getSvTNum()).isEqualTo(HexUtil.toInt(SV_R_LOG_SV_TNUM));

    cardTransactionManager
            .prepareSvReload(
                    HexUtil.toInt(SV_R_AMOUNT),
                    HexUtil.toByteArray(SV_R_DATE),
                    HexUtil.toByteArray(SV_R_TIME),
                    HexUtil.toByteArray(SV_R_FREE1 + SV_R_FREE2))
            . processCommands(CHANNEL_CONTROL_CLOSE_AFTER);

    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest1)), any(ChannelControl.class));
    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest2)), any(ChannelControl.class));
    verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest1)), any(ChannelControl.class));
    verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

    assertThat(calypsoCard.getSvBalance())
            .isEqualTo(HexUtil.toInt(SV_R_BALANCE) + HexUtil.toInt(SV_R_AMOUNT));
    assertThat(calypsoCard.getSvLastTNum()).isEqualTo(HexUtil.toInt(SV_R_TNUM) + 1);
    SvLoadLogRecord loadLog2 = calypsoCard.getSvLoadLogRecord();
    assertThat(loadLog2.getLoadDate()).isEqualTo(HexUtil.toByteArray(SV_R_DATE));
    assertThat(loadLog2.getLoadTime()).isEqualTo(HexUtil.toByteArray(SV_R_TIME));
    assertThat(loadLog2.getBalance())
            .isEqualTo(HexUtil.toInt(SV_R_BALANCE) + HexUtil.toInt(SV_R_AMOUNT));
    assertThat(loadLog2.getAmount()).isEqualTo(HexUtil.toInt(SV_R_AMOUNT));
    assertThat(loadLog2.getFreeData()).isEqualTo(HexUtil.toByteArray(SV_R_FREE1 + SV_R_FREE2));
    assertThat(loadLog2.getKvc()).isEqualTo(HexUtil.toByte(SV_R_CURRENT_KVC));
    assertThat(loadLog2.getSamId()).isEqualTo(HexUtil.toByteArray(SV_R_SAM_ID));
    assertThat(loadLog2.getSamTNum()).isEqualTo(HexUtil.toInt(SAM_PREPARE_LOAD_RSP_TNUM));
    assertThat(loadLog2.getSvTNum()).isEqualTo(HexUtil.toInt(SV_R_TNUM) + 1);
  }

  @Test
  public void prepareSvReload_whenOutOfSession_InExtendedMode_shouldUpdateReloadLog()
          throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED_WITH_STORED_VALUE);

    CardRequestSpi cardCardRequest1 = createCardRequest(CARD_SV_GET_RELOAD_EXT_CMD);
    CardResponseApi cardCardResponse1 = createCardResponse(CARD_SV_GET_RELOAD_EXT_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest1)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse1);

    CardRequestSpi cardCardRequest2 = createCardRequest(CARD_SV_RELOAD_EXT_CMD);
    CardResponseApi cardCardResponse2 = createCardResponse(CARD_SV_RELOAD_EXT_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest2)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse2);

    CardRequestSpi samCardRequest1 =
            createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_PREPARE_LOAD_EXT_CMD);
    CardResponseApi samCardResponse1 = createCardResponse(SW1SW2_OK, SAM_PREPARE_LOAD_EXT_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest1)), any(ChannelControl.class)))
            .thenReturn(samCardResponse1);

    CardRequestSpi samCardRequest2 = createCardRequest(SAM_SV_CHECK_EXT_CMD);
    CardResponseApi samCardResponse2 = createCardResponse(SW1SW2_OK);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class)))
            .thenReturn(samCardResponse2);

    cardTransactionManager.prepareSvGet(SvOperation.RELOAD, SvAction.DO). processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    assertThat(calypsoCard.getSvBalance()).isEqualTo(HexUtil.toInt(SV_R_BALANCE));
    assertThat(calypsoCard.getSvLastTNum()).isEqualTo(HexUtil.toShort(SV_R_TNUM));
    SvLoadLogRecord loadLog1 = calypsoCard.getSvLoadLogRecord();
    assertThat(loadLog1.getLoadDate()).isEqualTo(HexUtil.toByteArray(SV_R_LOG_DATE));
    assertThat(loadLog1.getLoadTime()).isEqualTo(HexUtil.toByteArray(SV_R_LOG_TIME));
    assertThat(loadLog1.getBalance()).isEqualTo(HexUtil.toInt(SV_R_LOG_BALANCE));
    assertThat(loadLog1.getAmount()).isEqualTo(HexUtil.toInt(SV_R_LOG_AMOUNT));
    assertThat(loadLog1.getFreeData())
            .isEqualTo(HexUtil.toByteArray(SV_R_LOG_FREE1 + SV_R_LOG_FREE2));
    assertThat(loadLog1.getKvc()).isEqualTo(HexUtil.toByte(SV_R_LOG_KVC));
    assertThat(loadLog1.getSamId()).isEqualTo(HexUtil.toByteArray(SV_R_LOG_SAM_ID));
    assertThat(loadLog1.getSamTNum()).isEqualTo(HexUtil.toInt(SV_R_LOG_SAM_TNUM));
    assertThat(loadLog1.getSvTNum()).isEqualTo(HexUtil.toInt(SV_R_LOG_SV_TNUM));
    SvDebitLogRecord debitLog1 = calypsoCard.getSvDebitLogLastRecord();
    assertThat(debitLog1.getDebitDate()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_DATE));
    assertThat(debitLog1.getDebitTime()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_TIME));
    assertThat(debitLog1.getBalance()).isEqualTo(HexUtil.toInt(SV_D_LOG_BALANCE));
    assertThat(debitLog1.getAmount()).isEqualTo(HexUtil.toInt(SV_D_LOG_AMOUNT));
    assertThat(debitLog1.getKvc()).isEqualTo(HexUtil.toByte(SV_D_LOG_KVC));
    assertThat(debitLog1.getSamId()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_SAM_ID));
    assertThat(debitLog1.getSamTNum()).isEqualTo(HexUtil.toInt(SV_D_LOG_SAM_TNUM));
    assertThat(debitLog1.getSvTNum()).isEqualTo(HexUtil.toInt(SV_D_LOG_SV_TNUM));

    cardTransactionManager
            .prepareSvReload(
                    HexUtil.toInt(SV_R_AMOUNT),
                    HexUtil.toByteArray(SV_R_DATE),
                    HexUtil.toByteArray(SV_R_TIME),
                    HexUtil.toByteArray(SV_R_FREE1 + SV_R_FREE2))
            . processCommands(CHANNEL_CONTROL_CLOSE_AFTER);

    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest1)), any(ChannelControl.class));
    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest2)), any(ChannelControl.class));
    verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest1)), any(ChannelControl.class));
    verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

    assertThat(calypsoCard.getSvBalance())
            .isEqualTo(HexUtil.toInt(SV_R_BALANCE) + HexUtil.toInt(SV_R_AMOUNT));
    assertThat(calypsoCard.getSvLastTNum()).isEqualTo(HexUtil.toInt(SV_R_TNUM) + 1);
    SvLoadLogRecord loadLog2 = calypsoCard.getSvLoadLogRecord();
    assertThat(loadLog2.getLoadDate()).isEqualTo(HexUtil.toByteArray(SV_R_DATE));
    assertThat(loadLog2.getLoadTime()).isEqualTo(HexUtil.toByteArray(SV_R_TIME));
    assertThat(loadLog2.getBalance())
            .isEqualTo(HexUtil.toInt(SV_R_BALANCE) + HexUtil.toInt(SV_R_AMOUNT));
    assertThat(loadLog2.getAmount()).isEqualTo(HexUtil.toInt(SV_R_AMOUNT));
    assertThat(loadLog2.getFreeData()).isEqualTo(HexUtil.toByteArray(SV_R_FREE1 + SV_R_FREE2));
    assertThat(loadLog2.getKvc()).isEqualTo(HexUtil.toByte(SV_R_CURRENT_KVC));
    assertThat(loadLog2.getSamId()).isEqualTo(HexUtil.toByteArray(SV_R_SAM_ID));
    assertThat(loadLog2.getSamTNum()).isEqualTo(HexUtil.toInt(SAM_PREPARE_LOAD_RSP_TNUM));
    assertThat(loadLog2.getSvTNum()).isEqualTo(HexUtil.toInt(SV_R_TNUM) + 1);
    SvDebitLogRecord debitLog2 = calypsoCard.getSvDebitLogLastRecord();
    assertThat(debitLog2.getDebitDate()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_DATE));
    assertThat(debitLog2.getDebitTime()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_TIME));
    assertThat(debitLog2.getBalance()).isEqualTo(HexUtil.toInt(SV_D_LOG_BALANCE));
    assertThat(debitLog2.getAmount()).isEqualTo(HexUtil.toInt(SV_D_LOG_AMOUNT));
    assertThat(debitLog2.getKvc()).isEqualTo(HexUtil.toByte(SV_D_LOG_KVC));
    assertThat(debitLog2.getSamId()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_SAM_ID));
    assertThat(debitLog2.getSamTNum()).isEqualTo(HexUtil.toInt(SV_D_LOG_SAM_TNUM));
    assertThat(debitLog2.getSvTNum()).isEqualTo(HexUtil.toInt(SV_D_LOG_SV_TNUM));
  }

  @Test
  public void prepareSvDebit_whenOutOfSession_InRegularMode_shouldUpdateReloadLog()
          throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);

    CardRequestSpi cardCardRequest1 = createCardRequest(CARD_SV_GET_DEBIT_CMD);
    CardResponseApi cardCardResponse1 = createCardResponse(CARD_SV_GET_DEBIT_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest1)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse1);

    CardRequestSpi cardCardRequest2 = createCardRequest(CARD_SV_DEBIT_CMD);
    CardResponseApi cardCardResponse2 = createCardResponse(CARD_SV_DEBIT_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest2)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse2);

    CardRequestSpi samCardRequest1 =
            createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_PREPARE_DEBIT_CMD);
    CardResponseApi samCardResponse1 = createCardResponse(SW1SW2_OK, SAM_PREPARE_DEBIT_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest1)), any(ChannelControl.class)))
            .thenReturn(samCardResponse1);

    CardRequestSpi samCardRequest2 = createCardRequest(SAM_SV_CHECK_CMD);
    CardResponseApi samCardResponse2 = createCardResponse(SW1SW2_OK);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class)))
            .thenReturn(samCardResponse2);

    cardTransactionManager.prepareSvGet(SvOperation.DEBIT, SvAction.DO). processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    assertThat(calypsoCard.getSvBalance()).isEqualTo(HexUtil.toInt(SV_D_BALANCE));
    assertThat(calypsoCard.getSvLastTNum()).isEqualTo(HexUtil.toShort(SV_D_TNUM));
    SvDebitLogRecord debitLog1 = calypsoCard.getSvDebitLogLastRecord();
    assertThat(debitLog1.getDebitDate()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_DATE));
    assertThat(debitLog1.getDebitTime()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_TIME));
    assertThat(debitLog1.getBalance()).isEqualTo(HexUtil.toInt(SV_D_LOG_BALANCE));
    assertThat(debitLog1.getAmount()).isEqualTo(HexUtil.toInt(SV_D_LOG_AMOUNT));
    assertThat(debitLog1.getKvc()).isEqualTo(HexUtil.toByte(SV_D_LOG_KVC));
    assertThat(debitLog1.getSamId()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_SAM_ID));
    assertThat(debitLog1.getSamTNum()).isEqualTo(HexUtil.toInt(SV_D_LOG_SAM_TNUM));
    assertThat(debitLog1.getSvTNum()).isEqualTo(HexUtil.toInt(SV_D_LOG_SV_TNUM));

    cardTransactionManager
            .prepareSvDebit(
                    HexUtil.toInt(SV_D_AMOUNT),
                    HexUtil.toByteArray(SV_D_DATE),
                    HexUtil.toByteArray(SV_D_TIME))
            . processCommands(CHANNEL_CONTROL_CLOSE_AFTER);

    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest1)), any(ChannelControl.class));
    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest2)), any(ChannelControl.class));
    verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest1)), any(ChannelControl.class));
    verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

    assertThat(calypsoCard.getSvBalance())
            .isEqualTo(HexUtil.toInt(SV_D_BALANCE) - HexUtil.toInt(SV_D_AMOUNT));
    assertThat(calypsoCard.getSvLastTNum()).isEqualTo(HexUtil.toInt(SV_D_TNUM) + 1);
    SvDebitLogRecord debitLog2 = calypsoCard.getSvDebitLogLastRecord();
    assertThat(debitLog2.getDebitDate()).isEqualTo(HexUtil.toByteArray(SV_D_DATE));
    assertThat(debitLog2.getDebitTime()).isEqualTo(HexUtil.toByteArray(SV_D_TIME));
    assertThat(debitLog2.getBalance())
            .isEqualTo(HexUtil.toInt(SV_D_BALANCE) - HexUtil.toInt(SV_D_AMOUNT));
    assertThat(debitLog2.getAmount()).isEqualTo(-HexUtil.toInt(SV_D_AMOUNT));
    assertThat(debitLog2.getKvc()).isEqualTo(HexUtil.toByte(SV_D_CURRENT_KVC));
    assertThat(debitLog2.getSamId()).isEqualTo(HexUtil.toByteArray(SV_D_SAM_ID));
    assertThat(debitLog2.getSamTNum()).isEqualTo(HexUtil.toInt(SAM_PREPARE_LOAD_RSP_TNUM));
    assertThat(debitLog2.getSvTNum()).isEqualTo(HexUtil.toInt(SV_D_TNUM) + 1);
  }

  @Test
  public void prepareSvDebit_whenOutOfSession_InExtendedMode_shouldUpdateReloadLog()
          throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED_WITH_STORED_VALUE);

    CardRequestSpi cardCardRequest1 = createCardRequest(CARD_SV_GET_DEBIT_EXT_CMD);
    CardResponseApi cardCardResponse1 = createCardResponse(CARD_SV_GET_DEBIT_EXT_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest1)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse1);

    CardRequestSpi cardCardRequest2 = createCardRequest(CARD_SV_DEBIT_EXT_CMD);
    CardResponseApi cardCardResponse2 = createCardResponse(CARD_SV_DEBIT_EXT_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest2)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse2);

    CardRequestSpi samCardRequest1 =
            createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_PREPARE_DEBIT_EXT_CMD);
    CardResponseApi samCardResponse1 = createCardResponse(SW1SW2_OK, SAM_PREPARE_DEBIT_EXT_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest1)), any(ChannelControl.class)))
            .thenReturn(samCardResponse1);

    CardRequestSpi samCardRequest2 = createCardRequest(SAM_SV_CHECK_EXT_CMD);
    CardResponseApi samCardResponse2 = createCardResponse(SW1SW2_OK);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class)))
            .thenReturn(samCardResponse2);

    cardTransactionManager.prepareSvGet(SvOperation.DEBIT, SvAction.DO). processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    assertThat(calypsoCard.getSvBalance()).isEqualTo(HexUtil.toInt(SV_D_BALANCE));
    assertThat(calypsoCard.getSvLastTNum()).isEqualTo(HexUtil.toShort(SV_D_TNUM));
    SvDebitLogRecord debitLog1 = calypsoCard.getSvDebitLogLastRecord();
    assertThat(debitLog1.getDebitDate()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_DATE));
    assertThat(debitLog1.getDebitTime()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_TIME));
    assertThat(debitLog1.getBalance()).isEqualTo(HexUtil.toInt(SV_D_LOG_BALANCE));
    assertThat(debitLog1.getAmount()).isEqualTo(HexUtil.toInt(SV_D_LOG_AMOUNT));
    assertThat(debitLog1.getKvc()).isEqualTo(HexUtil.toByte(SV_D_LOG_KVC));
    assertThat(debitLog1.getSamId()).isEqualTo(HexUtil.toByteArray(SV_D_LOG_SAM_ID));
    assertThat(debitLog1.getSamTNum()).isEqualTo(HexUtil.toInt(SV_D_LOG_SAM_TNUM));
    assertThat(debitLog1.getSvTNum()).isEqualTo(HexUtil.toInt(SV_D_LOG_SV_TNUM));

    cardTransactionManager
            .prepareSvDebit(
                    HexUtil.toInt(SV_D_AMOUNT),
                    HexUtil.toByteArray(SV_D_DATE),
                    HexUtil.toByteArray(SV_D_TIME))
            . processCommands(CHANNEL_CONTROL_CLOSE_AFTER);

    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest1)), any(ChannelControl.class));
    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest2)), any(ChannelControl.class));
    verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest1)), any(ChannelControl.class));
    verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

    assertThat(calypsoCard.getSvBalance())
            .isEqualTo(HexUtil.toInt(SV_D_BALANCE) - HexUtil.toInt(SV_D_AMOUNT));
    assertThat(calypsoCard.getSvLastTNum()).isEqualTo(HexUtil.toInt(SV_D_TNUM) + 1);
    SvDebitLogRecord debitLog2 = calypsoCard.getSvDebitLogLastRecord();
    assertThat(debitLog2.getDebitDate()).isEqualTo(HexUtil.toByteArray(SV_D_DATE));
    assertThat(debitLog2.getDebitTime()).isEqualTo(HexUtil.toByteArray(SV_D_TIME));
    assertThat(debitLog2.getBalance())
            .isEqualTo(HexUtil.toInt(SV_D_BALANCE) - HexUtil.toInt(SV_D_AMOUNT));
    assertThat(debitLog2.getAmount()).isEqualTo(-HexUtil.toInt(SV_D_AMOUNT));
    assertThat(debitLog2.getKvc()).isEqualTo(HexUtil.toByte(SV_D_CURRENT_KVC));
    assertThat(debitLog2.getSamId()).isEqualTo(HexUtil.toByteArray(SV_D_SAM_ID));
    assertThat(debitLog2.getSamTNum()).isEqualTo(HexUtil.toInt(SAM_PREPARE_LOAD_RSP_TNUM));
    assertThat(debitLog2.getSvTNum()).isEqualTo(HexUtil.toInt(SV_D_TNUM) + 1);
  }

  @Test(expected = IllegalStateException.class)
  public void prepareSvDebit_whenNoSvGetPreviouslyExecuted_shouldThrowISE() throws Exception {
    CardRequestSpi samCardRequest = createCardRequest(SAM_SV_CHECK_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
            .thenReturn(samCardResponse);
    cardTransactionManager.prepareSvDebit(1);
  }

  @Test(expected = IllegalStateException.class)
  public void prepareInvalidate_whenCardIsInvalidated_shouldThrowISE() throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED);
    cardTransactionManager.prepareInvalidate();
  }

  @Test
  public void prepareInvalidate_whenCardIsNotInvalidated_prepareInvalidateApdu() throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_INVALIDATE_CMD);
    CardResponseApi cardCardResponse = createCardResponse(SW1SW2_OK);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse);
    cardTransactionManager.prepareInvalidate();
    cardTransactionManager. processCommands(CHANNEL_CONTROL_KEEP_OPEN);
    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test(expected = IllegalStateException.class)
  public void prepareRehabilitate_whenCardIsNotInvalidated_shouldThrowISE() {
    cardTransactionManager.prepareRehabilitate();
  }

  @Test
  public void prepareRehabilitate_whenCardIsInvalidated_prepareInvalidateApdu() throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_REHABILITATE_CMD);
    CardResponseApi cardCardResponse = createCardResponse(SW1SW2_OK);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse);
    cardTransactionManager.prepareRehabilitate();
    cardTransactionManager. processCommands(CHANNEL_CONTROL_KEEP_OPEN);
    verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareEarlyMutualAuthentication_whenExtendedModeIsNotSupported_shouldThrowUOE()
          throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3);
    cardTransactionManager.prepareEarlyMutualAuthentication();
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareActivateEncryption_whenExtendedModeIsNotSupported_shouldThrowUOE()
          throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3);
    cardTransactionManager.prepareActivateEncryption();
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareDeactivateEncryption_whenExtendedModeIsNotSupported_shouldThrowUOE()
          throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3);
    cardTransactionManager.prepareDeactivateEncryption();
  }

  // @Test(expected = IllegalStateException.class) TODO activate on API version 2
  public void prepareEarlyMutualAuthentication_whenProcessedOutsideSession_shouldThrowISE()
          throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);
    cardTransactionManager.prepareEarlyMutualAuthentication();
    cardTransactionManager. processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }

  // @Test(expected = IllegalStateException.class) TODO activate on API version 2
  public void prepareActivateEncryption_whenProcessedOutsideSession_shouldThrowISE()
          throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);
    cardTransactionManager.prepareActivateEncryption();
    cardTransactionManager. processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }

  @Test(expected = IllegalStateException.class)
  public void prepareDeactivateEncryption_whenProcessedOutsideSession_shouldThrowISE()
          throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);
    cardTransactionManager.prepareDeactivateEncryption();
    cardTransactionManager. processCommands(CHANNEL_CONTROL_KEEP_OPEN);
  }

  @Test
  public void
  prepareEarlyMutualAuthenticationAndEncryption_whenExtendedModeIsNotSupportedAfterOpening_shouldThrowUOE()
          throws Exception {

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);

    // Mock
    CardRequestSpi samSelectDiversifierAndGetChallengeReq =
            createCardRequest(SAM_GET_CHALLENGE_EXTENDED_CMD);
    CardResponseApi samSelectDiversifierAndGetChallengeResp =
            createCardResponse(SAM_GET_CHALLENGE_EXTENDED_RSP);

    CardRequestSpi cardOssReq = createCardRequest(CARD_OPEN_SECURE_SESSION_EXTENDED_CMD);
    CardResponseApi cardOssResp =
            createCardResponse(CARD_OPEN_SECURE_SESSION_EXTENDED_NOT_SUPPORTED_RSP);

    CardRequestSpi samDigestInitAndInternalAuthReq =
            createCardRequest(
                    SAM_SELECT_DIVERSIFIER_CMD,
                    SAM_DIGEST_INIT_EXTENDED_NOT_SUPPORTED_OPEN_SECURE_SESSION_CMD,
                    SAM_DIGEST_INTERNAL_AUTHENTICATE_CMD);
    CardResponseApi samDigestInitAndInternalAuthResp =
            createCardResponse(SW1SW2_OK_RSP, SW1SW2_OK_RSP, SAM_DIGEST_INTERNAL_AUTHENTICATE_RSP);

    CardRequestSpi cardMssAuthReq = createCardRequest(CARD_MSS_AUTHENTICATION_CMD);
    CardResponseApi cardMssAuthResp = createCardResponse(SW1SW2_6985);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samSelectDiversifierAndGetChallengeReq)),
            any(ChannelControl.class)))
            .thenReturn(samSelectDiversifierAndGetChallengeResp);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestInitAndInternalAuthReq)),
            any(ChannelControl.class)))
            .thenReturn(samDigestInitAndInternalAuthResp);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardOssReq)), any(ChannelControl.class)))
            .thenReturn(cardOssResp);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardMssAuthReq)), any(ChannelControl.class)))
            .thenReturn(cardMssAuthResp);

    // Scenario
    assertThat(calypsoCard.isExtendedModeSupported()).isTrue();

    cardTransactionManager
            .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
            .prepareEarlyMutualAuthentication()
            .prepareActivateEncryption()
            .prepareDeactivateEncryption();
    try {
      cardTransactionManager. processCommands(CHANNEL_CONTROL_KEEP_OPEN);
      shouldHaveThrown(UnsupportedOperationException.class);
    } catch (UnsupportedOperationException ignored) {
    }

    assertThat(calypsoCard.isExtendedModeSupported()).isFalse();

    cardTransactionManager.prepareOpenSecureSession(WriteAccessLevel.DEBIT);
    try {
      cardTransactionManager.prepareEarlyMutualAuthentication();
      shouldHaveThrown(UnsupportedOperationException.class);
    } catch (UnsupportedOperationException ignored) {
    }
    try {
      cardTransactionManager.prepareActivateEncryption();
      shouldHaveThrown(UnsupportedOperationException.class);
    } catch (UnsupportedOperationException ignored) {
    }
    try {
      cardTransactionManager.prepareDeactivateEncryption();
      shouldHaveThrown(UnsupportedOperationException.class);
    } catch (UnsupportedOperationException ignored) {
    }
  }

  @Test
  public void
  prepareEarlyMutualAuthenticationAndEncryption_whenExtendedAndSession_shouldBeSuccessful()
          throws Exception {

    cardSecuritySetting.enableMultipleSession();
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED, 7);

    /** Process opening */
    CardRequestSpi samSelectDiversifierAndGetChallengeReq =
            createCardRequest(SAM_GET_CHALLENGE_EXTENDED_CMD);
    CardResponseApi samSelectDiversifierAndGetChallengeResp =
            createCardResponse(SAM_GET_CHALLENGE_EXTENDED_RSP);

    CardRequestSpi cardOssReq = createCardRequest(CARD_OPEN_SECURE_SESSION_EXTENDED_CMD);
    CardResponseApi cardOssResp = createCardResponse(CARD_OPEN_SECURE_SESSION_EXTENDED_RSP);

    // Digest Init + Mutual Authentication with encryption activation
    CardRequestSpi samDigestInitAndInternalAuthReq =
            createCardRequest(
                    SAM_SELECT_DIVERSIFIER_CMD,
                    SAM_DIGEST_INIT_EXTENDED_OPEN_SECURE_SESSION_CMD,
                    SAM_DIGEST_INTERNAL_AUTHENTICATE_CMD);
    CardResponseApi samDigestInitAndInternalAuthResp =
            createCardResponse(SW1SW2_OK_RSP, SW1SW2_OK_RSP, SAM_DIGEST_INTERNAL_AUTHENTICATE_RSP);

    CardRequestSpi cardMssAuthEncryptReq =
            createCardRequest(CARD_MSS_AUTHENTICATION_ENCRYPTION_CMD);
    CardResponseApi cardMssAuthEncryptResp =
            createCardResponse(CARD_MSS_AUTHENTICATION_ENCRYPTION_RSP);

    CardRequestSpi samDigestAuthReq = createCardRequest(SAM_DIGEST_AUTHENTICATE_EXTENDED_CMD);
    CardResponseApi samDigestAuthResp = createCardResponse(SW1SW2_OK_RSP);

    // Encrypted read record
    CardRequestSpi samDigestEncryptReqReq1 =
            createCardRequest(SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC1_CMD_CMD);
    CardResponseApi samDigestEncryptReqResp1 =
            createCardResponse(SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC1_CMD_RSP);

    CardRequestSpi cardEncryptReq1 = createCardRequest(CARD_READ_REC_ENCRYPTED_SFI1_REC1_CMD);
    CardResponseApi cardEncryptResp1 = createCardResponse(CARD_READ_REC_ENCRYPTED_SFI1_REC1_RSP);

    CardRequestSpi samDigestDecryptRespReq1 =
            createCardRequest(SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC1_RSP_CMD);
    CardResponseApi samDigestDecryptRespResp1 =
            createCardResponse(SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC1_RSP_RSP);

    // Mutual Authentication with encryption deactivation
    CardRequestSpi samDigestInternalAuthReq =
            createCardRequest(SAM_DIGEST_INTERNAL_AUTHENTICATE_CMD);
    CardResponseApi samDigestInternalAuthResp =
            createCardResponse(SAM_DIGEST_INTERNAL_AUTHENTICATE_RSP);

    CardRequestSpi cardMssAuthReq = createCardRequest(CARD_MSS_AUTHENTICATION_CMD);
    CardResponseApi cardMssAuthResp = createCardResponse(CARD_MSS_AUTHENTICATION_RSP);

    // Plain read + encryption activation
    CardRequestSpi cardMssAuthReqAndReadRec2AndMssEncryptReq =
            createCardRequest(
                    CARD_MSS_AUTHENTICATION_CMD, CARD_READ_REC_SFI1_REC2_CMD, CARD_MSS_ENCRYPTION_CMD);
    CardResponseApi cardMssAuthReqReadRec2AndMssEncryptResp =
            createCardResponse(CARD_MSS_AUTHENTICATION_RSP, CARD_READ_REC_SFI1_REC2_RSP, SW1SW2_OK_RSP);

    /** Process commands */

    // Mutual Authentication with encryption activation
    CardRequestSpi samDigestUpdateAndInternalAuthReq1 =
            createCardRequest(
                    SAM_DIGEST_UPDATE_MULTIPLE_READ_REC_SFI1_REC2_CMD,
                    SAM_DIGEST_INTERNAL_AUTHENTICATE_CMD);
    CardResponseApi samDigestUpdateAndInternalAuthResp1 =
            createCardResponse(SW1SW2_OK_RSP, SAM_DIGEST_INTERNAL_AUTHENTICATE_RSP);

    // Encrypted read record
    CardRequestSpi samDigestEncryptReqReq2 =
            createCardRequest(SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC3_CMD_CMD);
    CardResponseApi samDigestEncryptReqResp2 =
            createCardResponse(SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC3_CMD_RSP);

    CardRequestSpi cardEncryptReq2 = createCardRequest(CARD_READ_REC_ENCRYPTED_SFI1_REC3_CMD);
    CardResponseApi cardEncryptResp2 = createCardResponse(CARD_READ_REC_ENCRYPTED_SFI1_REC3_RSP);

    CardRequestSpi samDigestDecryptRespReq2 =
            createCardRequest(SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC3_RSP_CMD);
    CardResponseApi samDigestDecryptRespResp2 =
            createCardResponse(SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC3_RSP_RSP);

    // Encrypted update record
    CardRequestSpi samDigestEncryptReqReq3 =
            createCardRequest(SAM_DIGEST_UPDATE_ENCRYPTED_UPDATE_REC_SFI1_REC1_CMD_CMD);
    CardResponseApi samDigestEncryptReqResp3 =
            createCardResponse(SAM_DIGEST_UPDATE_ENCRYPTED_UPDATE_REC_SFI1_REC1_CMD_RSP);

    CardRequestSpi cardEncryptReq3 = createCardRequest(CARD_UPDATE_REC_ENCRYPTED_SFI1_REC1_CMD);
    CardResponseApi cardEncryptResp3 = createCardResponse(CARD_UPDATE_REC_ENCRYPTED_SFI1_REC1_RSP);

    CardRequestSpi samDigestDecryptRespReq3 =
            createCardRequest(SAM_DIGEST_UPDATE_ENCRYPTED_UPDATE_REC_SFI1_REC1_RSP_CMD);
    CardResponseApi samDigestDecryptRespResp3 =
            createCardResponse(SAM_DIGEST_UPDATE_ENCRYPTED_UPDATE_REC_SFI1_REC1_RSP_RSP);

    // Atomic closing
    CardRequestSpi samDigestCloseReq = createCardRequest(SAM_DIGEST_CLOSE_EXTENDED_CMD);
    CardResponseApi samDigestCloseResp = createCardResponse(SAM_DIGEST_CLOSE_EXTENDED_RSP);

    CardRequestSpi cardCssReq = createCardRequest(CARD_CLOSE_SECURE_SESSION_EXTENDED_CMD);
    CardResponseApi cardCssResp = createCardResponse(CARD_CLOSE_SECURE_SESSION_EXTENDED_RSP);

    // Atomic opening
    CardRequestSpi samGetChallengeReq = createCardRequest(SAM_GET_CHALLENGE_EXTENDED_CMD);
    CardResponseApi samGetChallengeResp = createCardResponse(SAM_GET_CHALLENGE_EXTENDED_RSP);

    CardRequestSpi cardOssAndMssEncryptReq =
            createCardRequest(CARD_OPEN_SECURE_SESSION_EXTENDED_CMD, CARD_MSS_ENCRYPTION_CMD);
    CardResponseApi cardOssAndMssEncryptResp =
            createCardResponse(CARD_OPEN_SECURE_SESSION_EXTENDED_RSP, SW1SW2_OK_RSP);

    // Encrypted update record
    CardRequestSpi samDigestInitAndEncryptReqReq4 =
            createCardRequest(
                    SAM_SELECT_DIVERSIFIER_CMD,
                    SAM_DIGEST_INIT_EXTENDED_OPEN_SECURE_SESSION_CMD,
                    SAM_DIGEST_UPDATE_ENCRYPTED_UPDATE_REC_SFI1_REC2_CMD_CMD);
    CardResponseApi samDigestInitAndEncryptReqResp4 =
            createCardResponse(
                    SW1SW2_OK_RSP, SW1SW2_OK_RSP, SAM_DIGEST_UPDATE_ENCRYPTED_UPDATE_REC_SFI1_REC2_CMD_RSP);

    CardRequestSpi samDigestDecryptRespReq4 =
            createCardRequest(SAM_DIGEST_UPDATE_ENCRYPTED_UPDATE_REC_SFI1_REC2_RSP_CMD);
    CardResponseApi samDigestDecryptRespResp4 =
            createCardResponse(SAM_DIGEST_UPDATE_ENCRYPTED_UPDATE_REC_SFI1_REC2_RSP_RSP);

    // MSS deactivate encryption
    CardRequestSpi cardEncryptReq4AndMssReq =
            createCardRequest(CARD_UPDATE_REC_ENCRYPTED_SFI1_REC2_CMD, CARD_MSS_CMD);
    CardResponseApi cardEncryptReq4AndMssResp =
            createCardResponse(CARD_UPDATE_REC_ENCRYPTED_SFI1_REC2_RSP, SW1SW2_OK_RSP);

    /** Process closing */

    // Plain read
    CardRequestSpi cardReadRec4Req = createCardRequest(CARD_READ_REC_SFI1_REC4_CMD);
    CardResponseApi cardReadRec4Resp = createCardResponse(CARD_READ_REC_SFI1_REC4_RSP);

    // Mutual Authentication with not encryption
    CardRequestSpi samDigestUpdateAndInternalAuthReq2 =
            createCardRequest(
                    SAM_DIGEST_UPDATE_MULTIPLE_READ_REC_SFI1_REC4_CMD,
                    SAM_DIGEST_INTERNAL_AUTHENTICATE_CMD);
    CardResponseApi samDigestUpdateAndInternalAuthResp2 =
            createCardResponse(SW1SW2_OK_RSP, SAM_DIGEST_INTERNAL_AUTHENTICATE_RSP);

    // Plain read + encryption activation
    CardRequestSpi cardMssAuthAndReadRec5AndMssEncryptReq =
            createCardRequest(
                    CARD_MSS_AUTHENTICATION_CMD, CARD_READ_REC_SFI1_REC5_CMD, CARD_MSS_ENCRYPTION_CMD);
    CardResponseApi cardMssAuthAndReadRec5AndMssEncryptResp =
            createCardResponse(CARD_MSS_AUTHENTICATION_RSP, CARD_READ_REC_SFI1_REC5_RSP, SW1SW2_OK_RSP);

    // Encrypted read record
    CardRequestSpi samDigestInitAndEncryptReqReq5 =
            createCardRequest(
                    SAM_DIGEST_UPDATE_MULTIPLE_READ_REC_SFI1_REC5_CMD,
                    SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC6_CMD_CMD);
    CardResponseApi samDigestInitAndEncryptReqResp5 =
            createCardResponse(SW1SW2_OK_RSP, SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC6_CMD_RSP);

    CardRequestSpi cardEncryptReq5 = createCardRequest(CARD_READ_REC_ENCRYPTED_SFI1_REC6_CMD);
    CardResponseApi cardEncryptResp5 = createCardResponse(CARD_READ_REC_ENCRYPTED_SFI1_REC6_RSP);

    CardRequestSpi samDigestDecryptRespReq5 =
            createCardRequest(SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC6_RSP_CMD);
    CardResponseApi samDigestDecryptRespResp5 =
            createCardResponse(SAM_DIGEST_UPDATE_ENCRYPTED_READ_REC_SFI1_REC6_RSP_RSP);

    /** Mock commands */
    when(cardReader.isContactless()).thenReturn(true);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samSelectDiversifierAndGetChallengeReq)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samSelectDiversifierAndGetChallengeResp);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestInitAndInternalAuthReq)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestInitAndInternalAuthResp);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestAuthReq)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestAuthResp);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestEncryptReqReq1)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestEncryptReqResp1);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestDecryptRespReq1)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestDecryptRespResp1);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestInternalAuthReq)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestInternalAuthResp);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestUpdateAndInternalAuthReq1)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestUpdateAndInternalAuthResp1);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestEncryptReqReq2)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestEncryptReqResp2);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestDecryptRespReq2)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestDecryptRespResp2);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestEncryptReqReq3)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestEncryptReqResp3);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestDecryptRespReq3)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestDecryptRespResp3);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestCloseReq)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestCloseResp);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samGetChallengeReq)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samGetChallengeResp);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestInitAndEncryptReqReq4)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestInitAndEncryptReqResp4);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestDecryptRespReq4)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestDecryptRespResp4);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestUpdateAndInternalAuthReq2)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestUpdateAndInternalAuthResp2);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestInitAndEncryptReqReq5)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestInitAndEncryptReqResp5);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samDigestDecryptRespReq5)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(samDigestDecryptRespResp5);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardOssReq)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardOssResp);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardMssAuthEncryptReq)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardMssAuthEncryptResp);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardEncryptReq1)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardEncryptResp1);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardMssAuthReq)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardMssAuthResp);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardMssAuthReqAndReadRec2AndMssEncryptReq)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardMssAuthReqReadRec2AndMssEncryptResp);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardEncryptReq2)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardEncryptResp2);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardEncryptReq3)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardEncryptResp3);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCssReq)), any(ChannelControl.class)))
            .thenReturn(cardCssResp);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardOssAndMssEncryptReq)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardOssAndMssEncryptResp);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardEncryptReq4AndMssReq)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardEncryptReq4AndMssResp);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardReadRec4Req)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardReadRec4Resp);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardMssAuthAndReadRec5AndMssEncryptReq)),
            eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardMssAuthAndReadRec5AndMssEncryptResp);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardEncryptReq5)), eq(ChannelControl.KEEP_OPEN)))
            .thenReturn(cardEncryptResp5);

    /** Scenario */
    cardTransactionManager
            .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
            .prepareEarlyMutualAuthentication() // Authentication
            .prepareActivateEncryption() // + encryption
            .prepareReadRecord((byte) 1, 1)
            .prepareEarlyMutualAuthentication() // Authentication
            .prepareDeactivateEncryption() // - encryption
            .prepareReadRecord((byte) 1, 2)
            .prepareActivateEncryption() // + encryption
            . processCommands(CHANNEL_CONTROL_KEEP_OPEN);
    cardTransactionManager
            .prepareEarlyMutualAuthentication() // Authentication
            .prepareEarlyMutualAuthentication() // Authentication (Twice consecutive call)
            .prepareReadRecord((byte) 1, 3)
            .prepareUpdateRecord((byte) 1, 1, new byte[] {(byte) 0xAA})
            .prepareUpdateRecord((byte) 1, 2, new byte[] {(byte) 0xBB}) // 2nd session
            .prepareDeactivateEncryption() // - encryption
            . processCommands(CHANNEL_CONTROL_KEEP_OPEN);
    cardTransactionManager
            .prepareReadRecord((byte) 1, 4)
            .prepareEarlyMutualAuthentication() // Authentication
            .prepareReadRecord((byte) 1, 5)
            .prepareActivateEncryption() // + encryption
            .prepareReadRecord((byte) 1, 6)
            .prepareCloseSecureSession()
            . processCommands(CHANNEL_CONTROL_CLOSE_AFTER);

    /** Check result */
    InOrder inOrder = inOrder(cardReader, samReader);
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samSelectDiversifierAndGetChallengeReq)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardOssReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestInitAndInternalAuthReq)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardMssAuthEncryptReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestAuthReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestEncryptReqReq1)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardEncryptReq1)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestDecryptRespReq1)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestInternalAuthReq)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardMssAuthReqAndReadRec2AndMssEncryptReq)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestAuthReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestUpdateAndInternalAuthReq1)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardMssAuthEncryptReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestAuthReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestEncryptReqReq2)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardEncryptReq2)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestDecryptRespReq2)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestEncryptReqReq3)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardEncryptReq3)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestDecryptRespReq3)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestCloseReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCssReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestAuthReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samGetChallengeReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardOssAndMssEncryptReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestInitAndEncryptReqReq4)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardEncryptReq4AndMssReq)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestDecryptRespReq4)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardReadRec4Req)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestUpdateAndInternalAuthReq2)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardMssAuthAndReadRec5AndMssEncryptReq)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestAuthReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestInitAndEncryptReqReq5)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardEncryptReq5)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestDecryptRespReq5)),
                    eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestCloseReq)), eq(ChannelControl.KEEP_OPEN));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCssReq)), eq(ChannelControl.CLOSE_AFTER));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samDigestAuthReq)), eq(ChannelControl.KEEP_OPEN));
  }

  @Test(expected = IllegalStateException.class)
  public void initSamContextForNextTransaction_whenNoSecuritySettings_shouldThrowISE() {
    cardTransactionManager =
            CalypsoExtensionService.getInstance()
                    .createCardTransactionWithoutSecurity(cardReader, calypsoCard);
    cardTransactionManager.initSamContextForNextTransaction();
  }

  @Test(expected = IllegalStateException.class)
  public void initSamContextForNextTransaction_whenCommandsArePending_shouldThrowISE() {
    cardTransactionManager.prepareReadRecord(FILE7, 1);
    cardTransactionManager.initSamContextForNextTransaction();
  }

  @Test
  public void initSamContextForNextTransaction_shouldUpdateChallengeInCryptoService()
          throws Exception {

    CardRequestSpi samCardRequest = createCardRequest(SAM_GET_CHALLENGE_CMD);
    CardResponseApi samCardResponse = createCardResponse(SAM_GET_CHALLENGE_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
            .thenReturn(samCardResponse);

    cardTransactionManager.initSamContextForNextTransaction();

    verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    assertThat(HexUtil.toHex(calypsoSam.popChallenge())).isEqualTo(SAM_CHALLENGE_HEX);
    assertThat(calypsoSam.popChallenge()).isNull();
  }

  @Test
  public void
  initSamContextForNextTransaction_whenANewSessionIsOpen_shouldInteractWithCardAndCryptoManagerWithoutGetChallenge()
          throws Exception {

    // Init context
    CardRequestSpi samCardRequest = createCardRequest(SAM_GET_CHALLENGE_CMD);
    CardResponseApi samCardResponse = createCardResponse(SAM_GET_CHALLENGE_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
            .thenReturn(samCardResponse);

    cardTransactionManager.initSamContextForNextTransaction();

    verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader);

    // Next session
    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
            .thenReturn(cardCardResponse);

    cardTransactionManager.prepareOpenSecureSession(WriteAccessLevel.DEBIT). processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    InOrder inOrder = inOrder(samReader, cardReader);
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));

    samCardRequest =
            createCardRequest(
                    SAM_SELECT_DIVERSIFIER_CMD,
                    SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD,
                    SAM_DIGEST_UPDATE_MULTIPLE_READ_REC_SFI7_REC1_L29_CMD,
                    SAM_DIGEST_CLOSE_CMD);
    CardRequestSpi cardCardRequestRead = createCardRequest(CARD_READ_REC_SFI7_REC1_L29_CMD_HEX);
    CardRequestSpi cardCardRequestClose = createCardRequest(CARD_CLOSE_SECURE_SESSION_CMD);

    samCardResponse =
            createCardResponse(SW1SW2_OK_RSP, SW1SW2_OK_RSP, SW1SW2_OK_RSP, SAM_DIGEST_CLOSE_RSP);
    CardResponseApi cardCardResponseRead = createCardResponse(CARD_READ_REC_SFI7_REC1_RSP_HEX);
    CardResponseApi cardCardResponseClose = createCardResponse(CARD_CLOSE_SECURE_SESSION_RSP);

    CardRequestSpi samCardRequest2 = createCardRequest(SAM_DIGEST_AUTHENTICATE_CMD);
    CardResponseApi samCardResponse2 = createCardResponse(SW1SW2_OK_RSP);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
            .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequestRead)), any(ChannelControl.class)))
            .thenReturn(cardCardResponseRead);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequestClose)), any(ChannelControl.class)))
            .thenReturn(cardCardResponseClose);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class)))
            .thenReturn(samCardResponse2);

    cardTransactionManager
            .prepareReadRecords(FILE7, 1, 1, 29)
            .prepareCloseSecureSession()
            . processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    inOrder = inOrder(samReader, cardReader);
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequestRead)), any(ChannelControl.class));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    inOrder
            .verify(cardReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(cardCardRequestClose)), any(ChannelControl.class));
    inOrder
            .verify(samReader)
            .transmitCardRequest(
                    argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }
}
