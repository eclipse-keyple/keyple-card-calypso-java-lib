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
import static org.assertj.core.api.Assertions.shouldHaveThrown;
import static org.mockito.Mockito.mock;

import org.calypsonet.terminal.calypso.GetDataTag;
import org.calypsonet.terminal.calypso.SelectFileControl;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.card.CalypsoCardSelection;
import org.calypsonet.terminal.card.CardSelectionResponseApi;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardSelectionRequestSpi;
import org.calypsonet.terminal.card.spi.CardSelectorSpi;
import org.calypsonet.terminal.card.spi.ParseException;
import org.eclipse.keyple.core.util.HexUtil;
import org.junit.Before;
import org.junit.Test;

public class CalypsoCardSelectionAdapterTest {
  CalypsoCardSelectionAdapter cardSelection;

  @Before
  public void setUp() {
    cardSelection =
        (CalypsoCardSelectionAdapter) CalypsoExtensionService.getInstance().createCardSelection();
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterByCardProtocol_whenCardProtocolIsNull_shouldThrowIAE() {
    cardSelection.filterByCardProtocol(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterByCardProtocol_whenCardProtocolIsEmpty_shouldThrowIAE() {
    cardSelection.filterByCardProtocol("");
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterByPowerOnData_whenPowerOnDataRegexIsNull_shouldThrowIAE() {
    cardSelection.filterByPowerOnData(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterByPowerOnData_whenPowerOnDataRegexIsEmpty_shouldThrowIAE() {
    cardSelection.filterByPowerOnData("");
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterByPowerOnData_whenPowerOnDataRegexIsInvalid_shouldThrowIAE() {
    cardSelection.filterByPowerOnData("[");
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterByDfName_whenAidIsNull_shouldThrowIAE() {
    byte[] nullArray = null;
    cardSelection.filterByDfName(nullArray);
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterByDfName_whenAidLengthIsLessThan5_shouldThrowIAE() {
    cardSelection.filterByDfName(new byte[4]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterByDfName_whenAidLengthIsMoreThan16_shouldThrowIAE() {
    cardSelection.filterByDfName(new byte[17]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void filterByDfName_whenAidIsNotHexString_shouldThrowIAE() {
    cardSelection.filterByDfName("11223344Z5");
  }

  @Test(expected = IllegalArgumentException.class)
  public void setFileOccurrence_whenFileOccurrenceIsNull_shouldThrowIAE() {
    cardSelection.setFileOccurrence(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void setFileControlInformation_whenFileControlIsNull_shouldThrowIAE() {
    cardSelection.setFileControlInformation(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void addSuccessfulStatusWord_whenStatusWordIsNegative_shouldThrowIAE() {
    cardSelection.addSuccessfulStatusWord(-1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void addSuccessfulStatusWord_whenStatusWordIsHigherThanFFFF_shouldThrowIAE() {
    cardSelection.addSuccessfulStatusWord(0x10000);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSelectFile_whenLidIsNull_shouldThrowIAE() {
    byte[] nullArray = null;
    cardSelection.prepareSelectFile(nullArray);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSelectFile_whenLidIsLessThan2ByteLong_shouldThrowIAE() {
    cardSelection.prepareSelectFile(new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSelectFile_whenLidIsMoreThan2ByteLong_shouldThrowIAE() {
    cardSelection.prepareSelectFile(new byte[3]);
  }

  @Test
  public void prepareSelectFile_whenLidIs1234_shouldProduceSelectFileApduWithLid1234() {
    cardSelection.prepareSelectFile((short) 0x1234);
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00A4090002123400");
  }

  @Test
  public void
      prepareSelectFile_whenSelectFileControlIsNext_shouldProduceSelectFileApduWithSelectFileControlNext() {
    cardSelection.prepareSelectFile(SelectFileControl.NEXT_EF);
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00A4020202000000");
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecord_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardSelection.prepareReadRecord((byte) 31, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecord_whenRecordNumberIsLessThan0_shouldThrowIAE() {
    cardSelection.prepareReadRecord((byte) 0x07, -1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecord_whenRecordNumberIsMoreThan250_shouldThrowIAE() {
    cardSelection.prepareReadRecord((byte) 0x07, 251);
  }

  @Test
  public void
      prepareReadRecord_whenSfi07RecNumber1_shouldPrepareReadRecordApduWithSfi07RecNumber1() {
    cardSelection.prepareReadRecord((byte) 0x07, 1);
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B2013C00");
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenSfiIsNegative_shouldThrowIAE() {
    cardSelection.prepareReadBinary((byte) -1, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardSelection.prepareReadBinary((byte) 31, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenOffsetIsNegative_shouldThrowIAE() {
    cardSelection.prepareReadBinary((byte) 1, -1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE() {
    cardSelection.prepareReadBinary((byte) 1, 32768, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenNbBytesToReadIsLessThan1_shouldThrowIAE() {
    cardSelection.prepareReadBinary((byte) 1, 1, 0);
  }

  @Test
  public void
      prepareReadBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand() {
    cardSelection.prepareReadBinary((byte) 1, 256, 1);
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B0810001");
    commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(1);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B0010001");
  }

  @Test
  public void prepareReadBinary_whenNbBytesToReadIsLessThanPayLoad_shouldPrepareOneCommand() {
    cardSelection.prepareReadBinary((byte) 1, 0, 1);
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B0810001");
  }

  @Test
  public void
      prepareReadBinary_whenNbBytesToReadIsGreaterThanPayLoad_shouldPrepareMultipleCommands() {
    cardSelection.prepareReadBinary((byte) 1, 0, 251);
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B08100FA");
    commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(1);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B081FA01");
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadCounter_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardSelection.prepareReadCounter((byte) 31, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void preparePreOpenSecureSession_whenWriteAccessLevelIsNull_shouldThrowIAE() {
    cardSelection.preparePreOpenSecureSession(null);
  }

  @Test
  public void preparePreOpenSecureSession_whenIsAlreadyPrepared_shouldThrowISE() {
    cardSelection.preparePreOpenSecureSession(WriteAccessLevel.LOAD);
    try {
      cardSelection.preparePreOpenSecureSession(WriteAccessLevel.LOAD);
      shouldHaveThrown(IllegalStateException.class);
    } catch (IllegalStateException ignored) {
    }
  }

  @Test
  public void
      preparePreOpenSecureSession_whenWriteAccessLevelIsLoad_shouldAddCmd_Cla00_Ins8A_P102_P202_Lc01_Data00_Le00() {
    cardSelection.preparePreOpenSecureSession(WriteAccessLevel.LOAD);
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("008A0202010000");
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareGetData_whenGetDataTagIsNull_shouldThrowIAE() {
    cardSelection.prepareGetData(null);
  }

  @Test
  public void
      getCardSelectionRequest_whenNotSettingAreAdded_shouldReturnResponseContainingANotDefaultCardSelector() {
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    CardSelectorSpi cardSelector = cardSelectionRequest.getCardSelector();
    assertThat(cardSelector).isNotNull();
    assertThat(cardSelector.getCardProtocol()).isNull();
    assertThat(cardSelector.getPowerOnDataRegex()).isNull();
    assertThat(cardSelector.getAid()).isNull();
    assertThat(cardSelector.getFileOccurrence()).isEqualTo(CardSelectorSpi.FileOccurrence.FIRST);
    assertThat(cardSelector.getFileControlInformation())
        .isEqualTo(CardSelectorSpi.FileControlInformation.FCI);
    assertThat(cardSelector.getSuccessfulSelectionStatusWords()).containsExactly(0x9000);
  }

  @Test
  public void
      getCardSelectionRequest_whenCardProtocolIsSet_shouldReturnResponseContainingACardSelectorWithCardProtocol() {
    cardSelection.filterByCardProtocol("PROTOCOL_1");
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    CardSelectorSpi cardSelector = cardSelectionRequest.getCardSelector();
    assertThat(cardSelector.getCardProtocol()).isEqualTo("PROTOCOL_1");
  }

  @Test
  public void
      getCardSelectionRequest_whenPowerOnDataRegexIsSet_shouldReturnResponseContainingACardSelectorWithPowerOnDataRegex() {
    cardSelection.filterByPowerOnData("1122334455*");
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    CardSelectorSpi cardSelector = cardSelectionRequest.getCardSelector();
    assertThat(cardSelector.getPowerOnDataRegex()).isEqualTo("1122334455*");
  }

  @Test
  public void
      getCardSelectionRequest_whenAidIsSet_shouldReturnResponseContainingACardSelectorWithAid() {
    cardSelection.filterByDfName("6677889900");
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    CardSelectorSpi cardSelector = cardSelectionRequest.getCardSelector();
    assertThat(HexUtil.toHex(cardSelector.getAid())).isEqualTo("6677889900");
  }

  @Test
  public void
      getCardSelectionRequest_whenFileOccurrenceIsSet_shouldReturnResponseContainingACardSelectorWithFileOccurrence() {
    cardSelection.setFileOccurrence(CalypsoCardSelection.FileOccurrence.PREVIOUS);
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    CardSelectorSpi cardSelector = cardSelectionRequest.getCardSelector();
    assertThat(cardSelector.getFileOccurrence()).isEqualTo(CardSelectorSpi.FileOccurrence.PREVIOUS);
  }

  @Test
  public void
      getCardSelectionRequest_whenFileControlIsSet_shouldReturnResponseContainingACardSelectorWithFileControl() {
    cardSelection.setFileControlInformation(
        CalypsoCardSelection.FileControlInformation.NO_RESPONSE);
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    CardSelectorSpi cardSelector = cardSelectionRequest.getCardSelector();
    assertThat(cardSelector.getFileControlInformation())
        .isEqualTo(CardSelectorSpi.FileControlInformation.NO_RESPONSE);
  }

  @Test
  public void
      getCardSelectionRequest_whenSuccessfulStatusWordIsAdded_shouldReturnResponseContainingACardSelectorWithSuccessfulStatusWord() {
    cardSelection.addSuccessfulStatusWord(0x1234);
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    CardSelectorSpi cardSelector = cardSelectionRequest.getCardSelector();
    assertThat(cardSelector.getSuccessfulSelectionStatusWords()).containsExactly(0x9000, 0x1234);
  }

  @Test
  public void
      getCardSelectionRequest_whenAcceptInvalidatedCardIsInvoked_shouldReturnResponseContainingACardSelectorWithSuccessfulStatusWord6283() {
    cardSelection.acceptInvalidatedCard();
    CardSelectionRequestSpi cardSelectionRequest = cardSelection.getCardSelectionRequest();
    CardSelectorSpi cardSelector = cardSelectionRequest.getCardSelector();
    assertThat(cardSelector.getSuccessfulSelectionStatusWords()).containsExactly(0x9000, 0x6283);
  }

  @Test(expected = ParseException.class)
  public void parse_whenCommandsResponsesMismatch_shouldThrowParseException() throws Exception {
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    cardSelection.prepareGetData(GetDataTag.FCI_FOR_CURRENT_DF);
    cardSelection.parse(cardSelectionResponseApi);
  }
}
