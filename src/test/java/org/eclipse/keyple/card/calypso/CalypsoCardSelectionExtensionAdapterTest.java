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

import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.GetDataTag;
import org.eclipse.keypop.calypso.card.SelectFileControl;
import org.eclipse.keypop.calypso.card.WriteAccessLevel;
import org.eclipse.keypop.card.CardSelectionResponseApi;
import org.eclipse.keypop.card.ParseException;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardSelectionRequestSpi;
import org.junit.Before;
import org.junit.Test;

public class CalypsoCardSelectionExtensionAdapterTest {
  CalypsoCardSelectionExtensionAdapter cardSelectionExtension;

  @Before
  public void setUp() {
    cardSelectionExtension =
        (CalypsoCardSelectionExtensionAdapter)
            CalypsoExtensionService.getInstance()
                .getCalypsoCardApiFactory()
                .createCalypsoCardSelectionExtension();
  }

  @Test
  public void prepareSelectFile_whenLidIs1234_shouldProduceSelectFileApduWithLid1234() {
    cardSelectionExtension.prepareSelectFile((short) 0x1234);
    CardSelectionRequestSpi cardSelectionRequest = cardSelectionExtension.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00A4090002123400");
  }

  @Test
  public void
      prepareSelectFile_whenSelectFileControlIsNext_shouldProduceSelectFileApduWithSelectFileControlNext() {
    cardSelectionExtension.prepareSelectFile(SelectFileControl.NEXT_EF);
    CardSelectionRequestSpi cardSelectionRequest = cardSelectionExtension.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00A4020202000000");
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecord_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardSelectionExtension.prepareReadRecord((byte) 31, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecord_whenRecordNumberIsLessThan0_shouldThrowIAE() {
    cardSelectionExtension.prepareReadRecord((byte) 0x07, -1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecord_whenRecordNumberIsMoreThan250_shouldThrowIAE() {
    cardSelectionExtension.prepareReadRecord((byte) 0x07, 251);
  }

  @Test
  public void
      prepareReadRecord_whenSfi07RecNumber1_shouldPrepareReadRecordApduWithSfi07RecNumber1() {
    cardSelectionExtension.prepareReadRecord((byte) 0x07, 1);
    CardSelectionRequestSpi cardSelectionRequest = cardSelectionExtension.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B2013C00");
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenSfiIsNegative_shouldThrowIAE() {
    cardSelectionExtension.prepareReadBinary((byte) -1, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardSelectionExtension.prepareReadBinary((byte) 31, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenOffsetIsNegative_shouldThrowIAE() {
    cardSelectionExtension.prepareReadBinary((byte) 1, -1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE() {
    cardSelectionExtension.prepareReadBinary((byte) 1, 32768, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadBinary_whenNbBytesToReadIsLessThan1_shouldThrowIAE() {
    cardSelectionExtension.prepareReadBinary((byte) 1, 1, 0);
  }

  @Test
  public void
      prepareReadBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand() {
    cardSelectionExtension.prepareReadBinary((byte) 1, 256, 1);
    CardSelectionRequestSpi cardSelectionRequest = cardSelectionExtension.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B0810001");
    commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(1);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B0010001");
  }

  @Test
  public void prepareReadBinary_whenNbBytesToReadIsLessThanPayLoad_shouldPrepareOneCommand() {
    cardSelectionExtension.prepareReadBinary((byte) 1, 0, 1);
    CardSelectionRequestSpi cardSelectionRequest = cardSelectionExtension.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B0810001");
  }

  @Test
  public void
      prepareReadBinary_whenNbBytesToReadIsGreaterThanPayLoad_shouldPrepareMultipleCommands() {
    cardSelectionExtension.prepareReadBinary((byte) 1, 0, 251);
    CardSelectionRequestSpi cardSelectionRequest = cardSelectionExtension.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B08100FA");
    commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(1);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("00B081FA01");
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadCounter_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardSelectionExtension.prepareReadCounter((byte) 31, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void preparePreOpenSecureSession_whenWriteAccessLevelIsNull_shouldThrowIAE() {
    cardSelectionExtension.preparePreOpenSecureSession(null);
  }

  @Test
  public void preparePreOpenSecureSession_whenIsAlreadyPrepared_shouldThrowISE() {
    cardSelectionExtension.preparePreOpenSecureSession(WriteAccessLevel.LOAD);
    try {
      cardSelectionExtension.preparePreOpenSecureSession(WriteAccessLevel.LOAD);
      shouldHaveThrown(IllegalStateException.class);
    } catch (IllegalStateException ignored) {
    }
  }

  @Test
  public void
      preparePreOpenSecureSession_whenWriteAccessLevelIsLoad_shouldAddCmd_Cla00_Ins8A_P102_P202_Lc01_Data00_Le00() {
    cardSelectionExtension.preparePreOpenSecureSession(WriteAccessLevel.LOAD);
    CardSelectionRequestSpi cardSelectionRequest = cardSelectionExtension.getCardSelectionRequest();
    ApduRequestSpi commandApdu = cardSelectionRequest.getCardRequest().getApduRequests().get(0);
    assertThat(HexUtil.toHex(commandApdu.getApdu())).isEqualTo("008A0202010000");
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareGetData_whenGetDataTagIsNull_shouldThrowIAE() {
    cardSelectionExtension.prepareGetData(null);
  }

  @Test
  public void
      getCardSelectionRequest_whenAcceptInvalidatedCardIsInvoked_shouldReturnResponseContainingACardSelectorWithSuccessfulStatusWord6283() {
    cardSelectionExtension.acceptInvalidatedCard();
    CardSelectionRequestSpi cardSelectionRequest = cardSelectionExtension.getCardSelectionRequest();
    assertThat(cardSelectionRequest.getSuccessfulSelectionStatusWords())
        .containsExactly(0x9000, 0x6283);
  }

  @Test(expected = ParseException.class)
  public void parse_whenCommandsResponsesMismatch_shouldThrowParseException() throws Exception {
    CardSelectionResponseApi cardSelectionResponseApi = mock(CardSelectionResponseApi.class);
    cardSelectionExtension.prepareGetData(GetDataTag.FCI_FOR_CURRENT_DF);
    cardSelectionExtension.parse(cardSelectionResponseApi);
  }
}
