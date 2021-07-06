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
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.calypsonet.terminal.calypso.GetDataTag;
import org.calypsonet.terminal.calypso.SelectFileControl;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.transaction.*;
import org.calypsonet.terminal.card.*;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.calypsonet.terminal.reader.CardReader;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.InOrder;

public class CardTransactionManagerAdapterTest {

  private static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3 =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C20051410019000";
  private static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C21051410019000";
  private static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C22051410019000";
  private static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2_WITH_STORED_VALUE =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C12051410019000";
  private static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C20051410016283";
  private static final String SAM_C1_POWER_ON_DATA = "3B3F9600805A4880C120501711223344829000";
  private static final String FCI_REV10 =
      "6F228408315449432E494341A516BF0C13C708   0000000011223344 5307060A01032003119000";
  private static final String FCI_REV24 =
      "6F2A8410A0000004040125090101000000000000A516BF0C13C708 0000000011223344 53070A2E11420001019000";
  private static final String FCI_REV31 =
      "6F238409315449432E49434131A516BF0C13C708 0000000011223344 53070A3C23121410019000";
  private static final String FCI_STORED_VALUE_REV31 =
      "6F238409315449432E49434131A516BF0C13C708 0000000011223344 53070A3C23201410019000";
  private static final String FCI_REV31_INVALIDATED =
      "6F238409315449432E49434131A516BF0C13C708 0000000011223344 53070A3C23121410016283";

  private static final String ATR1 = "3B3F9600805A0080C120000012345678829000";

  private static final String PIN_OK = "1234";
  private static final String CIPHER_PIN_OK = "1122334455667788";
  private static final String PIN_5_DIGITS = "12345";

  private static final byte FILE7 = (byte) 0x07;
  private static final byte FILE8 = (byte) 0x08;
  private static final byte FILE9 = (byte) 0x09;
  private static final byte FILE10 = (byte) 0x10;
  private static final byte FILE11 = (byte) 0x11;

  private static final String SW1SW2_OK = "9000";
  private static final String SW1SW2_KO = "6700";
  private static final String SW1SW2_INCORRECT_SIGNATURE = "6988";
  private static final String SAM_CHALLENGE = "C1C2C3C4";
  private static final String CARD_CHALLENGE = "C1C2C3C4C5C6C7C8";
  private static final String CARD_DIVERSIFIER = "0000000011223344";
  private static final String SAM_SIGNATURE = "12345678";
  private static final String CARD_SIGNATURE = "9ABCDEF0";

  private static final String FILE7_REC1_29B =
      "7111111111111111111111111111111111111111111111111111111111";
  private static final String FILE7_REC2_29B =
      "7222222222222222222222222222222222222222222222222222222222";
  private static final String FILE7_REC3_29B =
      "7333333333333333333333333333333333333333333333333333333333";
  private static final String FILE7_REC4_29B =
      "7444444444444444444444444444444444444444444444444444444444";
  private static final String FILE7_REC1_4B = "00112233";
  private static final String FILE8_REC1_29B =
      "8111111111111111111111111111111111111111111111111111111111";
  private static final String FILE8_REC1_5B = "8122334455";
  private static final String FILE8_REC1_4B = "84332211";
  private static final String FILE9_REC1_4B = "8899AABB";

  private static final String FILE10_REC1_COUNTER =
      "00112200000000000000000000000000000000000000000000000000000000000000";
  private static final String FILE11_REC1_COUNTER =
      "00221100000000000000000000000000000000000000000000000000000000000000";

  private static final String FILE7_REC1_COUNTER1 = "A55AA5";
  private static final String FILE7_REC1_COUNTER2 = "5AA55A";

  private static final String REC_COUNTER_1000 = "0003E8";
  private static final String REC_COUNTER_2000 = "0007D0";

  private static final byte[] FILE7_REC1_29B_BYTES = ByteArrayUtil.fromHex(FILE7_REC1_29B);
  private static final byte[] FILE7_REC2_29B_BYTES = ByteArrayUtil.fromHex(FILE7_REC2_29B);
  private static final byte[] FILE7_REC3_29B_BYTES = ByteArrayUtil.fromHex(FILE7_REC3_29B);
  private static final byte[] FILE7_REC4_29B_BYTES = ByteArrayUtil.fromHex(FILE7_REC4_29B);
  private static final byte[] FILE8_REC1_29B_BYTES = ByteArrayUtil.fromHex(FILE8_REC1_29B);
  private static final byte[] FILE8_REC1_5B_BYTES = ByteArrayUtil.fromHex(FILE8_REC1_5B);
  private static final byte[] FILE8_REC1_4B_BYTES = ByteArrayUtil.fromHex(FILE8_REC1_4B);

  private static final short LID_3F00 = (short) 0x3F00;
  private static final short LID_0002 = (short) 0x0002;
  private static final short LID_0003 = (short) 0x0003;
  private static final String LID_3F00_STR = "3F00";
  private static final String LID_0002_STR = "0002";
  private static final String LID_0003_STR = "0003";
  private static final String ACCESS_CONDITIONS_1234 = "10100000";
  private static final String KEY_INDEXES_1234 = "01030101";
  private static final String ACCESS_CONDITIONS_0002 = "1F000000";
  private static final String KEY_INDEXES_0002 = "01010101";
  private static final String ACCESS_CONDITIONS_0003 = "01100000";
  private static final String KEY_INDEXES_0003 = "01020101";

  private static final String SW1SW2_OK_RSP = SW1SW2_OK;
  private static final String CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD =
      "008A0B3904" + SAM_CHALLENGE + "00";
  private static final String CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP =
      "030490980030791D" + FILE7_REC1_29B + SW1SW2_OK;
  private static final String CARD_OPEN_SECURE_SESSION_SFI7_REC1_NOT_RATIFIED_RSP =
      "030490980130791D" + FILE7_REC1_29B + SW1SW2_OK;
  private static final String CARD_OPEN_SECURE_SESSION_CMD = "008A030104" + SAM_CHALLENGE + "00";
  private static final String CARD_OPEN_SECURE_SESSION_RSP = "0304909800307900" + SW1SW2_OK;
  private static final String CARD_OPEN_SECURE_SESSION_KVC_78_CMD = "0304909800307800" + SW1SW2_OK;
  private static final String CARD_OPEN_SECURE_SESSION_SFI7_REC1_2_4_CMD = "948A8B3804C1C2C3C400";
  private static final String CARD_OPEN_SECURE_SESSION_SFI7_REC1_2_4_RSP =
      "79030D307124B928480805CBABAE30001240800000000000000000000000000000009000";
  private static final String CARD_CLOSE_SECURE_SESSION_CMD = "008E800004" + SAM_SIGNATURE + "00";
  private static final String CARD_CLOSE_SECURE_SESSION_NOT_RATIFIED_CMD =
      "008E000004" + SAM_SIGNATURE + "00";
  private static final String CARD_CLOSE_SECURE_SESSION_RSP = CARD_SIGNATURE + SW1SW2_OK;
  private static final String CARD_CLOSE_SECURE_SESSION_FAILED_RSP = "6988";
  private static final String CARD_ABORT_SECURE_SESSION_CMD = "008E000000";
  private static final String CARD_RATIFICATION_CMD = "00B2000000";
  private static final String CARD_RATIFICATION_RSP = "6B00";

  private static final String CARD_READ_REC_SFI7_REC1_CMD = "00B2013C00";
  private static final String CARD_READ_REC_SFI7_REC1_RSP = FILE7_REC1_29B + SW1SW2_OK;
  private static final String CARD_READ_REC_SFI7_REC1_6B_COUNTER_CMD = "00B2013C06";
  private static final String CARD_READ_REC_SFI7_REC1_6B_COUNTER_RSP =
      FILE7_REC1_COUNTER1 + FILE7_REC1_COUNTER2 + SW1SW2_OK;
  private static final String CARD_READ_REC_SFI8_REC1_CMD = "00B2014400";
  private static final String CARD_READ_REC_SFI8_REC1_RSP = FILE8_REC1_29B + SW1SW2_OK;
  private static final String CARD_READ_REC_SFI7_REC3_4_CMD = "00B2033D3E";
  private static final String CARD_READ_REC_SFI7_REC3_4_RSP =
      "031D" + FILE7_REC3_29B + "041D" + FILE7_REC4_29B + SW1SW2_OK;
  private static final String CARD_READ_REC_SFI10_REC1_CMD = "00B2018400";
  private static final String CARD_READ_REC_SFI10_REC1_RSP = FILE10_REC1_COUNTER + SW1SW2_OK;
  private static final String CARD_READ_REC_SFI11_REC1_CMD = "00B2018C00";
  private static final String CARD_READ_REC_SFI11_REC1_RSP = FILE11_REC1_COUNTER + SW1SW2_OK;
  private static final String CARD_UPDATE_REC_SFI7_REC1_4B_CMD = "00DC013C0400112233";
  private static final String CARD_UPDATE_REC_SFI8_REC1_29B_CMD = "00DC01441D" + FILE8_REC1_29B;
  private static final String CARD_UPDATE_REC_SFI8_REC1_5B_CMD = "00DC014405" + FILE8_REC1_5B;
  private static final String CARD_UPDATE_REC_SFI8_REC1_4B_CMD = "00DC014404" + FILE8_REC1_4B;
  private static final String CARD_UPDATE_REC_SFI8_REC1_29B_2_4_CMD = "94DC01441D" + FILE8_REC1_29B;
  private static final String CARD_WRITE_REC_SFI8_REC1_4B_CMD = "00D2014404" + FILE8_REC1_4B;
  private static final String CARD_APPEND_REC_SFI9_REC1_4B_CMD = "00E2004804" + FILE9_REC1_4B;
  private static final String CARD_DECREASE_SFI10_REC1_100U_CMD = "003001800300006400";
  private static final String CARD_DECREASE_SFI10_REC1_100U_RSP = "0010BE9000";
  private static final String CARD_INCREASE_SFI11_REC1_100U_CMD = "003201880300006400";
  private static final String CARD_INCREASE_SFI11_REC1_100U_RSP = "0022759000";

  private static final String CARD_SELECT_FILE_CURRENT_CMD = "00A4090002000000";
  private static final String CARD_SELECT_FILE_FIRST_CMD = "00A4020002000000";
  private static final String CARD_SELECT_FILE_NEXT_CMD = "00A4020202000000";
  private static final String CARD_SELECT_FILE_1234_CMD = "00A4090002123400";
  private static final String CARD_SELECT_FILE_1234_RSP =
      "85170001000000" + ACCESS_CONDITIONS_1234 + KEY_INDEXES_1234 + "00777879616770003F009000";

  private static final String CARD_GET_DATA_FCI_CMD = "00CA006F00";
  private static final String CARD_GET_DATA_FCP_CMD = "00CA006200";
  private static final String CARD_GET_DATA_FCI_RSP = SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3;
  private static final String CARD_GET_DATA_FCP_RSP = CARD_SELECT_FILE_1234_RSP;

  private static final String CARD_VERIFY_PIN_PLAIN_OK_CMD =
      "0020000004" + ByteArrayUtil.toHex(PIN_OK.getBytes());
  private static final String CARD_VERIFY_PIN_ENCRYPTED_OK_CMD = "0020000008" + CIPHER_PIN_OK;
  private static final String CARD_CHECK_PIN_CMD = "0020000000";
  private static final String CARD_VERIFY_PIN_OK_RSP = "9000";
  private static final String CARD_VERIFY_PIN_KO_RSP = "63C2";

  private static int SV_BALANCE = 0x123456;
  private static String SV_BALANCE_STR = "123456";
  private static final String CARD_SV_GET_DEBIT_CMD = "007C000900";
  private static final String CARD_SV_GET_DEBIT_RSP =
      "790073A54BC97DFA" + SV_BALANCE_STR + "FFFE0000000079123456780000DD0000160072" + SW1SW2_OK;
  private static final String CARD_SV_GET_RELOAD_CMD = "007C000700";
  private static final String CARD_PRIME_REV2_SV_GET_RELOAD_CMD = "FA7C000700";
  private static final String CARD_SV_GET_RELOAD_RSP =
      "79007221D35F0E36"
          + SV_BALANCE_STR
          + "000000790000001A0000020000123456780000DB0070"
          + SW1SW2_OK;
  private static final String CARD_SV_RELOAD_CMD =
      "00B89591171600000079000000020000123456780000DE2C8CB3D280";
  private static final String CARD_SV_RELOAD_RSP = "A54BC9" + SW1SW2_OK;
  private static final String CARD_SV_DEBIT_CMD =
      "00BACD001434FFFE0000000079123456780000DF0C9437AABB";
  private static final String CARD_SV_DEBIT_RSP = "A54BC9" + SW1SW2_OK;
  private static final String CARD_SV_UNDEBIT_CMD =
      "00BCCD00143400020000000079123456780000DF0C9437AABB";
  private static final String CARD_SV_UNDEBIT_RSP = "A54BC9" + SW1SW2_OK;
  private static final String CARD_READ_SV_LOAD_LOG_FILE_CMD = "00B201A400";
  private static final String CARD_READ_SV_LOAD_LOG_FILE_RSP =
      "000000780000001A0000020000AABBCCDD0000DB007000000000000000" + SW1SW2_OK;
  private static final String CARD_READ_SV_DEBIT_LOG_FILE_CMD = "00B201AD5D";
  private static final String CARD_READ_SV_DEBIT_LOG_FILE_RSP =
      "011DFFFE0000000079AABBCC010000DA000018006F00000000000000000000"
          + "021DFFFE0000000079AABBCC020000DA000018006F00000000000000000000"
          + "031DFFFE0000000079AABBCC030000DA000018006F00000000000000000000"
          + SW1SW2_OK;

  private static final String CARD_INVALIDATE_CMD = "0004000000";
  private static final String CARD_REHABILITATE_CMD = "0044000000";

  private static final String CARD_GET_CHALLENGE_CMD = "0084000008";
  private static final String CARD_GET_CHALLENGE_RSP = CARD_CHALLENGE + SW1SW2_OK;

  private static final String SAM_SELECT_DIVERSIFIER_CMD = "8014000008" + CARD_DIVERSIFIER;
  private static final String SAM_GET_CHALLENGE_CMD = "8084000004";
  private static final String SAM_GET_CHALLENGE_RSP = SAM_CHALLENGE + SW1SW2_OK;
  private static final String SAM_DIGEST_INIT_OPEN_SECURE_SESSION_SFI7_REC1_CMD =
      "808A00FF273079030490980030791D" + FILE7_REC1_29B;
  private static final String SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD =
      "808A00FF0A30790304909800307900";
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_CMD = "808C00000500B2013C00";
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_RSP_CMD =
      "808C00001F\" + FILE7_REC1_29B+ \"9000";
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI8_REC1_RSP_CMD =
      "808C00001F" + FILE8_REC1_29B + "9000";
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_RSP =
      "808C00001F" + FILE7_REC1_29B + SW1SW2_OK;
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI8_REC1_CMD = "808C00000500B2014400";
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI10_REC1_CMD = "808C00000500B2018C00";
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI10_REC1_RSP_CMD =
      "808C000024001122000000000000000000000000000000000000000000000000000000000000009000";
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI11_REC1_CMD = "808C00000500B2018400";
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI11_REC1_RSP_CMD =
      "808C000024002211000000000000000000000000000000000000000000000000000000000000009000";
  private static final String SAM_DIGEST_UPDATE_RSP_OK_CMD = "808C0000029000";
  private static final String SAM_DIGEST_UPDATE_UPDATE_REC_SFI8_REC1_29B_CMD =
      "808C00002200DC01441D" + FILE8_REC1_29B;
  private static final String SAM_DIGEST_UPDATE_UPDATE_REC_SFI8_REC1_5B_CMD =
      "808C00000A00DC0144058122334455";
  private static final String SAM_DIGEST_UPDATE_UPDATE_REC_SFI8_REC1_4B_CMD =
      "808C00000900DC014404" + FILE8_REC1_4B;
  private static final String SAM_DIGEST_UPDATE_UPDATE_REC_SFI7_REC1_4B_CMD =
      "808C00000900DC013C04" + FILE7_REC1_4B;
  private static final String SAM_DIGEST_UPDATE_DECREASE_SFI10_CMD = "808C0000080030018003000064";
  private static final String SAM_DIGEST_UPDATE_DECREASE_SFI10_RESP = "808C0000050010BE9000";
  private static final String SAM_DIGEST_UPDATE_INCREASE_SFI11_CMD = "808C0000080032018803000064";
  private static final String SAM_DIGEST_UPDATE_INCREASE_SFI11_RESP = "808C0000050022759000";
  private static final String SAM_DIGEST_UPDATE_WRITE_REC_SFI8_REC1_4B_CMD =
      "808C00000900D2014404" + FILE8_REC1_4B;
  private static final String SAM_DIGEST_UPDATE_APPEND_REC_SFI9_REC1_4B_CMD =
      "808C00000900E2004804" + FILE9_REC1_4B;
  private static final String SAM_DIGEST_CLOSE_CMD = "808E000004";
  private static final String SAM_DIGEST_CLOSE_RSP = SAM_SIGNATURE + SW1SW2_OK;
  private static final String SAM_DIGEST_AUTHENTICATE_CMD = "8082000004" + CARD_SIGNATURE;
  private static final String SAM_DIGEST_AUTHENTICATE_FAILED = "6988";

  private static final String SAM_CARD_CIPHER_PIN_CMD =
      "801280FF060000" + ByteArrayUtil.toHex(PIN_OK.getBytes());
  private static final String SAM_CARD_CIPHER_PIN_RSP = CIPHER_PIN_OK + SW1SW2_OK;
  private static final String SAM_GIVE_RANDOM_CMD = "8086000008" + CARD_CHALLENGE;
  private static final String SAM_GIVE_RANDOM_RSP = SW1SW2_OK;
  private static final String SAM_PREPARE_LOAD_CMD =
      "805601FF367C00070079007221D35F0E36"
          + SV_BALANCE_STR
          + "000000790000001A0000020000123456780000DB00709000B80000170000000079000000020000";
  private static final String SAM_PREPARE_LOAD_RSP = "9591160000DE2C8CB3D280" + SW1SW2_OK;
  private static final String SAM_PREPARE_DEBIT_CMD =
      "805401FF307C000900790073A54BC97DFA"
          + SV_BALANCE_STR
          + "FFFE0000000079123456780000DD00001600729000BA00001400FFFE0000000079";
  private static final String SAM_PREPARE_DEBIT_RSP = "CD00340000DF0C9437AABB" + SW1SW2_OK;
  private static final String SAM_PREPARE_UNDEBIT_CMD =
      "805C01FF307C000900790073A54BC97DFA"
          + SV_BALANCE_STR
          + "FFFE0000000079123456780000DD00001600729000BC0000140000020000000079";
  private static final String SAM_PREPARE_UNDEBIT_RSP = "CD00340000DF0C9437AABB" + SW1SW2_OK;
  private static final String SAM_SV_CHECK_CMD = "8058000003A54BC9";

  private CardTransactionManager cardTransactionManager;
  private CalypsoCardAdapter calypsoCard;
  private ReaderMock cardReader;
  private ReaderMock samReader;
  private CardSelectionResponseApi samCardSelectionResponse;
  private CalypsoSamAdapter calypsoSam;
  private CardSecuritySetting cardSecuritySetting;

  interface ReaderMock extends CardReader, ProxyReaderApi {}

  @Before
  public void setUp() {
    cardReader = mock(ReaderMock.class);
    calypsoCard = new CalypsoCardAdapter();
    calypsoCard.initializeWithFci(
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3)));
    samReader = mock(ReaderMock.class);
    samCardSelectionResponse = mock(CardSelectionResponseApi.class);
    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);
    calypsoSam = new CalypsoSamAdapter(samCardSelectionResponse);
    cardSecuritySetting = mock(CardSecuritySetting.class);
    when(cardSecuritySetting.getSamReader()).thenReturn(samReader);
    when(cardSecuritySetting.getCalypsoSam()).thenReturn(calypsoSam);
    when(cardSecuritySetting.isSessionKeyAuthorized(any(Byte.class), any(Byte.class)))
        .thenReturn(true);
    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);
  }

  @Test
  public void getCardReader_shouldReturnCardReader() {
    assertThat(cardTransactionManager.getCardReader()).isSameAs(cardReader);
  }

  @Test
  public void getCalypsoCard_shouldReturnCalypsoCard() {
    assertThat(cardTransactionManager.getCalypsoCard()).isSameAs(calypsoCard);
  }

  @Test
  public void getCardSecuritySetting_shouldReturnCardSecuritySetting() {
    assertThat(cardTransactionManager.getCardSecuritySetting()).isSameAs(cardSecuritySetting);
  }

  @Test
  public void processOpening_whenNoCommandsArePrepared_shouldExchangeApduWithCardAndSam()
      throws Exception {
    CardRequestSpi samCardRequest =
        createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.processOpening(WriteAccessLevel.DEBIT);
    InOrder inOrder = inOrder(cardReader, samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test
  public void processOpening_whenOneReadRecordIsPrepared_shouldExchangeApduWithCardAndSam()
      throws Exception {
    CardRequestSpi samCardRequest =
        createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareReadRecordFile(FILE7, 1);
    cardTransactionManager.processOpening(WriteAccessLevel.DEBIT);
    InOrder inOrder = inOrder(cardReader, samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test
  public void processOpening_whenTwoReadRecordIsPrepared_shouldExchangeApduWithCardAndSam()
      throws Exception {
    CardRequestSpi samCardRequest =
        createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD);
    CardRequestSpi cardCardRequest =
        createCardRequest(CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD, CARD_READ_REC_SFI8_REC1_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP);
    CardResponseApi cardCardResponse =
        createCardResponse(CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP, CARD_READ_REC_SFI8_REC1_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareReadRecordFile(FILE7, 1);
    cardTransactionManager.prepareReadRecordFile(FILE8, 1);
    cardTransactionManager.processOpening(WriteAccessLevel.DEBIT);
    InOrder inOrder = inOrder(cardReader, samReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test(expected = UnauthorizedKeyException.class)
  public void processOpening_whenKeyNotAuthorized_shouldThrowUnauthorizedKeyException()
      throws Exception {
    when(cardSecuritySetting.isSessionKeyAuthorized(any(Byte.class), any(Byte.class)))
        .thenReturn(false);
    CardRequestSpi samCardRequest =
        createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.processOpening(WriteAccessLevel.DEBIT);
  }

  @Test
  public void processCardCommands_whenOutOfSession_shouldExchangeApduWithCardOnly()
      throws Exception {
    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_READ_REC_SFI7_REC1_CMD, CARD_READ_REC_SFI8_REC1_CMD, CARD_READ_REC_SFI10_REC1_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(
            CARD_READ_REC_SFI7_REC1_RSP, CARD_READ_REC_SFI8_REC1_RSP, CARD_READ_REC_SFI10_REC1_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareReadRecordFile(FILE7, 1);
    cardTransactionManager.prepareReadRecordFile(FILE8, 1);
    cardTransactionManager.prepareReadRecordFile(FILE10, 1);
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test(expected = IllegalStateException.class)
  public void processClosing_whenNoSessionIsOpen_shouldThrowISE() {
    cardTransactionManager.processClosing();
  }

  @Test
  public void processClosing_whenASessionIsOpen_shouldExchangeApduWithCardAndSam()
      throws Exception {
    // open sesion
    CardRequestSpi samCardRequest =
        createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.processOpening(WriteAccessLevel.DEBIT);

    InOrder inOrder = inOrder(samReader, cardReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));

    samCardRequest =
        createCardRequest(SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD, SAM_DIGEST_CLOSE_CMD);
    cardCardRequest = createCardRequest(CARD_CLOSE_SECURE_SESSION_CMD);

    samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_DIGEST_CLOSE_RSP);
    cardCardResponse = createCardResponse(CARD_CLOSE_SECURE_SESSION_RSP);

    CardRequestSpi samCardRequest2 = createCardRequest(SAM_DIGEST_AUTHENTICATE_CMD);
    CardResponseApi samCardResponse2 = createCardResponse(SW1SW2_OK_RSP);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class)))
        .thenReturn(samCardResponse2);

    cardTransactionManager.processClosing();
    inOrder = inOrder(samReader, cardReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test(expected = CardCloseSecureSessionException.class)
  public void processClosing_whenCloseSessionFails_shouldThrowCardCloseSecureSessionException()
      throws Exception {
    // open sesion
    CardRequestSpi samCardRequest =
        createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.processOpening(WriteAccessLevel.DEBIT);

    InOrder inOrder = inOrder(samReader, cardReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));

    samCardRequest =
        createCardRequest(SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD, SAM_DIGEST_CLOSE_CMD);
    cardCardRequest = createCardRequest(CARD_CLOSE_SECURE_SESSION_CMD);

    samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_DIGEST_CLOSE_RSP);
    cardCardResponse = createCardResponse(SW1SW2_INCORRECT_SIGNATURE);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.processClosing();
  }

  @Test(expected = SessionAuthenticationException.class)
  public void processClosing_whenCardAuthenticationFails_shouldThrowSessionAuthenticationException()
      throws Exception {
    // open session
    CardRequestSpi samCardRequest =
        createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.processOpening(WriteAccessLevel.DEBIT);

    InOrder inOrder = inOrder(samReader, cardReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));

    samCardRequest =
        createCardRequest(SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD, SAM_DIGEST_CLOSE_CMD);
    cardCardRequest = createCardRequest(CARD_CLOSE_SECURE_SESSION_CMD);

    samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_DIGEST_CLOSE_RSP);
    cardCardResponse = createCardResponse(CARD_CLOSE_SECURE_SESSION_RSP);

    CardRequestSpi samCardRequest2 = createCardRequest(SAM_DIGEST_AUTHENTICATE_CMD);
    CardResponseApi samCardResponse2 = createCardResponse(SW1SW2_INCORRECT_SIGNATURE);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest2)), any(ChannelControl.class)))
        .thenReturn(samCardResponse2);

    cardTransactionManager.processClosing();
  }

  @Test(expected = IllegalStateException.class)
  public void processCancel_whenNoSessionIsOpen_shouldThrowISE() {
    cardTransactionManager.processCancel();
  }

  @Test
  public void processCancel_whenASessionIsOpen_shouldSendCancelApduToCard() throws Exception {
    // open session
    CardRequestSpi samCardRequest =
        createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.processOpening(WriteAccessLevel.DEBIT);

    InOrder inOrder = inOrder(samReader, cardReader);
    inOrder
        .verify(samReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class));
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    cardCardRequest = createCardRequest(CARD_ABORT_SECURE_SESSION_CMD);
    cardCardResponse = createCardResponse(SW1SW2_OK);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.processCancel();
    inOrder = inOrder(samReader, cardReader);
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test(expected = IllegalArgumentException.class)
  public void processVerifyPin_whenPINIsNull_shouldThrowIAE() {
    byte[] nullArray = null;
    cardTransactionManager.processVerifyPin(nullArray);
  }

  @Test(expected = IllegalArgumentException.class)
  public void processVerifyPin_whenPINIsNot4Digits_shouldThrowIAE() {
    cardTransactionManager.processVerifyPin(PIN_5_DIGITS);
  }

  @Test(expected = IllegalStateException.class)
  public void processVerifyPin_whenPINIsNotFirstCommand_shouldThrowISE() {
    calypsoCard.initializeWithFci(
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN)));
    cardTransactionManager.prepareReadRecordFile(FILE7, 1);
    cardTransactionManager.processVerifyPin(PIN_OK);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void processVerifyPin_whenPINNotAvailable_shouldThrowUOE() {
    cardTransactionManager.processVerifyPin(PIN_OK);
  }

  @Test
  public void processVerifyPin_whenPINTransmittedInPlainText_shouldSendApduVerifyPIN()
      throws Exception {
    when(cardSecuritySetting.isPinPlainTransmissionEnabled()).thenReturn(true);
    calypsoCard.initializeWithFci(
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN)));
    CardRequestSpi cardCardRequest = createCardRequest(CARD_VERIFY_PIN_PLAIN_OK_CMD);
    CardResponseApi cardCardResponse = createCardResponse(SW1SW2_OK);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.processVerifyPin(PIN_OK);
    InOrder inOrder = inOrder(samReader, cardReader);
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSelectFile_whenLidIsNull_shouldThrowIAE() {
    byte[] nullArray = null;
    cardTransactionManager.prepareSelectFile(nullArray);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSelectFile_whenLidIsLessThan2ByteLong_shouldThrowIAE() {
    cardTransactionManager.prepareSelectFile(new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSelectFile_whenLidIsMoreThan2ByteLong_shouldThrowIAE() {
    cardTransactionManager.prepareSelectFile(new byte[3]);
  }

  @Test
  public void prepareSelectFile_whenLidIs1234_shouldPrepareSelectFileApduWith1234()
      throws Exception {
    byte[] lid = new byte[] {(byte) 0x12, (byte) 0x34};
    CardRequestSpi cardCardRequest = createCardRequest(CARD_SELECT_FILE_1234_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SELECT_FILE_1234_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSelectFile(lid);
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordFile_whenSfiIsHigherThan31_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordFile((byte) 32, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordFile_whenRecordNumberIsLessThan0_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordFile(FILE7, -1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordFile_whenRecordNumberIsMoreThan255_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordFile(FILE7, 256);
  }

  @Test
  public void
      prepareReadRecordFile_whenSfi07RecNumber1_shouldPrepareReadRecordApduWithSfi07RecNumber1()
          throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_READ_REC_SFI7_REC1_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_READ_REC_SFI7_REC1_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareReadRecordFile(FILE7, 1);
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordFile_api2_whenSfiIsHigherThan31_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordFile((byte) 32, 1, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordFile_api2_whenFirstRecordNumberIsLessThan0_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordFile(FILE7, -1, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordFile_api2_whenFirstRecordNumberIsMoreThan255_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordFile(FILE7, 256, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordFile_api2_whenNumberOfRecordsIsLessThan0_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordFile(FILE7, 1, -1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadRecordFile_api2_whenNumberOfRecordIsMoreThan255_shouldThrowIAE() {
    cardTransactionManager.prepareReadRecordFile(FILE7, 1, 256, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadCounterFile_whenSfiIsHigherThan31_shouldThrowIAE() {
    cardTransactionManager.prepareReadCounterFile((byte) 32, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareAppendRecord_whenSfiIsHigherThan31_shouldThrowIAE() {
    cardTransactionManager.prepareAppendRecord((byte) 32, new byte[3]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareAppendRecord_whenRecordDataIsNull_shouldThrowIAE() {
    cardTransactionManager.prepareAppendRecord(FILE7, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateRecord_whenSfiIsHigherThan31_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateRecord((byte) 32, 1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateRecord_whenRecordNumberIsHigherThan255_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateRecord(FILE7, 256, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareUpdateRecord_whenRecordDataIsNull_shouldThrowIAE() {
    cardTransactionManager.prepareUpdateRecord(FILE7, 1, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteRecord_whenSfiIsHigherThan31_shouldThrowIAE() {
    cardTransactionManager.prepareWriteRecord((byte) 32, 1, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareWriteRecord_whenRecordNumberIsHigherThan255_shouldThrowIAE() {
    cardTransactionManager.prepareWriteRecord(FILE7, 256, new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounter_whenSfiIsHigherThan31_shouldThrowIAE() {
    cardTransactionManager.prepareIncreaseCounter((byte) 32, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounter_whenValueIsLessThan0_shouldThrowIAE() {
    cardTransactionManager.prepareIncreaseCounter(FILE7, 1, -1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounter_whenValueIsHigherThan16777215_shouldThrowIAE() {
    cardTransactionManager.prepareIncreaseCounter(FILE7, 1, 16777216);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareIncreaseCounter_whenRecordNumberIsHigherThan255_shouldThrowIAE() {
    cardTransactionManager.prepareIncreaseCounter(FILE7, 256, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounter_whenSfiIsHigherThan31_shouldThrowIAE() {
    cardTransactionManager.prepareDecreaseCounter((byte) 32, 1, 1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounter_whenValueIsLessThan0_shouldThrowIAE() {
    cardTransactionManager.prepareDecreaseCounter(FILE7, 1, -1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounter_whenValueIsHigherThan16777215_shouldThrowIAE() {
    cardTransactionManager.prepareDecreaseCounter(FILE7, 1, 16777216);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareDecreaseCounter_whenRecordNumberIsHigherThan255_shouldThrowIAE() {
    cardTransactionManager.prepareDecreaseCounter(FILE7, 256, 1);
  }

  @Test(expected = IllegalStateException.class)
  public void prepareSetCounter_whenCounterNotPreviouslyRead_shouldThrowISE() {
    cardTransactionManager.prepareSetCounter(FILE7, 1, 1);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareCheckPinStatus_whenPinFeatureIsNotAvailable_shouldThrowISE() {
    cardTransactionManager.prepareCheckPinStatus();
  }

  @Test
  public void prepareCheckPinStatus_whenPinFeatureIsAvailable_shouldPrepareCheckPinStatusApdu()
      throws Exception {
    calypsoCard.initializeWithFci(
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN)));
    CardRequestSpi cardCardRequest = createCardRequest(CARD_CHECK_PIN_CMD);
    CardResponseApi cardCardResponse = createCardResponse(SW1SW2_OK);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareCheckPinStatus();
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
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
    calypsoCard.initializeWithFci(
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE)));
    CardRequestSpi cardCardRequest = createCardRequest(CARD_SV_GET_DEBIT_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SV_GET_DEBIT_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSvGet(SvOperation.DEBIT, SvAction.DO);
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test
  public void prepareSvGet_whenSvOperationReload_shouldPrepareSvGetReloadApdu() throws Exception {
    calypsoCard.initializeWithFci(
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE)));
    CardRequestSpi cardCardRequest = createCardRequest(CARD_SV_GET_RELOAD_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SV_GET_RELOAD_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSvGet(SvOperation.RELOAD, SvAction.DO);
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test
  public void prepareSvGet_whenSvOperationReloadWithPrimeRev2_shouldPrepareSvGetReloadApdu()
      throws Exception {
    calypsoCard.initializeWithFci(
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2_WITH_STORED_VALUE)));
    CardRequestSpi cardCardRequest = createCardRequest(CARD_PRIME_REV2_SV_GET_RELOAD_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SV_GET_RELOAD_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSvGet(SvOperation.RELOAD, SvAction.DO);
    cardTransactionManager.processCardCommands();
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

  @Test(expected = IllegalStateException.class)
  public void prepareSvDebit_whenNoSvGetPreviouslyExecuted_shouldThrowISE() throws Exception {
    CardRequestSpi samCardRequest = createCardRequest(SAM_SV_CHECK_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK);
    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    cardTransactionManager.prepareSvDebit(1);
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareSvReadAllLogs_whenPinFeatureIsNotAvailable_shouldThrowISE() {
    cardTransactionManager.prepareSvReadAllLogs();
  }

  @Test(expected = UnsupportedOperationException.class)
  public void prepareSvReadAllLogs_whenNotAnSVApplication_shouldThrowISE() {
    calypsoCard.initializeWithFci(
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE)));
    cardTransactionManager.prepareSvReadAllLogs();
  }

  @Test(expected = IllegalStateException.class)
  public void prepareInvalidate_whenCardIsInvalidated_shouldThrowISE() {
    calypsoCard.initializeWithFci(
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED)));
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
    cardTransactionManager.processCardCommands();
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
    calypsoCard.initializeWithFci(
        new ApduResponseAdapter(
            ByteArrayUtil.fromHex(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED)));
    CardRequestSpi cardCardRequest = createCardRequest(CARD_REHABILITATE_CMD);
    CardResponseApi cardCardResponse = createCardResponse(SW1SW2_OK);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareRehabilitate();
    cardTransactionManager.processCardCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  private CardRequestSpi createCardRequest(String... apduCommands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    for (String apduCommand : apduCommands) {
      apduRequests.add(new ApduRequestAdapter(ByteArrayUtil.fromHex(apduCommand)));
    }
    return new CardRequestAdapter(apduRequests, false);
  }

  private CardResponseApi createCardResponse(String... apduCommandResponses) {
    List<ApduResponseApi> apduResponses = new ArrayList<ApduResponseApi>();
    for (String apduResponse : apduCommandResponses) {
      apduResponses.add(new ApduResponseAdapter(ByteArrayUtil.fromHex(apduResponse)));
    }
    return new CardResponseAdapter(apduResponses, true);
  }

  public class CardRequestMatcher implements ArgumentMatcher<CardRequestSpi> {
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
}
