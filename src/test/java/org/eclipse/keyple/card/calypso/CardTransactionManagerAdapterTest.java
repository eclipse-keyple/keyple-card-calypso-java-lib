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

import java.util.*;
import org.calypsonet.terminal.calypso.GetDataTag;
import org.calypsonet.terminal.calypso.SelectFileControl;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.card.FileHeader;
import org.calypsonet.terminal.calypso.transaction.*;
import org.calypsonet.terminal.card.*;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.calypsonet.terminal.reader.CardReader;
import org.eclipse.keyple.core.util.HexUtil;
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
  private static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2 =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C02051410019000";
  private static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2_WITH_STORED_VALUE =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C12051410019000";
  private static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C20051410016283";
  private static final String SELECT_APPLICATION_RESPONSE_LIGHT =
      "6F238409315449432E49434134A516BF0C13C70800000000112233445307064390312B01009000";
  private static final String SAM_C1_POWER_ON_DATA = "3B3F9600805A4880C120501711223344829000";
  private static final String HSM_C1_POWER_ON_DATA = "3B3F9600805A4880C108501711223344829000";
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
  private static final String NEW_PIN = "4567";
  private static final String CIPHER_PIN_VERIFICATION_OK = "1122334455667788";
  private static final String CIPHER_PIN_UPDATE_OK = "88776655443322111122334455667788";
  private static final String PIN_5_DIGITS = "12345";
  private static final byte PIN_CIPHERING_KEY_KIF = 0x11;
  private static final byte PIN_CIPHERING_KEY_KVC = 0x22;

  private static final byte FILE7 = (byte) 0x07;
  private static final byte FILE8 = (byte) 0x08;
  private static final byte FILE9 = (byte) 0x09;
  private static final byte FILE10 = (byte) 0x10;
  private static final byte FILE11 = (byte) 0x11;

  private static final String SW1SW2_OK = "9000";
  private static final String SW1SW2_KO = "6700";
  private static final String SW1SW2_6200 = "6200";
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

  private static final byte[] FILE7_REC1_29B_BYTES = HexUtil.toByteArray(FILE7_REC1_29B);
  private static final byte[] FILE7_REC2_29B_BYTES = HexUtil.toByteArray(FILE7_REC2_29B);
  private static final byte[] FILE7_REC3_29B_BYTES = HexUtil.toByteArray(FILE7_REC3_29B);
  private static final byte[] FILE7_REC4_29B_BYTES = HexUtil.toByteArray(FILE7_REC4_29B);
  private static final byte[] FILE8_REC1_29B_BYTES = HexUtil.toByteArray(FILE8_REC1_29B);
  private static final byte[] FILE8_REC1_5B_BYTES = HexUtil.toByteArray(FILE8_REC1_5B);
  private static final byte[] FILE8_REC1_4B_BYTES = HexUtil.toByteArray(FILE8_REC1_4B);

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

  private static final String CIPHERED_KEY =
      "000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000";

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
  private static final String CARD_READ_REC_SFI7_REC1_L29_CMD = "00B2013C1D";
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
  private static final String CARD_READ_RECORDS_FROM1_TO2_CMD = "00B2010D06";
  private static final String CARD_READ_RECORDS_FROM1_TO2_RSP = "010111020122" + SW1SW2_OK;
  private static final String CARD_READ_RECORDS_FROM3_TO4_CMD = "00B2030D06";
  private static final String CARD_READ_RECORDS_FROM3_TO4_RSP = "030133040144" + SW1SW2_OK;
  private static final String CARD_READ_RECORDS_FROM5_TO5_CMD = "00B2050C01";
  private static final String CARD_READ_RECORDS_FROM5_TO5_RSP = "55" + SW1SW2_OK;
  private static final String CARD_UPDATE_REC_SFI7_REC1_4B_CMD = "00DC013C0400112233";
  private static final String CARD_UPDATE_REC_SFI8_REC1_29B_CMD = "00DC01441D" + FILE8_REC1_29B;
  private static final String CARD_UPDATE_REC_SFI8_REC1_5B_CMD = "00DC014405" + FILE8_REC1_5B;
  private static final String CARD_UPDATE_REC_SFI8_REC1_4B_CMD = "00DC014404" + FILE8_REC1_4B;
  private static final String CARD_UPDATE_REC_SFI8_REC1_29B_2_4_CMD = "94DC01441D" + FILE8_REC1_29B;
  private static final String CARD_WRITE_REC_SFI8_REC1_4B_CMD = "00D2014404" + FILE8_REC1_4B;
  private static final String CARD_APPEND_REC_SFI9_REC1_4B_CMD = "00E2004804" + FILE9_REC1_4B;
  private static final String CARD_DECREASE_SFI10_CNT1_100U_CMD = "003001080300006400";
  private static final String CARD_DECREASE_SFI10_CNT1_4286U_RSP = "0010BE9000";
  private static final String CARD_INCREASE_SFI11_CNT1_100U_CMD = "003201080300006400";
  private static final String CARD_INCREASE_SFI11_CNT1_8821U_RSP = "0022759000";
  private static final String CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_C3_3_CMD =
      "003A00080C01000001020000020300000300";
  private static final String CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_C3_33_RSP =
      "0100001102000022030000339000";
  private static final String CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_CMD =
      "003A000808010000010200000200";
  private static final String CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_RSP = "01000011020000229000";
  private static final String CARD_INCREASE_MULTIPLE_SFI1_C3_3_CMD = "003A0008040300000300";
  private static final String CARD_INCREASE_MULTIPLE_SFI1_C3_33_RSP = "030000339000";
  private static final String CARD_DECREASE_MULTIPLE_SFI1_C1_11_C2_22_C8_88_CMD =
      "003800080C01000011020000220800008800";
  private static final String CARD_DECREASE_MULTIPLE_SFI1_C1_111_C2_222_C8_888_RSP =
      "0100011102000222080008889000";
  private static final String
      CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_CMD =
          "00A2010F070000021234FFFF00";
  private static final String
      CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_RSP = "020406" + SW1SW2_OK;
  private static final String
      CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_56FF_CMD =
          "00A2010F07000002123456FF00";
  private static final String
      CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_56FF_RSP = "020406" + SW1SW2_OK;
  private static final String
      CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_5677_CMD =
          "00A2010F070000021234567700";
  private static final String
      CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_5677_RSP = "020406" + SW1SW2_OK;
  private static final String
      CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_CMD =
          "00A20227078103021234FFFF00";
  private static final String
      CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_RSP =
          "020406112233123456" + SW1SW2_OK;
  private static final String CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_CMD =
      "00B3010D045402030100";
  private static final String CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_RSP =
      "1122" + SW1SW2_6200;
  private static final String CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NBBYTE1_CMD =
      "00B3030D045402030100";
  private static final String CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NBBYTE1_RSP =
      "3344" + SW1SW2_6200;
  private static final String CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NBBYTE1_CMD =
      "00B3050D045402030100";
  private static final String CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NBBYTE1_RSP = "55" + SW1SW2_OK;
  private static final String CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD = "00B0810001";
  private static final String CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP = "11" + SW1SW2_OK;
  private static final String CARD_READ_BINARY_SFI0_OFFSET256_1B_CMD = "00B0010001";
  private static final String CARD_READ_BINARY_SFI0_OFFSET256_1B_RSP = "66" + SW1SW2_OK;
  private static final String CARD_READ_BINARY_SFI1_OFFSET0_2B_CMD = "00B0810002";
  private static final String CARD_READ_BINARY_SFI1_OFFSET0_2B_RSP = "1122" + SW1SW2_OK;
  private static final String CARD_READ_BINARY_SFI1_OFFSET2_2B_CMD = "00B0810202";
  private static final String CARD_READ_BINARY_SFI1_OFFSET2_2B_RSP = "3344" + SW1SW2_OK;
  private static final String CARD_READ_BINARY_SFI1_OFFSET4_1B_CMD = "00B0810401";
  private static final String CARD_READ_BINARY_SFI1_OFFSET4_1B_RSP = "55" + SW1SW2_OK;
  private static final String CARD_UPDATE_BINARY_SFI1_OFFSET0_2B_CMD = "00D68100021122";
  private static final String CARD_UPDATE_BINARY_SFI1_OFFSET2_2B_CMD = "00D68102023344";
  private static final String CARD_UPDATE_BINARY_SFI1_OFFSET4_1B_CMD = "00D681040155";
  private static final String CARD_UPDATE_BINARY_SFI0_OFFSET256_1B_CMD = "00D601000166";
  private static final String CARD_WRITE_BINARY_SFI1_OFFSET0_2B_CMD = "00D08100021122";
  private static final String CARD_WRITE_BINARY_SFI1_OFFSET2_2B_CMD = "00D08102023344";
  private static final String CARD_WRITE_BINARY_SFI1_OFFSET4_1B_CMD = "00D081040155";
  private static final String CARD_WRITE_BINARY_SFI0_OFFSET256_1B_CMD = "00D001000166";

  private static final String CARD_SELECT_FILE_CURRENT_CMD = "00A4090002000000";
  private static final String CARD_SELECT_FILE_FIRST_CMD = "00A4020002000000";
  private static final String CARD_SELECT_FILE_NEXT_CMD = "00A4020202000000";
  private static final String CARD_SELECT_FILE_1234_CMD = "00A4090002123400";
  private static final String CARD_SELECT_FILE_1234_RSP =
      "85170001000000" + ACCESS_CONDITIONS_1234 + KEY_INDEXES_1234 + "00777879616770003F009000";
  private static final String CARD_SELECT_FILE_1234_CMD_PRIME_REV2 = "94A4020002123400";
  private static final String CARD_SELECT_FILE_1234_RSP_PRIME_REV2 =
      "85170001000000" + ACCESS_CONDITIONS_1234 + KEY_INDEXES_1234 + "00777879616770003F009000";

  private static final String CARD_GET_DATA_FCI_CMD = "00CA006F00";
  private static final String CARD_GET_DATA_FCP_CMD = "00CA006200";
  private static final String CARD_GET_DATA_EF_LIST_CMD = "00CA00C000";
  private static final String CARD_GET_DATA_TRACEABILITY_INFORMATION_CMD = "00CA018500";
  private static final String CARD_GET_DATA_FCI_RSP = SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3;
  private static final String CARD_GET_DATA_FCP_RSP = CARD_SELECT_FILE_1234_RSP;
  private static final String CARD_GET_DATA_EF_LIST_RSP =
      "C028C106200107021D01C10620FF09011D04C106F1231004F3F4C106F1241108F3F4C106F1251F09F3F49000";
  private static final String CARD_GET_DATA_TRACEABILITY_INFORMATION_RSP =
      "001122334455667788999000";

  private static final String CARD_VERIFY_PIN_PLAIN_OK_CMD =
      "0020000004" + HexUtil.toHex(PIN_OK.getBytes());
  private static final String CARD_VERIFY_PIN_ENCRYPTED_OK_CMD =
      "0020000008" + CIPHER_PIN_VERIFICATION_OK;
  private static final String CARD_CHECK_PIN_CMD = "0020000000";
  private static final String CARD_CHANGE_PIN_CMD = "00D800FF10" + CIPHER_PIN_UPDATE_OK;
  private static final String CARD_CHANGE_PIN_PLAIN_CMD =
      "00D800FF04" + HexUtil.toHex(NEW_PIN.getBytes());
  private static final String CARD_VERIFY_PIN_OK_RSP = SW1SW2_OK;
  private static final String CARD_VERIFY_PIN_KO_RSP = "63C2";
  private static final String CARD_CHANGE_PIN_RSP = SW1SW2_OK;
  private static final String CARD_CHANGE_PIN_PLAIN_RSP = SW1SW2_OK;

  private static final int SV_BALANCE = 0x123456;
  private static final String SV_BALANCE_STR = "123456";
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

  private static final String CARD_CHANGE_KEY_CMD = "00D8000120" + CIPHERED_KEY;

  private static final String SAM_SELECT_DIVERSIFIER_CMD = "8014000008" + CARD_DIVERSIFIER;
  private static final String SAM_GET_CHALLENGE_CMD = "8084000004";
  private static final String SAM_GET_CHALLENGE_RSP = SAM_CHALLENGE + SW1SW2_OK;
  private static final String SAM_DIGEST_INIT_OPEN_SECURE_SESSION_SFI7_REC1_CMD =
      "808A00FF273079030490980030791D" + FILE7_REC1_29B;
  private static final String SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD =
      "808A00FF0A30790304909800307900";
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_CMD = "808C00000500B2013C00";
  private static final String SAM_DIGEST_UPDATE_MULTIPLE_READ_REC_SFI7_REC1_L29_CMD =
      "808C8000" + "26" + "05" + "00B2013C1D" + "1F" + FILE7_REC1_29B + SW1SW2_OK;
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_RSP_CMD =
      "808C00001F\" + FILE7_REC1_29B+ \"9000";
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI8_REC1_RSP_CMD =
      "808C00001F" + FILE8_REC1_29B + "9000";
  private static final String SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_L29_CMD = "808C00000500B2013C1D";
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

  private static final String SAM_CARD_CIPHER_PIN_VERIFICATION_CMD =
      "801280FF060000" + HexUtil.toHex(PIN_OK.getBytes());
  private static final String SAM_CARD_CIPHER_PIN_VERIFICATION_RSP =
      CIPHER_PIN_VERIFICATION_OK + SW1SW2_OK;
  private static final String SAM_CARD_CIPHER_PIN_UPDATE_CMD =
      "801240FF0A112200000000" + HexUtil.toHex(NEW_PIN.getBytes());
  private static final String SAM_CARD_CIPHER_PIN_UPDATE_RSP = CIPHER_PIN_UPDATE_OK + SW1SW2_OK;
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

  private static final String SAM_CARD_GENERATE_KEY_CMD = "8012FFFF050405020390";
  private static final String SAM_CARD_GENERATE_KEY_RSP = CIPHERED_KEY + SW1SW2_OK;

  private CardTransactionManager cardTransactionManager;
  private CalypsoCardAdapter calypsoCard;
  private ReaderMock cardReader;
  private ReaderMock samReader;
  private CalypsoSamAdapter calypsoSam;
  private CardSecuritySetting cardSecuritySetting;

  interface ReaderMock extends CardReader, ProxyReaderApi {}

  private void initCalypsoCard(String selectApplicationResponse) throws Exception {
    calypsoCard =
        spy(
            new CalypsoCardAdapter(
                new CardSelectionResponseAdapter(
                    new ApduResponseAdapter(HexUtil.toByteArray(selectApplicationResponse)))));
    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);
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

  public static class CardRequestMatcher implements ArgumentMatcher<CardRequestSpi> {
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

  @Before
  public void setUp() throws Exception {
    cardReader = mock(ReaderMock.class);
    samReader = mock(ReaderMock.class);
    CardSelectionResponseApi samCardSelectionResponse = mock(CardSelectionResponseApi.class);
    when(samCardSelectionResponse.getPowerOnData()).thenReturn(SAM_C1_POWER_ON_DATA);
    calypsoSam = new CalypsoSamAdapter(samCardSelectionResponse);
    cardSecuritySetting =
        CalypsoExtensionService.getInstance()
            .createCardSecuritySetting()
            .setControlSamResource(samReader, calypsoSam);
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3);
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
  public void getSecuritySetting_shouldReturnCardSecuritySetting() {
    assertThat(cardTransactionManager.getSecuritySetting()).isSameAs(cardSecuritySetting);
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
  public void processOpening_whenSuccessful_shouldUpdateTransactionCounterAndRatificationStatus()
      throws Exception {

    CardRequestSpi samCardRequest =
        createCardRequest(SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD);
    CardResponseApi samCardResponse = createCardResponse(SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_OPEN_SECURE_SESSION_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_OPEN_SECURE_SESSION_RSP);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.processOpening(WriteAccessLevel.DEBIT);

    assertThat(calypsoCard.isDfRatified()).isTrue();
    assertThat(calypsoCard.getTransactionCounter()).isEqualTo(0x030490);
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
    cardTransactionManager.prepareReadRecord(FILE7, 1);
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
    cardTransactionManager.prepareReadRecord(FILE7, 1);
    cardTransactionManager.prepareReadRecord(FILE8, 1);
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
    // force the checking of the session key to fail
    cardSecuritySetting =
        CalypsoExtensionService.getInstance()
            .createCardSecuritySetting()
            .setControlSamResource(samReader, calypsoSam)
            .addAuthorizedSessionKey((byte) 0x00, (byte) 0x00);
    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);
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
  public void processCommands_whenOutOfSession_shouldExchangeApduWithCardOnly() throws Exception {
    CardRequestSpi cardCardRequest =
        createCardRequest(
            CARD_READ_REC_SFI7_REC1_CMD, CARD_READ_REC_SFI8_REC1_CMD, CARD_READ_REC_SFI10_REC1_CMD);
    CardResponseApi cardCardResponse =
        createCardResponse(
            CARD_READ_REC_SFI7_REC1_RSP, CARD_READ_REC_SFI8_REC1_RSP, CARD_READ_REC_SFI10_REC1_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareReadRecord(FILE7, 1);
    cardTransactionManager.prepareReadRecord(FILE8, 1);
    cardTransactionManager.prepareReadRecord(FILE10, 1);
    cardTransactionManager.processCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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
    cardTransactionManager.prepareReadRecord(FILE7, 1);
    cardTransactionManager.prepareReadRecord(FILE8, 1);
    cardTransactionManager.prepareReadRecord(FILE10, 1);
    cardTransactionManager.processCommands();
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
  public void
      processClosing_whenASessionIsOpenAndNotSamC1_shouldExchangeApduWithCardAndSamWithoutDigestUpdateMultiple()
          throws Exception {
    // HSM
    CardSelectionResponseApi samCardSelectionResponse = mock(CardSelectionResponseApi.class);
    when(samCardSelectionResponse.getPowerOnData()).thenReturn(HSM_C1_POWER_ON_DATA);
    calypsoSam = new CalypsoSamAdapter(samCardSelectionResponse);
    cardSecuritySetting =
        CalypsoExtensionService.getInstance()
            .createCardSecuritySetting()
            .setControlSamResource(samReader, calypsoSam);
    cardTransactionManager =
        CalypsoExtensionService.getInstance()
            .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);
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
        createCardRequest(
            SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD,
            SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_L29_CMD,
            SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_RSP,
            SAM_DIGEST_CLOSE_CMD);
    CardRequestSpi cardCardRequestRead = createCardRequest(CARD_READ_REC_SFI7_REC1_L29_CMD);
    CardRequestSpi cardCardRequestClose = createCardRequest(CARD_CLOSE_SECURE_SESSION_CMD);

    samCardResponse =
        createCardResponse(SW1SW2_OK_RSP, SW1SW2_OK_RSP, SW1SW2_OK_RSP, SAM_DIGEST_CLOSE_RSP);
    CardResponseApi cardCardResponseRead = createCardResponse(CARD_READ_REC_SFI7_REC1_RSP);
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

    cardTransactionManager.prepareReadRecords(FILE7, 1, 1, 29);

    cardTransactionManager.processClosing();
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

  @Test
  public void
      processClosing_whenASessionIsOpenAndSamC1_shouldExchangeApduWithCardAndSamWithDigestUpdateMultiple()
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
        createCardRequest(
            SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD,
            SAM_DIGEST_UPDATE_MULTIPLE_READ_REC_SFI7_REC1_L29_CMD,
            SAM_DIGEST_CLOSE_CMD);
    CardRequestSpi cardCardRequestRead = createCardRequest(CARD_READ_REC_SFI7_REC1_L29_CMD);
    CardRequestSpi cardCardRequestClose = createCardRequest(CARD_CLOSE_SECURE_SESSION_CMD);

    samCardResponse = createCardResponse(SW1SW2_OK_RSP, SW1SW2_OK_RSP, SAM_DIGEST_CLOSE_RSP);
    CardResponseApi cardCardResponseRead = createCardResponse(CARD_READ_REC_SFI7_REC1_RSP);
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

    cardTransactionManager.prepareReadRecords(FILE7, 1, 1, 29);

    cardTransactionManager.processClosing();
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

  @Test(expected = UnexpectedCommandStatusException.class)
  public void processClosing_whenCloseSessionFails_shouldThrowUCSE() throws Exception {
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
    cardCardResponse = createCardResponse(SW1SW2_INCORRECT_SIGNATURE);

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);

    cardTransactionManager.processClosing();
  }

  @Test(expected = InvalidCardSignatureException.class)
  public void processClosing_whenCardAuthenticationFails_shouldThrowICSE() throws Exception {
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
    cardTransactionManager.processVerifyPin(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void processVerifyPin_whenPINIsNot4Digits_shouldThrowIAE() {
    cardTransactionManager.processVerifyPin(PIN_5_DIGITS.getBytes());
  }

  @Test(expected = IllegalStateException.class)
  public void processVerifyPin_whenPINIsNotFirstCommand_shouldThrowISE() throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);
    cardTransactionManager.prepareReadRecord(FILE7, 1);
    cardTransactionManager.processVerifyPin(PIN_OK.getBytes());
  }

  @Test(expected = UnsupportedOperationException.class)
  public void processVerifyPin_whenPINNotAvailable_shouldThrowUOE() {
    cardTransactionManager.processVerifyPin(PIN_OK.getBytes());
  }

  @Test
  public void processVerifyPin_whenPINTransmittedInPlainText_shouldSendApduVerifyPIN()
      throws Exception {
    cardSecuritySetting =
        CalypsoExtensionService.getInstance()
            .createCardSecuritySetting()
            .setControlSamResource(samReader, calypsoSam)
            .enablePinPlainTransmission();
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_VERIFY_PIN_PLAIN_OK_CMD);
    CardResponseApi cardCardResponse = createCardResponse(SW1SW2_OK);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.processVerifyPin(PIN_OK.getBytes());
    InOrder inOrder = inOrder(samReader, cardReader);
    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test
  public void processChangePin_whenTransmissionIsPlain_shouldSendApdusToTheCardAndTheSAM()
      throws Exception {
    cardSecuritySetting =
        CalypsoExtensionService.getInstance()
            .createCardSecuritySetting()
            .enablePinPlainTransmission()
            .setControlSamResource(samReader, calypsoSam);
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    calypsoCard.setPinAttemptRemaining(3);

    CardRequestSpi cardChangePinCardRequest = createCardRequest(CARD_CHANGE_PIN_PLAIN_CMD);
    CardResponseApi cardChangePinCardResponse = createCardResponse(CARD_CHANGE_PIN_PLAIN_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardChangePinCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardChangePinCardResponse);

    cardTransactionManager.processChangePin(NEW_PIN.getBytes());

    InOrder inOrder = inOrder(cardReader);

    inOrder
        .verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardChangePinCardRequest)), any(ChannelControl.class));

    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test
  public void processChangePin_whenTransmissionIsEncrypted_shouldSendApdusToTheCardAndTheSAM()
      throws Exception {
    cardSecuritySetting =
        CalypsoExtensionService.getInstance()
            .createCardSecuritySetting()
            .setPinModificationCipheringKey(PIN_CIPHERING_KEY_KIF, PIN_CIPHERING_KEY_KVC)
            .setControlSamResource(samReader, calypsoSam);
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    CardRequestSpi cardGetChallengeCardRequest = createCardRequest(CARD_GET_CHALLENGE_CMD);
    CardResponseApi cardGetChallengeCardResponse = createCardResponse(CARD_GET_CHALLENGE_RSP);

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

    when(samReader.transmitCardRequest(
            argThat(new CardRequestMatcher(samCardRequest)), any(ChannelControl.class)))
        .thenReturn(samCardResponse);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardChangePinCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardChangePinCardResponse);

    cardTransactionManager.processChangePin(NEW_PIN.getBytes());

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
            argThat(new CardRequestMatcher(cardChangePinCardRequest)), any(ChannelControl.class));

    verifyNoMoreInteractions(samReader, cardReader);
  }

  @Test
  public void processChangeKey_shouldSendApdusToTheCardAndTheSAM() throws Exception {
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

    cardTransactionManager.processChangeKey(1, (byte) 2, (byte) 3, (byte) 4, (byte) 5);

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
  public void prepareSelectFileDeprecated_whenLidIsNull_shouldThrowIAE() {
    cardTransactionManager.prepareSelectFile((byte[]) null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSelectFileDeprecated_whenLidIsLessThan2ByteLong_shouldThrowIAE() {
    cardTransactionManager.prepareSelectFile(new byte[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSelectFileDeprecated_whenLidIsMoreThan2ByteLong_shouldThrowIAE() {
    cardTransactionManager.prepareSelectFile(new byte[3]);
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
    cardTransactionManager.processCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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
    cardTransactionManager.processCommands();
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
    cardTransactionManager.processCommands();
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
    cardTransactionManager.processCommands();
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
    cardTransactionManager.processCommands();
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
    cardTransactionManager.processCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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
    cardTransactionManager.processCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));

    verifyNoMoreInteractions(samReader, cardReader);

    assertThat(calypsoCard.getFiles()).hasSize(5);

    FileHeader fileHeader07 = calypsoCard.getFileBySfi((byte) 0x07).getHeader();
    assertThat(fileHeader07.getLid()).isEqualTo((short) 0x2001);
    assertThat(fileHeader07.getEfType()).isEqualTo(ElementaryFile.Type.LINEAR);
    assertThat(fileHeader07.getRecordSize()).isEqualTo((byte) 0x1D);
    assertThat(fileHeader07.getRecordsNumber()).isEqualTo((byte) 0x01);

    FileHeader fileHeader09 = calypsoCard.getFileBySfi((byte) 0x09).getHeader();
    assertThat(fileHeader09.getLid()).isEqualTo((short) 0x20FF);
    assertThat(fileHeader09.getEfType()).isEqualTo(ElementaryFile.Type.BINARY);
    assertThat(fileHeader09.getRecordSize()).isEqualTo((byte) 0x1D);
    assertThat(fileHeader09.getRecordsNumber()).isEqualTo((byte) 0x04);

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

    cardTransactionManager.processCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));

    verifyNoMoreInteractions(samReader, cardReader);

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
    cardTransactionManager.processCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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
    CardRequestSpi cardCardRequest = createCardRequest(CARD_READ_REC_SFI7_REC1_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_READ_REC_SFI7_REC1_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareReadRecord(FILE7, 1);
    cardTransactionManager.processCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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

    cardTransactionManager.prepareReadRecords((byte) 1, 1, 2, 1);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
            .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareReadRecords((byte) 1, 1, 5, 1);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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

  @Test(expected = IllegalArgumentException.class)
  public void prepareReadCounter_whenSfiIsGreaterThan30_shouldThrowIAE() {
    cardTransactionManager.prepareReadCounter((byte) 31, 1);
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
            .createSearchCommandData()
            .setSfi((byte) -1)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenSfiGreaterThanSfiMax_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .createSearchCommandData()
            .setSfi((byte) 31)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenRecordNumberIs0_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .createSearchCommandData()
            .startAtRecord(0)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenRecordNumberIsGreaterThan250_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .createSearchCommandData()
            .startAtRecord(251)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenOffsetIsNegative_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .createSearchCommandData()
            .setOffset(-1)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenOffsetIsGreaterThan249_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .createSearchCommandData()
            .setOffset(250)
            .setSearchData(new byte[1]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenSearchDataIsNotSet_shouldThrowIAE() {
    SearchCommandData data = CalypsoExtensionService.getInstance().createSearchCommandData();
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenSearchDataIsNull_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance().createSearchCommandData().setSearchData(null);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenSearchDataIsEmpty_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance().createSearchCommandData().setSearchData(new byte[0]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareSearchRecords_whenSearchDataLengthIsGreaterThan250MinusOffset0_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .createSearchCommandData()
            .setSearchData(new byte[251]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void
      prepareSearchRecords_whenSearchDataLengthIsGreaterThan249MinusOffset1_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
            .createSearchCommandData()
            .setOffset(1)
            .setSearchData(new byte[250]);
    cardTransactionManager.prepareSearchRecords(data);
  }

  @Test(expected = IllegalArgumentException.class)
  public void prepareSearchRecords_whenMaskLengthIsGreaterThanSearchDataLength_shouldThrowIAE() {
    SearchCommandData data =
        CalypsoExtensionService.getInstance()
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
            .createSearchCommandData()
            .setSearchData(new byte[] {0x12, 0x34});
    cardTransactionManager.prepareSearchRecords(data);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
            .createSearchCommandData()
            .setSfi((byte) 4)
            .startAtRecord(2)
            .setOffset(3)
            .enableRepeatedOffset()
            .setSearchData(new byte[] {0x12, 0x34})
            .fetchFirstMatchingResult();
    cardTransactionManager.prepareSearchRecords(data);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
            .createSearchCommandData()
            .setSearchData(new byte[] {0x12, 0x34});
    cardTransactionManager.prepareSearchRecords(data);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
            .createSearchCommandData()
            .setSearchData(new byte[] {0x12, 0x34})
            .setMask(new byte[] {0x56});
    cardTransactionManager.prepareSearchRecords(data);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
            .createSearchCommandData()
            .setSearchData(new byte[] {0x12, 0x34})
            .setMask(new byte[] {0x56, 0x77});
    cardTransactionManager.prepareSearchRecords(data);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

    assertThat(data.getMatchingRecordNumbers()).containsExactly(4, 6);
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

    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 1, 2, 3, 1);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
            .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareReadRecordsPartially((byte) 1, 1, 5, 3, 1);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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

  @Test(expected = UnsupportedOperationException.class)
  public void prepareUpdateBinary_whenProductTypeIsNotPrimeRev2OrRev3_shouldThrowUOE()
      throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_LIGHT);
    cardTransactionManager.prepareUpdateBinary((byte) 1, 1, new byte[1]);
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
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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

    cardTransactionManager.prepareReadBinary((byte) 1, 0, 1);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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

    cardTransactionManager.prepareReadBinary((byte) 1, 0, 1);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContent())
        .isEqualTo(HexUtil.toByteArray("11"));
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
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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

    cardTransactionManager.prepareUpdateBinary((byte) 1, 4, HexUtil.toByteArray("55"));
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
            .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareUpdateBinary((byte) 1, 0, HexUtil.toByteArray("1122334455"));
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
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

    cardTransactionManager.prepareWriteBinary((byte) 1, 4, HexUtil.toByteArray("55"));
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
            .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);

    cardTransactionManager.prepareWriteBinary((byte) 1, 0, HexUtil.toByteArray("1122334455"));
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
    when(calypsoCard.getPayloadCapacity()).thenReturn(2);

    cardTransactionManager.prepareIncreaseCounter((byte) 1, 1, 100);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(1))
        .isEqualTo(8821);
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

  @Test
  public void prepareDecreaseCounter_whenParametersAreCorrect_shouldAddDecreaseMultipleCommand()
      throws Exception {
    CardRequestSpi cardCardRequest = createCardRequest(CARD_DECREASE_SFI10_CNT1_100U_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_DECREASE_SFI10_CNT1_4286U_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(2);

    cardTransactionManager.prepareDecreaseCounter((byte) 1, 1, 100);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(1))
        .isEqualTo(4286);
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
    when(calypsoCard.getPayloadCapacity()).thenReturn(2);

    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToIncValueMap.put(1, 100);

    cardTransactionManager.prepareIncreaseCounters((byte) 1, counterNumberToIncValueMap);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
            .createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);

    Map<Integer, Integer> counterNumberToIncValueMap = new HashMap<Integer, Integer>(3);
    counterNumberToIncValueMap.put(1, 1);
    counterNumberToIncValueMap.put(2, 2);
    counterNumberToIncValueMap.put(3, 3);
    cardTransactionManager.prepareIncreaseCounters((byte) 1, counterNumberToIncValueMap);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(1))
        .isEqualTo(0x11);
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(2))
        .isEqualTo(0x22);
    assertThat(calypsoCard.getFileBySfi((byte) 1).getData().getContentAsCounterValue(3))
        .isEqualTo(0x33);
  }

  @Test
  public void prepareDecreaseCounters_whenCardIsLowerThanPrime3_shouldThrowUOE() throws Exception {
    when(calypsoCard.getProductType()).thenReturn(CalypsoCard.ProductType.BASIC);

    CardRequestSpi cardCardRequest = createCardRequest(CARD_DECREASE_SFI10_CNT1_100U_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_DECREASE_SFI10_CNT1_4286U_RSP);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    when(calypsoCard.getPayloadCapacity()).thenReturn(2);

    Map<Integer, Integer> counterNumberToDecValueMap = new HashMap<Integer, Integer>(1);
    counterNumberToDecValueMap.put(1, 100);

    cardTransactionManager.prepareDecreaseCounters((byte) 1, counterNumberToDecValueMap);
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
    cardTransactionManager.processCommands();

    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);

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
    cardTransactionManager.processCommands();
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
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);
    CardRequestSpi cardCardRequest = createCardRequest(CARD_SV_GET_DEBIT_CMD);
    CardResponseApi cardCardResponse = createCardResponse(CARD_SV_GET_DEBIT_RSP);
    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class)))
        .thenReturn(cardCardResponse);
    cardTransactionManager.prepareSvGet(SvOperation.DEBIT, SvAction.DO);
    cardTransactionManager.processCommands();
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
    cardTransactionManager.processCommands();
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
    cardTransactionManager.processCommands();
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
  public void prepareSvReadAllLogs_whenNotAnSVApplication_shouldThrowISE() throws Exception {
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);
    cardTransactionManager.prepareSvReadAllLogs();
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
    cardTransactionManager.processCommands();
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
    cardTransactionManager.processCommands();
    verify(cardReader)
        .transmitCardRequest(
            argThat(new CardRequestMatcher(cardCardRequest)), any(ChannelControl.class));
    verifyNoMoreInteractions(samReader, cardReader);
  }
}
