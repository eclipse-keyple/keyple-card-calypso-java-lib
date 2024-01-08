/* **************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;
import org.eclipse.keypop.reader.CardReader;
import org.mockito.ArgumentMatcher;

abstract class AbstractTransactionManagerTest {

  static org.eclipse.keypop.calypso.card.transaction.ChannelControl CHANNEL_CONTROL_KEEP_OPEN =
      org.eclipse.keypop.calypso.card.transaction.ChannelControl.KEEP_OPEN;
  static org.eclipse.keypop.calypso.card.transaction.ChannelControl CHANNEL_CONTROL_CLOSE_AFTER =
      org.eclipse.keypop.calypso.card.transaction.ChannelControl.CLOSE_AFTER;

  static final String CARD_SERIAL_NUMBER = "0000000011223344";
  static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3 =
      "6F238409315449432E49434131A516BF0C13C708" + CARD_SERIAL_NUMBER + "53070A3C20051410019000";
  static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C28051410019000";
  static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C21051410019000";
  static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C22051410019000";
  static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED_WITH_STORED_VALUE =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C2A051410019000";
  static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2 =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C02051410019000";
  static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2_WITH_STORED_VALUE =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C12051410019000";
  static final String SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED =
      "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C20051410016283";
  static final String SELECT_APPLICATION_RESPONSE_LIGHT =
      "6F238409315449432E49434134A516BF0C13C70800000000112233445307064390312B01009000";

  static final String PIN_OK = "1234";
  static final String NEW_PIN = "4567";
  static final String CIPHER_PIN_UPDATE_OK = "88776655443322111122334455667788";
  static final String PIN_5_DIGITS = "12345";
  static final byte PIN_CIPHERING_KEY_KIF = 0x11;
  static final byte PIN_CIPHERING_KEY_KVC = 0x22;

  static final byte FILE7 = 0x07;
  static final byte FILE8 = 0x08;
  static final byte FILE10 = 0x10;

  static final String SW_9000 = "9000";
  static final String SW_6200 = "6200";
  static final String SW_6985 = "6985";
  static final String SW_INCORRECT_SIGNATURE = "6988";
  static final String SAM_CHALLENGE = "C1C2C3C4";
  static final String SAM_CHALLENGE_EXTENDED = "C1C2C3C4C5C6C7C8";
  static final String CARD_CHALLENGE = "C1C2C3C4C5C6C7C8";
  static final String SAM_SIGNATURE = "12345678";
  static final String CARD_SIGNATURE = "9ABCDEF0";

  static final String FILE7_REC1_29B = "7111111111111111111111111111111111111111111111111111111111";
  static final String FILE7_REC2_29B = "7222222222222222222222222222222222222222222222222222222222";
  static final String FILE8_REC1_29B = "8111111111111111111111111111111111111111111111111111111111";

  static final String FILE10_REC1_COUNTER =
      "00112200000000000000000000000000000000000000000000000000000000000000";

  static final String ACCESS_CONDITIONS_1234 = "10100000";
  static final String KEY_INDEXES_1234 = "01030101";
  static final String CIPHERED_KEY =
      "000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000";

  static final String CARD_OPEN_SECURE_SESSION_CMD = "008A030104" + SAM_CHALLENGE + "00";
  static final String KIF = "30";
  static final String KVC = "79";
  static final String CARD_OPEN_SECURE_SESSION_DATA_OUT = "0304909800" + KIF + KVC + "00";
  static final String CARD_OPEN_SECURE_SESSION_RSP = CARD_OPEN_SECURE_SESSION_DATA_OUT + SW_9000;
  static final String CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD = "008A0B3904" + SAM_CHALLENGE + "00";
  static final String CARD_OPEN_SECURE_SESSION_SFI7_REC1_DATA_OUT =
      "0304909800" + KIF + KVC + "1D" + FILE7_REC1_29B;
  static final String CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP =
      CARD_OPEN_SECURE_SESSION_SFI7_REC1_DATA_OUT + SW_9000;
  static final String CARD_OPEN_SECURE_SESSION_EXTENDED_CMD =
      "008A030209" + "00" + SAM_CHALLENGE_EXTENDED + "00";

  static final String CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT =
      "C8C7C6C5C4C3C2C102" + KIF + KVC + "00";
  static final String CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT_2 =
      "C8C7C6C5C4C3C2C102" + "AABB" + "00";
  static final String CARD_OPEN_SECURE_SESSION_EXTENDED_RSP =
      CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT + SW_9000;
  static final String CARD_OPEN_SECURE_SESSION_EXTENDED_NOT_SUPPORTED_RSP =
      "C8C7C6C50000000000" + KIF + KVC + "00" + SW_9000;
  static final String CARD_CLOSE_SECURE_SESSION_CMD = "008E800004" + SAM_SIGNATURE + "00";
  static final String CARD_CLOSE_SECURE_SESSION_EXTENDED_CMD =
      "008E800008" + "1122334455667788" + "00";
  static final String CARD_SIGNATURE_EXTENDED = "8877665544332211";
  static final String CARD_CLOSE_SECURE_SESSION_EXTENDED_RSP = CARD_SIGNATURE_EXTENDED + SW_9000;
  static final String CARD_CLOSE_SECURE_SESSION_RSP = CARD_SIGNATURE + SW_9000;
  static final String CARD_ABORT_SECURE_SESSION_CMD = "008E000000";

  static final String CARD_READ_REC_SFI1_REC2_CMD = "00B2020C00";
  static final String CARD_READ_REC_SFI1_REC2_RSP = "22" + SW_9000;
  static final String CARD_READ_REC_SFI1_REC4_CMD = "00B2040C00";
  static final String CARD_READ_REC_SFI1_REC4_RSP = "44" + SW_9000;
  static final String CARD_READ_REC_SFI1_REC5_CMD = "00B2050C00";
  static final String CARD_READ_REC_SFI1_REC5_RSP = "55" + SW_9000;
  static final String CARD_READ_REC_SFI7_REC1_CMD = "00B2013C00";
  static final String CARD_READ_REC_SFI7_REC1_L29_CMD = "00B2013C1D";
  static final String CARD_READ_REC_SFI7_REC1_RSP = FILE7_REC1_29B + SW_9000;
  static final String CARD_READ_REC_SFI8_REC1_CMD = "00B2014400";
  static final String CARD_READ_REC_SFI8_REC1_RSP = FILE8_REC1_29B + SW_9000;
  static final String CARD_READ_REC_SFI10_REC1_CMD = "00B2018400";
  static final String CARD_READ_REC_SFI10_REC1_RSP = FILE10_REC1_COUNTER + SW_9000;
  static final String CARD_READ_RECORDS_FROM1_TO2_CMD = "00B2010D06";
  static final String CARD_READ_RECORDS_FROM1_TO2_RSP = "010111020122" + SW_9000;
  static final String CARD_READ_RECORDS_FROM3_TO4_CMD = "00B2030D06";
  static final String CARD_READ_RECORDS_FROM3_TO4_RSP = "030133040144" + SW_9000;
  static final String CARD_READ_RECORDS_FROM5_TO5_CMD = "00B2050C01";
  static final String CARD_READ_RECORDS_FROM5_TO5_RSP = "55" + SW_9000;
  static final String CARD_DECREASE_SFI10_CNT1_100U_CMD = "003001080300006400";
  static final String CARD_DECREASE_SFI10_CNT1_4286U_RSP = "0010BE9000";
  static final String CARD_INCREASE_SFI11_CNT1_100U_CMD = "003201080300006400";
  static final String CARD_INCREASE_SFI11_CNT1_8821U_RSP = "0022759000";
  static final String CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_C3_3_CMD =
      "003A00080C01000001020000020300000300";
  static final String CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_C3_33_RSP =
      "0100001102000022030000339000";
  static final String CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_CMD = "003A000808010000010200000200";
  static final String CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_RSP = "01000011020000229000";
  static final String CARD_INCREASE_MULTIPLE_SFI1_C3_3_CMD = "003A0008040300000300";
  static final String CARD_INCREASE_MULTIPLE_SFI1_C3_33_RSP = "030000339000";
  static final String CARD_DECREASE_MULTIPLE_SFI1_C1_11_C2_22_C8_88_CMD =
      "003800080C01000011020000220800008800";
  static final String CARD_DECREASE_MULTIPLE_SFI1_C1_111_C2_222_C8_888_RSP =
      "0100011102000222080008889000";
  static final String CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_FFFF_CMD =
      "00A2010F070000021234FFFF00";
  static final String CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_FFFF_RSP =
      "020406" + SW_9000;
  static final String CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_56FF_CMD =
      "00A2010F07000002123456FF00";
  static final String CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_56FF_RSP =
      "020406" + SW_9000;
  static final String CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_5677_CMD =
      "00A2010F070000021234567700";
  static final String CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_5677_RSP =
      "020406" + SW_9000;
  static final String CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_CMD =
      "00A20227078103021234FFFF00";
  static final String CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_RSP =
      "020406112233123456" + SW_9000;
  static final String CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NB_BYTE1_CMD = "00B3010D045402030100";
  static final String CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NB_BYTE1_RSP = "1122" + SW_6200;
  static final String CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NB_BYTE1_CMD = "00B3030D045402030100";
  static final String CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NB_BYTE1_RSP = "3344" + SW_6200;
  static final String CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NB_BYTE1_CMD = "00B3050D045402030100";
  static final String CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NB_BYTE1_RSP = "55" + SW_9000;
  static final String CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD = "00B0810001";
  static final String CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP = "11" + SW_9000;
  static final String CARD_READ_BINARY_SFI0_OFFSET256_1B_CMD = "00B0010001";
  static final String CARD_READ_BINARY_SFI0_OFFSET256_1B_RSP = "66" + SW_9000;
  static final String CARD_UPDATE_BINARY_SFI1_OFFSET0_2B_CMD = "00D68100021122";
  static final String CARD_UPDATE_BINARY_SFI1_OFFSET2_2B_CMD = "00D68102023344";
  static final String CARD_UPDATE_BINARY_SFI1_OFFSET4_1B_CMD = "00D681040155";
  static final String CARD_UPDATE_BINARY_SFI0_OFFSET256_1B_CMD = "00D601000166";
  static final String CARD_WRITE_BINARY_SFI1_OFFSET0_2B_CMD = "00D08100021122";
  static final String CARD_WRITE_BINARY_SFI1_OFFSET2_2B_CMD = "00D08102023344";
  static final String CARD_WRITE_BINARY_SFI1_OFFSET4_1B_CMD = "00D081040155";
  static final String CARD_WRITE_BINARY_SFI0_OFFSET256_1B_CMD = "00D001000166";

  static final String CARD_SELECT_FILE_CURRENT_CMD = "00A4090002000000";
  static final String CARD_SELECT_FILE_FIRST_CMD = "00A4020002000000";
  static final String CARD_SELECT_FILE_NEXT_CMD = "00A4020202000000";
  static final String CARD_SELECT_FILE_1234_CMD = "00A4090002123400";
  static final String CARD_SELECT_FILE_1234_RSP =
      "85170001000000" + ACCESS_CONDITIONS_1234 + KEY_INDEXES_1234 + "00777879616770003F009000";
  static final String CARD_SELECT_FILE_1234_CMD_PRIME_REV2 = "94A4020002123400";
  static final String CARD_SELECT_FILE_1234_RSP_PRIME_REV2 =
      "85170001000000" + ACCESS_CONDITIONS_1234 + KEY_INDEXES_1234 + "00777879616770003F009000";

  static final String CARD_GET_DATA_FCI_CMD = "00CA006F00";
  static final String CARD_GET_DATA_FCP_CMD = "00CA006200";
  static final String CARD_GET_DATA_EF_LIST_CMD = "00CA00C000";
  static final String CARD_GET_DATA_TRACEABILITY_INFORMATION_CMD = "00CA018500";
  static final String CARD_GET_DATA_FCI_RSP = SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3;
  static final String CARD_GET_DATA_FCP_RSP = CARD_SELECT_FILE_1234_RSP;
  static final String CARD_GET_DATA_EF_LIST_RSP =
      "C028C106200107021D01C10620FF09011D04C106F1231004F3F4C106F1241108F3F4C106F1251F09F3F49000";
  static final String CARD_GET_DATA_TRACEABILITY_INFORMATION_RSP = "001122334455667788999000";

  static final String CARD_VERIFY_PIN_PLAIN_OK_CMD =
      "0020000004" + HexUtil.toHex(PIN_OK.getBytes());
  static final String CARD_CHECK_PIN_CMD = "0020000000";
  static final String CARD_CHANGE_PIN_CMD = "00D800FF10" + CIPHER_PIN_UPDATE_OK;
  static final String CARD_CHANGE_PIN_PLAIN_CMD = "00D800FF04" + HexUtil.toHex(NEW_PIN.getBytes());
  static final String CARD_CHANGE_PIN_RSP = SW_9000;
  static final String CARD_CHANGE_PIN_PLAIN_RSP = SW_9000;

  static final String SV_R_PREV_SIGN_LO = "A54BC9";
  static final String SV_R_CHALLENGE_OUT = "7DFA";
  static final String SV_R_PREV_SIGN_LO_EXT = "55AABB66DD77";
  static final String SV_D_PREV_SIGN_LO_EXT = "55AABB66DD77";
  static final String SV_R_CHALLENGE_OUT_EXT = "8877665544332211";
  static final String SV_D_CHALLENGE_OUT_EXT = "8877665544332211";
  static final String SV_R_CURRENT_KVC = "12";
  static final String SV_R_TNUM = "1234";
  static final String SV_R_BALANCE = "564321";
  static final String SV_R_LOG_DATE = "0123";
  static final String SV_R_LOG_FREE1 = "12";
  static final String SV_R_LOG_KVC = "34";
  static final String SV_R_LOG_FREE2 = "34";
  static final String SV_R_LOG_BALANCE = "7890AB";
  static final String SV_R_LOG_AMOUNT = "223344";
  static final String SV_R_LOG_TIME = "3210";
  static final String SV_R_LOG_SAM_ID = "11223344";
  static final String SV_R_LOG_SAM_TNUM = "543210";
  static final String SV_R_LOG_SV_TNUM = "5678";
  static final String SV_D_CURRENT_KVC = "CD";
  static final String SV_D_TNUM = "1234";
  static final String SV_D_PREV_SIGN_LO = "A54BC9";
  static final String SV_D_CHALLENGE_OUT = "7DFA";
  static final String SV_D_BALANCE = "564321";
  static final String SV_D_LOG_AMOUNT = "3344";
  static final String SV_D_LOG_DATE = "0123";
  static final String SV_D_LOG_TIME = "3210";
  static final String SV_D_LOG_KVC = "34";
  static final String SV_D_LOG_SAM_ID = "11223344";
  static final String SV_D_LOG_SAM_TNUM = "543210";
  static final String SV_D_LOG_BALANCE = "7890AB";
  static final String SV_D_LOG_SV_TNUM = "5678";
  static final String CARD_SV_GET_DEBIT_CMD = "007C00091E";
  static final String CARD_SV_GET_DEBIT_EXT_CMD = "007C01093D";
  static final String CARD_SV_GET_DEBIT_RSP =
      SV_D_CURRENT_KVC
          + SV_D_TNUM
          + SV_D_PREV_SIGN_LO
          + SV_D_CHALLENGE_OUT
          + SV_D_BALANCE
          + SV_D_LOG_AMOUNT
          + SV_D_LOG_DATE
          + SV_D_LOG_TIME
          + SV_D_LOG_KVC
          + SV_D_LOG_SAM_ID
          + SV_D_LOG_SAM_TNUM
          + SV_D_LOG_BALANCE
          + SV_D_LOG_SV_TNUM
          + SW_9000;
  static final String CARD_SV_GET_DEBIT_EXT_RSP =
      SV_D_CHALLENGE_OUT_EXT
          + SV_D_CURRENT_KVC
          + SV_D_TNUM
          + SV_D_PREV_SIGN_LO_EXT
          + SV_D_BALANCE
          + SV_R_LOG_DATE
          + SV_R_LOG_FREE1
          + SV_R_LOG_KVC
          + SV_R_LOG_FREE2
          + SV_R_LOG_BALANCE
          + SV_R_LOG_AMOUNT
          + SV_R_LOG_TIME
          + SV_R_LOG_SAM_ID
          + SV_R_LOG_SAM_TNUM
          + SV_R_LOG_SV_TNUM
          + SV_D_LOG_AMOUNT
          + SV_D_LOG_DATE
          + SV_D_LOG_TIME
          + SV_D_LOG_KVC
          + SV_D_LOG_SAM_ID
          + SV_D_LOG_SAM_TNUM
          + SV_D_LOG_BALANCE
          + SV_D_LOG_SV_TNUM
          + SW_9000;
  static final String CARD_SV_GET_RELOAD_CMD = "007C000721";
  static final String CARD_SV_GET_RELOAD_EXT_CMD = "007C01073D";
  static final String CARD_PRIME_REV2_SV_GET_RELOAD_CMD = "FA7C000721";
  static final String CARD_SV_GET_RELOAD_RSP =
      SV_R_CURRENT_KVC
          + SV_R_TNUM
          + SV_R_PREV_SIGN_LO
          + SV_R_CHALLENGE_OUT
          + SV_R_BALANCE
          + SV_R_LOG_DATE
          + SV_R_LOG_FREE1
          + SV_R_LOG_KVC
          + SV_R_LOG_FREE2
          + SV_R_LOG_BALANCE
          + SV_R_LOG_AMOUNT
          + SV_R_LOG_TIME
          + SV_R_LOG_SAM_ID
          + SV_R_LOG_SAM_TNUM
          + SV_R_LOG_SV_TNUM
          + SW_9000;
  static final String CARD_SV_GET_RELOAD_EXT_RSP =
      SV_R_CHALLENGE_OUT_EXT
          + SV_R_CURRENT_KVC
          + SV_R_TNUM
          + SV_R_PREV_SIGN_LO_EXT
          + SV_R_BALANCE
          + SV_R_LOG_DATE
          + SV_R_LOG_FREE1
          + SV_R_LOG_KVC
          + SV_R_LOG_FREE2
          + SV_R_LOG_BALANCE
          + SV_R_LOG_AMOUNT
          + SV_R_LOG_TIME
          + SV_R_LOG_SAM_ID
          + SV_R_LOG_SAM_TNUM
          + SV_R_LOG_SV_TNUM
          + SV_D_LOG_AMOUNT
          + SV_D_LOG_DATE
          + SV_D_LOG_TIME
          + SV_D_LOG_KVC
          + SV_D_LOG_SAM_ID
          + SV_D_LOG_SAM_TNUM
          + SV_D_LOG_BALANCE
          + SV_D_LOG_SV_TNUM
          + SW_9000;

  static final String CARD_INVALIDATE_CMD = "0004000000";
  static final String CARD_REHABILITATE_CMD = "0044000000";

  static final String CARD_GET_CHALLENGE_CMD = "0084000008";
  static final String CARD_GET_CHALLENGE_RSP = CARD_CHALLENGE + SW_9000;

  static final String CARD_CHANGE_KEY_CMD = "00D8000120" + CIPHERED_KEY;
  static final String SAM_SIGNATURE_EXTENDED = "1122334455667788";
  static final String CARD_MSS_AUTHENTICATION_ENCRYPTION_CMD =
      "00820003" + "08" + "1122334455667788" + "00";
  static final String CARD_MSS_AUTHENTICATION_ENCRYPTION_RSP = "8877665544332211" + SW_9000;
  static final String CARD_MSS_AUTHENTICATION_CMD = "00820001" + "08" + "1122334455667788" + "00";
  static final String CARD_MSS_AUTHENTICATION_RSP = "8877665544332211" + SW_9000;
  static final String CARD_MSS_ENCRYPTION_CMD = "0082000200";
  static final String CARD_MSS_CMD = "0082000000";
  static final String CARD_READ_REC_ENCRYPTED_SFI1_REC1_CMD = "00B2010C00";
  static final String CARD_READ_REC_ENCRYPTED_SFI1_REC1_RSP = "E1" + SW_9000;
  static final String CARD_READ_REC_DECRYPTED_SFI1_REC1_RSP = "11" + SW_9000;
  static final String CARD_READ_REC_ENCRYPTED_SFI1_REC3_CMD = "00B2030C00";
  static final String CARD_READ_REC_ENCRYPTED_SFI1_REC3_RSP = "E3" + SW_9000;
  static final String CARD_READ_REC_DECRYPTED_SFI1_REC3_RSP = "33" + SW_9000;
  static final String CARD_READ_REC_ENCRYPTED_SFI1_REC6_CMD = "00B2060C00";
  static final String CARD_READ_REC_ENCRYPTED_SFI1_REC6_RSP = "E6" + SW_9000;
  static final String CARD_READ_REC_DECRYPTED_SFI1_REC6_RSP = "66" + SW_9000;
  static final String CARD_UPDATE_REC_SFI1_REC1_CMD = "00DC010C01" + "AA";
  static final String CARD_UPDATE_REC_ENCRYPTED_SFI1_REC1_CMD = "00DC010C01" + "E1";
  static final String CARD_UPDATE_REC_ENCRYPTED_SFI1_REC1_RSP = SW_9000;
  static final String CARD_UPDATE_REC_SFI1_REC2_CMD = "00DC020C01" + "BB";
  static final String CARD_UPDATE_REC_ENCRYPTED_SFI1_REC2_CMD = "00DC020C01" + "E2";
  static final String CARD_UPDATE_REC_ENCRYPTED_SFI1_REC2_RSP = SW_9000;

  /* Content */

  ReaderMock cardReader;
  CalypsoCardAdapter calypsoCard;

  interface ReaderMock extends CardReader, ProxyReaderApi {}

  void initCalypsoCardAndTransactionManager(String selectApplicationResponse) throws Exception {
    initCalypsoCard(selectApplicationResponse);
    initTransactionManager();
  }

  void initCalypsoCard(String selectApplicationResponse) throws Exception {
    calypsoCard =
        spy(
            new CalypsoCardAdapter(
                new TestDtoAdapters.CardSelectionResponseAdapter(
                    new TestDtoAdapters.ApduResponseAdapter(
                        HexUtil.toByteArray(selectApplicationResponse)))));
  }

  abstract void initTransactionManager();

  CardRequestSpi mockTransmitCardRequest(String... apdus) throws Exception {

    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    List<ApduResponseApi> apduResponses = new ArrayList<ApduResponseApi>();
    for (int i = 0; i < apdus.length; i += 2) {
      apduRequests.add(new DtoAdapters.ApduRequestAdapter(HexUtil.toByteArray(apdus[i])));
      apduResponses.add(new TestDtoAdapters.ApduResponseAdapter(HexUtil.toByteArray(apdus[i + 1])));
    }
    CardRequestSpi cardRequest = new DtoAdapters.CardRequestAdapter(apduRequests, false);
    CardResponseApi cardResponse = new TestDtoAdapters.CardResponseAdapter(apduResponses, true);

    when(cardReader.transmitCardRequest(
            argThat(new CardRequestMatcher(cardRequest)), any(ChannelControl.class)))
        .thenReturn(cardResponse);

    return cardRequest;
  }

  static class CardRequestMatcher implements ArgumentMatcher<CardRequestSpi> {
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
