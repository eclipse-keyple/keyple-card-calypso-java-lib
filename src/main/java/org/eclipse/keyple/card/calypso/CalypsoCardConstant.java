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

/**
 * Constants related to Calypso cards.
 *
 * @since 2.0.0
 */
final class CalypsoCardConstant {

  // SW
  static final int SW_FILE_NOT_FOUND = 0x6A82;
  static final int SW_RECORD_NOT_FOUND = 0x6A83;

  static final int MASK_15_BITS = 0x7FFF; // 32 767

  static final int MASK_3_BYTES = 0xFFFFFF; // 16 777 215

  // SFI
  static final int SFI_MIN = 0;
  static final int SFI_MAX = 30; // 1Eh

  // Record number
  static final int NB_REC_MIN = 1;
  static final int NB_REC_MAX = 250;

  // Counter number
  static final int NUM_CNT_MIN = 1;

  // Counter value
  static final int CNT_VALUE_MIN = 0;
  static final int CNT_VALUE_MAX = MASK_3_BYTES;

  // Offset
  static final int OFFSET_MIN = 0;
  static final int OFFSET_MAX = 249;
  static final int OFFSET_BINARY_MAX = MASK_15_BITS;

  // Data
  static final int DATA_LENGTH_MIN = 1;

  // File Type Values
  static final int FILE_TYPE_MF = 1;
  static final int FILE_TYPE_DF = 2;
  static final int FILE_TYPE_EF = 4;

  // EF Type Values
  static final int EF_TYPE_DF = 0;
  static final int EF_TYPE_BINARY = 1;
  static final int EF_TYPE_LINEAR = 2;
  static final int EF_TYPE_CYCLIC = 4;
  static final int EF_TYPE_SIMULATED_COUNTERS = 8;
  static final int EF_TYPE_COUNTERS = 9;

  // Field offsets in select file response (tag/length excluded)
  static final int SEL_SFI_OFFSET = 0;
  static final int SEL_TYPE_OFFSET = 1;
  static final int SEL_EF_TYPE_OFFSET = 2;
  static final int SEL_REC_SIZE_OFFSET = 3;
  static final int SEL_NUM_REC_OFFSET = 4;
  static final int SEL_AC_OFFSET = 5;
  static final int SEL_AC_LENGTH = 4;
  static final int SEL_NKEY_OFFSET = 9;
  static final int SEL_NKEY_LENGTH = 4;
  static final int SEL_DF_STATUS_OFFSET = 13;
  static final int SEL_KVCS_OFFSET = 14;
  static final int SEL_KIFS_OFFSET = 17;
  static final int SEL_DATA_REF_OFFSET = 14;
  static final int SEL_LID_OFFSET = 21;
  static final int SEL_LID_OFFSET_REV2 = 20;

  // PIN Code
  static final int PIN_LENGTH = 4;

  // Stored Value
  static final byte STORED_VALUE_FILE_STRUCTURE_ID = 0x20;
  static final byte SV_RELOAD_LOG_FILE_SFI = 0x14;
  static final int SV_RELOAD_LOG_FILE_NB_REC = 1;
  static final byte SV_DEBIT_LOG_FILE_SFI = 0x15;
  static final int SV_DEBIT_LOG_FILE_NB_REC = 3;
  static final int SV_LOG_FILE_REC_LENGTH = 29;
  static final int SV_LOAD_MIN_VALUE = -8388608; // -2^23: smallest 3-byte negative value
  static final int SV_LOAD_MAX_VALUE = 8388607; //  2^23 - 1: largest 3-byte positive value
  static final int SV_DEBIT_MIN_VALUE = 0;
  static final int SV_DEBIT_MAX_VALUE = 32767; // 2^15 - 1: largest 2-byte positive value

  static final int DEFAULT_PAYLOAD_CAPACITY = 250;

  static final int LEGACY_REC_LENGTH = 29;

  static final int CARD_CERTIFICATE_SIZE = 316;
  static final int CA_CERTIFICATE_SIZE = 384;

  // TLV TAGS
  static final int TAG_FCP_FOR_CURRENT_FILE = 0x62;
  static final byte TAG_FCP_FOR_CURRENT_FILE_LSB = (byte) (TAG_FCP_FOR_CURRENT_FILE & 0xFF);
  static final byte TAG_FCP_FOR_CURRENT_FILE_MSB =
      (byte) ((TAG_FCP_FOR_CURRENT_FILE & 0xFF00) >> 8);
  static final int TAG_FCI_FOR_CURRENT_DF = 0x6F;
  static final byte TAG_FCI_FOR_CURRENT_DF_LSB = (byte) (TAG_FCI_FOR_CURRENT_DF & 0xFF);
  static final byte TAG_FCI_FOR_CURRENT_DF_MSB = (byte) ((TAG_FCI_FOR_CURRENT_DF & 0xFF00) >> 8);
  static final int TAG_EF_LIST = 0xC0;
  static final byte TAG_EF_LIST_LSB = (byte) (TAG_EF_LIST & 0xFF);
  static final byte TAG_EF_LIST_MSB = (byte) ((TAG_EF_LIST & 0xFF00) >> 8);
  static final int TAG_TRACEABILITY_INFORMATION = 0x185;
  static final byte TAG_TRACEABILITY_INFORMATION_LSB = (byte) (TAG_TRACEABILITY_INFORMATION & 0xFF);
  static final byte TAG_TRACEABILITY_INFORMATION_MSB =
      (byte) ((TAG_TRACEABILITY_INFORMATION & 0xFF00) >> 8);
  static final int TAG_ECC_PUBLIC_KEY = 0xDF2C;
  static final byte TAG_ECC_PUBLIC_KEY_LSB = (byte) (TAG_ECC_PUBLIC_KEY & 0xFF);
  static final byte TAG_ECC_PUBLIC_KEY_MSB = (byte) ((TAG_ECC_PUBLIC_KEY & 0xFF00) >> 8);
  static final int TAG_CA_CERTIFICATE = 0xDF4A;
  static final byte TAG_CA_CERTIFICATE_LSB = (byte) (TAG_CA_CERTIFICATE & 0xFF);
  static final byte TAG_CA_CERTIFICATE_MSB = (byte) ((TAG_CA_CERTIFICATE & 0xFF00) >> 8);
  static final int TAG_CARD_CERTIFICATE = 0xDF4C;
  static final byte TAG_CARD_CERTIFICATE_LSB = (byte) (TAG_CARD_CERTIFICATE & 0xFF);
  static final byte TAG_CARD_CERTIFICATE_MSB = (byte) ((TAG_CARD_CERTIFICATE & 0xFF00) >> 8);

  /** (private) */
  private CalypsoCardConstant() {}
}
