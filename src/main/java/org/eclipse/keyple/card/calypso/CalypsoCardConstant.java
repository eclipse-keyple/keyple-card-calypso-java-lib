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
 * (package-private)<br>
 * Constants related to Calypso cards.
 *
 * @since 2.0.0
 */
final class CalypsoCardConstant {

  static final int MASK_3_BITS = 0x7; // 7
  static final int MASK_4_BITS = 0xF; // 15
  static final int MASK_5_BITS = 0x1F; // 31
  static final int MASK_7_BITS = 0x7F; // 127
  static final int MASK_1_BYTE = 0xFF; // 255
  static final int MASK_2_BYTES = 0xFFFF;
  static final int MASK_3_BYTES = 0xFFFFFF;

  // SFI
  static final int SFI_MIN = 0;
  static final int SFI_MAX = MASK_5_BITS;
  // Record number
  static final int NB_REC_MIN = 1;
  static final int NB_REC_MAX = 255;

  // Counter number
  static final int NB_CNT_MIN = 1;
  static final int NB_CNT_MAX = 255;

  // Counter value
  static final int CNT_VALUE_MIN = 0;
  static final int CNT_VALUE_MAX = 16777215;

  // Le max
  static final int LE_MAX = 255;

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

  // PIN Code
  static final int PIN_LENGTH = 4;

  // Stored Value
  static final byte STORED_VALUE_FILE_STRUCTURE_ID = (byte) 0x20;
  static final byte SV_RELOAD_LOG_FILE_SFI = (byte) 0x14;
  static final int SV_RELOAD_LOG_FILE_NB_REC = 1;
  static final byte SV_DEBIT_LOG_FILE_SFI = (byte) 0x15;
  static final int SV_DEBIT_LOG_FILE_NB_REC = 3;
  static final int SV_LOG_FILE_REC_LENGTH = 29;

  /** (private) */
  private CalypsoCardConstant() {}
}
