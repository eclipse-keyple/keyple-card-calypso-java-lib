/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
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
 * Definition of the BER TLV tags used by Get/Put Data commands.
 *
 * <p>The tags are expected to be 1 or 2 bytes long, both MSB and LSB values are pre-calculated.
 *
 * @since 3.1.0
 */
class BerTlvTag {
  static final int FCP_FOR_CURRENT_FILE = 0x62;
  static final byte FCP_FOR_CURRENT_FILE_MSB = (byte) ((FCP_FOR_CURRENT_FILE & 0xFF00) >> 8);
  static final byte FCP_FOR_CURRENT_FILE_LSB = (byte) (FCP_FOR_CURRENT_FILE & 0xFF);

  static final int FCI_FOR_CURRENT_DF = 0x6F;
  static final byte FCI_FOR_CURRENT_DF_MSB = (byte) ((FCI_FOR_CURRENT_DF & 0xFF00) >> 8);
  static final byte FCI_FOR_CURRENT_DF_LSB = (byte) (FCI_FOR_CURRENT_DF & 0xFF);

  static final int EF_LIST = 0xC0;
  static final byte EF_LIST_MSB = (byte) ((EF_LIST & 0xFF00) >> 8);
  static final byte EF_LIST_LSB = (byte) (EF_LIST & 0xFF);

  static final int TRACEABILITY_INFORMATION = 0x185;
  static final byte TRACEABILITY_INFORMATION_MSB =
      (byte) ((TRACEABILITY_INFORMATION & 0xFF00) >> 8);
  static final byte TRACEABILITY_INFORMATION_LSB = (byte) (TRACEABILITY_INFORMATION & 0xFF);

  static final int ECC_PUBLIC_KEY = 0xDF2C;
  static final byte ECC_PUBLIC_KEY_MSB = (byte) ((ECC_PUBLIC_KEY & 0xFF00) >> 8);
  static final byte ECC_PUBLIC_KEY_LSB = (byte) (ECC_PUBLIC_KEY & 0xFF);

  static final int CA_CERTIFICATE = 0xDF4A;
  static final byte CA_CERTIFICATE_MSB = (byte) ((CA_CERTIFICATE & 0xFF00) >> 8);
  static final byte CA_CERTIFICATE_LSB = (byte) (CA_CERTIFICATE & 0xFF);

  static final int CARD_CERTIFICATE = 0xDF4C;
  static final byte CARD_CERTIFICATE_MSB = (byte) ((CARD_CERTIFICATE & 0xFF00) >> 8);
  static final byte CARD_CERTIFICATE_LSB = (byte) (CARD_CERTIFICATE & 0xFF);

  private BerTlvTag() {} // Private constructor to prevent instantiation
}
