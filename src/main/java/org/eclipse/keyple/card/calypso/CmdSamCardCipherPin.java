/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the Card Cipher PIN APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamCardCipherPin extends SamCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(SamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", SamIllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", SamCounterOverflowException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied.", SamAccessForbiddenException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P1 or P2", SamIllegalParameterException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: ciphering key not found", SamDataAccessException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CmdSamCardCipherPin and generate the ciphered data for a "Verify PIN" or
   * Change PIN card command.
   *
   * <p>In the case of a PIN verification, only the current PIN must be provided (newPin must be set
   * to null).
   *
   * <p>In the case of a PIN update, the current and new PINs must be provided.
   *
   * @param calypsoSam The Calypso SAM.
   * @param cipheringKif the KIF of the key used to encipher the PIN data.
   * @param cipheringKvc the KVC of the key used to encipher the PIN data.
   * @param currentPin the current PIN (a 4-byte byte array).
   * @param newPin the new PIN (a 4-byte byte array if the operation in progress is a PIN update,
   *     null if the operation in progress is a PIN verification)
   * @since 2.0.1
   */
  CmdSamCardCipherPin(
      CalypsoSamAdapter calypsoSam,
      byte cipheringKif,
      byte cipheringKvc,
      byte[] currentPin,
      byte[] newPin) {

    super(SamCommandRef.CARD_CIPHER_PIN, 0, calypsoSam);

    if (currentPin == null || currentPin.length != 4) {
      throw new IllegalArgumentException("Bad current PIN value.");
    }

    if (newPin != null && newPin.length != 4) {
      throw new IllegalArgumentException("Bad new PIN value.");
    }

    byte cla = calypsoSam.getClassByte();

    byte p1;
    byte p2;
    byte[] data;

    if (newPin == null) {
      // no new PIN is provided, we consider it's a PIN verification
      p1 = (byte) 0x80;
      data = new byte[6];
    } else {
      // a new PIN is provided, we consider it's a PIN update
      p1 = (byte) 0x40;
      data = new byte[10];
      System.arraycopy(newPin, 0, data, 6, 4);
    }
    p2 = (byte) 0xFF; // KIF and KVC in incoming data

    data[0] = cipheringKif;
    data[1] = cipheringKvc;

    System.arraycopy(currentPin, 0, data, 2, 4);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, data, null)));
  }

  /**
   * Gets the 8 bytes of ciphered data.
   *
   * @return The ciphered data byte array
   * @since 2.0.1
   */
  byte[] getCipheredData() {
    return getApduResponse().getDataOut();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
