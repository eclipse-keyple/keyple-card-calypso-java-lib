/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://www.calypsonet-asso.org/
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

import org.eclipse.keyple.card.calypso.sam.SamRevision;
import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private) <br>
 * Builds the Card Cipher PIN APDU command.
 *
 * @since 2.0
 */
final class SamCardCipherPinBuilder extends AbstractSamCommandBuilder<SamCardCipherPinParser> {
  /** The command reference. */
  private static final SamCommand command = SamCommand.CARD_CIPHER_PIN;

  /**
   * Instantiates a new SamCardCipherPinBuilder and generate the ciphered data for a Verify PIN or
   * Change PIN PO command.
   *
   * <p>In the case of a PIN verification, only the current PIN must be provided (newPin must be set
   * to null).
   *
   * <p>In the case of a PIN update, the current and new PINs must be provided.
   *
   * @param revision of the SAM.
   * @param cipheringKif the KIF of the key used to encipher the PIN data.
   * @param cipheringKvc the KVC of the key used to encipher the PIN data.
   * @param currentPin the current PIN (a 4-byte byte array).
   * @param newPin the new PIN (a 4-byte byte array if the operation in progress is a PIN update,
   *     null if the operation in progress is a PIN verification)
   * @since 2.0
   */
  public SamCardCipherPinBuilder(
      SamRevision revision,
      byte cipheringKif,
      byte cipheringKvc,
      byte[] currentPin,
      byte[] newPin) {
    super(command);

    if (revision != null) {
      this.defaultRevision = revision;
    }
    if (currentPin == null || currentPin.length != 4) {
      throw new IllegalArgumentException("Bad current PIN value.");
    }

    if (newPin != null && newPin.length != 4) {
      throw new IllegalArgumentException("Bad new PIN value.");
    }

    byte cla = this.defaultRevision.getClassByte();

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
        new ApduRequest(ApduUtil.build(cla, command.getInstructionByte(), p1, p2, data, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamCardCipherPinParser createResponseParser(ApduResponse apduResponse) {
    return new SamCardCipherPinParser(apduResponse, this);
  }
}
