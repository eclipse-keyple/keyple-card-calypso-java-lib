/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.calypso;

import org.eclipse.keyple.calypso.sam.SamRevision;
import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * Builds the Give Random APDU command.
 *
 * @since 2.0
 */
final class SamCardGenerateKeyBuilder extends AbstractSamCommandBuilder<SamCardGenerateKeyParser> {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.CARD_GENERATE_KEY;

  /**
   * Instantiates a new SamDigestUpdateBuilder and generate the ciphered data for a key ciphered by
   * another.
   *
   * <p>If the provided ciphering key reference is null, the source key is ciphered with the null
   * key.
   *
   * @param revision of the SAM.
   * @param cipheringKey the key used to ciphering the source key (the null key is used if this.
   *     reference is null)
   * @param sourceKey the reference of the key to be loaded.
   * @since 2.0
   */
  public SamCardGenerateKeyBuilder(
      SamRevision revision, KeyReference cipheringKey, KeyReference sourceKey) {
    super(command, null);
    if (revision != null) {
      this.defaultRevision = revision;
    }
    if (sourceKey == null) {
      throw new IllegalArgumentException("The source key reference can't be null.");
    }

    byte cla = this.defaultRevision.getClassByte();

    byte p1;
    byte p2;
    byte[] data;

    if (cipheringKey == null) {
      // case where the source key is ciphered by the null key
      p1 = (byte) 0xFF;
      p2 = (byte) 0x00;

      data = new byte[3];
      data[0] = sourceKey.getKif();
      data[1] = sourceKey.getKvc();
      data[2] = (byte) 0x90;
    } else {
      p1 = (byte) 0xFF;
      p2 = (byte) 0xFF;

      data = new byte[5];
      data[0] = cipheringKey.getKif();
      data[1] = cipheringKey.getKvc();
      data[2] = sourceKey.getKif();
      data[3] = sourceKey.getKvc();
      data[4] = (byte) 0x90;
    }

    request = new ApduRequest(cla, command.getInstructionByte(), p1, p2, data, null);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamCardGenerateKeyParser createResponseParser(ApduResponse apduResponse) {
    return new SamCardGenerateKeyParser(apduResponse, this);
  }
}
