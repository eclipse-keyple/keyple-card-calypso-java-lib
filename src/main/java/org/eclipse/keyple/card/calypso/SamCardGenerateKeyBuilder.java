/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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

import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private) <br>
 * Builds the Give Random APDU command.
 *
 * @since 2.0.0
 */
final class SamCardGenerateKeyBuilder extends AbstractSamCommandBuilder<SamCardGenerateKeyParser> {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.CARD_GENERATE_KEY;

  /**
   * Instantiates a new SamDigestUpdateBuilder and generate the ciphered data for a key ciphered by
   * another.
   *
   * <p>If bot KIF and KVC of the ciphering are equal to 0, the source key is ciphered with the null
   * key.
   *
   * @param samProductType The SAM samProductType.
   * @param cipheringKif The KIF of the ciphering key.
   * @param cipheringKvc The KVC of the ciphering key.
   * @param sourceKif The KIF of the source key.
   * @param sourceKvc The KVC of the source key.
   * @since 2.0.0
   */
  public SamCardGenerateKeyBuilder(
      CalypsoSam.ProductType samProductType,
      byte cipheringKif,
      byte cipheringKvc,
      byte sourceKif,
      byte sourceKvc) {
    super(command);
    if (samProductType != null) {
      this.defaultProductType = samProductType;
    }

    byte cla = SamUtilAdapter.getClassByte(this.defaultProductType);

    byte p1;
    byte p2;
    byte[] data;

    if (cipheringKif == 0 && cipheringKvc == 0) {
      // case where the source key is ciphered by the null key
      p1 = (byte) 0xFF;
      p2 = (byte) 0x00;

      data = new byte[3];
      data[0] = sourceKif;
      data[1] = sourceKvc;
      data[2] = (byte) 0x90;
    } else {
      p1 = (byte) 0xFF;
      p2 = (byte) 0xFF;

      data = new byte[5];
      data[0] = cipheringKif;
      data[1] = cipheringKvc;
      data[2] = sourceKif;
      data[3] = sourceKvc;
      data[4] = (byte) 0x90;
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, data, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public SamCardGenerateKeyParser createResponseParser(ApduResponseApi apduResponse) {
    return new SamCardGenerateKeyParser(apduResponse, this);
  }
}
