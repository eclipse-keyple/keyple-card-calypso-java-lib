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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the Give Random APDU command.
 *
 * @since 2.0.0
 */
final class CmdSamCardGenerateKey extends AbstractSamCommand {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.CARD_GENERATE_KEY;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied.", CalypsoSamAccessForbiddenException.class));
    m.put(
        0x6A00,
        new StatusProperties("Incorrect P1 or P2", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect incoming data: unknown or incorrect format",
            CalypsoSamIncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: ciphering key or key to cipher not found",
            CalypsoSamDataAccessException.class));
    STATUS_TABLE = m;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdSamDigestUpdate and generate the ciphered data for a key ciphered by
   * another.
   *
   * <p>If bot KIF and KVC of the ciphering are equal to 0, the source key is ciphered with the null
   * key.
   *
   * @param productType the SAM product type.
   * @param cipheringKif The KIF of the ciphering key.
   * @param cipheringKvc The KVC of the ciphering key.
   * @param sourceKif The KIF of the source key.
   * @param sourceKvc The KVC of the source key.
   * @since 2.0.0
   */
  CmdSamCardGenerateKey(
      CalypsoSam.ProductType productType,
      byte cipheringKif,
      byte cipheringKvc,
      byte sourceKif,
      byte sourceKvc) {
    super(command);

    byte cla = SamUtilAdapter.getClassByte(productType);

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
   * (package-private)<br>
   * Gets the 32 bytes of ciphered data.
   *
   * @return the ciphered data byte array or null if the operation failed
   * @since 2.0.0
   */
  byte[] getCipheredData() {
    return isSuccessful() ? getApduResponse().getDataOut() : null;
  }
}
