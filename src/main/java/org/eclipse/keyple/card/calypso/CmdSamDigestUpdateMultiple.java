/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
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
 * Builds the SAM Digest Update Multiple APDU command.
 *
 * @since 2.0.0
 */
final class CmdSamDigestUpdateMultiple extends AbstractSamCommand {

  /** The command. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.DIGEST_UPDATE_MULTIPLE;

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
        0x6A80,
        new StatusProperties(
            "Incorrect value in the incoming data: incorrect structure.",
            CalypsoSamIncorrectInputDataException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1.", CalypsoSamIllegalParameterException.class));
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
   * Instantiates a new CmdSamDigestUpdateMultiple.
   *
   * @param productType the product type.
   * @param encryptedSession the encrypted session flag, true if encrypted.
   * @param digestData the digest data.
   * @since 2.0.0
   */
  CmdSamDigestUpdateMultiple(
      CalypsoSam.ProductType productType, boolean encryptedSession, byte[] digestData) {
    super(command);

    byte cla = SamUtilAdapter.getClassByte(productType);
    byte p1 = (byte) 0x00;
    byte p2 = encryptedSession ? (byte) 0x80 : (byte) 0x00;

    if (digestData == null || digestData.length > 255) {
      throw new IllegalArgumentException("Digest data null or too long!");
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, digestData, null)));
  }
}
