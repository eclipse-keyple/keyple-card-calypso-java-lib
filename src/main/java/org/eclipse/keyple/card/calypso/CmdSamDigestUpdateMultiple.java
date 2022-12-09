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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the SAM Digest Update Multiple APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamDigestUpdateMultiple extends SamCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(SamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", SamIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied.", SamAccessForbiddenException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect value in the incoming data: incorrect structure.",
            SamIncorrectInputDataException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1.", SamIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CmdSamDigestUpdateMultiple.
   *
   * @param calypsoSam The Calypso SAM.
   * @param digestData the digest data.
   * @since 2.0.1
   */
  CmdSamDigestUpdateMultiple(CalypsoSamAdapter calypsoSam, byte[] digestData) {
    super(SamCommandRef.DIGEST_UPDATE_MULTIPLE, 0, calypsoSam);

    byte cla = calypsoSam.getClassByte();
    byte p1 = (byte) 0x80;
    byte p2 = (byte) 0x00;

    if (digestData == null || digestData.length > 255) {
      throw new IllegalArgumentException("Digest data null or too long!");
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, digestData, null)));
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
