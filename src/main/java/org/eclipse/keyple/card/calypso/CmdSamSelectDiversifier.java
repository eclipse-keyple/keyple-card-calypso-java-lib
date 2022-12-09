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
 * Builds the SAM Select Diversifier APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamSelectDiversifier extends SamCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(SamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", SamIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied: the SAM is locked.", SamAccessForbiddenException.class));
    STATUS_TABLE = m;
  }

  /**
   * Creates a new instance.
   *
   * @param calypsoSam The Calypso SAM.
   * @param diversifier The key diversifier.
   * @since 2.0.1
   */
  CmdSamSelectDiversifier(CalypsoSamAdapter calypsoSam, byte[] diversifier) {

    super(SamCommandRef.SELECT_DIVERSIFIER, 0, calypsoSam);

    // Format the diversifier on 4 or 8 bytes if needed.
    if (diversifier.length != 4 && diversifier.length != 8) {
      int newLength = diversifier.length < 4 ? 4 : 8;
      byte[] tmp = new byte[newLength];
      System.arraycopy(diversifier, 0, tmp, newLength - diversifier.length, diversifier.length);
      diversifier = tmp;
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoSam.getClassByte(),
                getCommandRef().getInstructionByte(),
                (byte) 0,
                (byte) 0,
                diversifier,
                null)));
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
