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
 * Builds the SAM Select Diversifier APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamSelectDiversifier extends AbstractSamCommand {

  /** The command. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.SELECT_DIVERSIFIER;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied: the SAM is locked.",
            CalypsoSamAccessForbiddenException.class));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdSamSelectDiversifier.
   *
   * @param productType the SAM product type.
   * @param diversifier the application serial number.
   * @throws IllegalArgumentException If the diversifier is null or has a wrong length
   * @since 2.0.1
   */
  CmdSamSelectDiversifier(CalypsoSam.ProductType productType, byte[] diversifier) {
    super(command);

    if (diversifier == null || (diversifier.length != 4 && diversifier.length != 8)) {
      throw new IllegalArgumentException("Bad diversifier value!");
    }

    byte cla = SamUtilAdapter.getClassByte(productType);
    byte p1 = 0x00;
    byte p2 = 0x00;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, diversifier, null)));
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
