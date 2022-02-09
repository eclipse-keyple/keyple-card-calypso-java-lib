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
 * Builds the "Unlock" APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamUnlock extends AbstractSamCommand {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.UNLOCK;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied (SAM not locked?).",
            CalypsoSamAccessForbiddenException.class));
    m.put(
        0x6988,
        new StatusProperties("Incorrect UnlockData.", CalypsoSamSecurityDataException.class));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * CalypsoSamCardSelectorBuilder constructor
   *
   * @param productType the SAM product type.
   * @param unlockData the unlocked data.
   * @since 2.0.1
   */
  CmdSamUnlock(CalypsoSam.ProductType productType, byte[] unlockData) {
    super(command, 0);
    byte cla = SamUtilAdapter.getClassByte(productType);
    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    if (unlockData == null) {
      throw new IllegalArgumentException("Unlock data null!");
    }

    if (unlockData.length != 8 && unlockData.length != 16) {
      throw new IllegalArgumentException("Unlock data should be 8 ou 16 bytes long!");
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, unlockData, null)));
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
