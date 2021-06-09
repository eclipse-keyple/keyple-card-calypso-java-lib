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
 * Builds the Unlock APDU command.
 *
 * @since 2.0
 */
final class SamUnlockBuilder extends AbstractSamCommandBuilder<SamUnlockParser> {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.UNLOCK;

  /**
   * CalypsoSamCardSelectorBuilder constructor
   *
   * @param revision the SAM revision.
   * @param unlockData the unlock data.
   * @since 2.0
   */
  public SamUnlockBuilder(CalypsoSam.ProductType revision, byte[] unlockData) {
    super(command);
    if (revision != null) {
      this.defaultProductType = revision;
    }
    byte cla = SamUtilAdapter.getClassByte(this.defaultProductType);
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
   * @since 2.0
   */
  @Override
  public SamUnlockParser createResponseParser(ApduResponseApi apduResponse) {
    return new SamUnlockParser(apduResponse, this);
  }
}
