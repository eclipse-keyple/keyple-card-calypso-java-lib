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
 * Builds the Get Challenge APDU command.
 *
 * @since 2.0.0
 */
final class CmdSamGetChallenge extends AbstractSamCommand {

  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.GET_CHALLENGE;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Le.", CalypsoSamIllegalParameterException.class));
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
   * Instantiates a new CmdSamGetChallenge.
   *
   * @param productType the SAM product type.
   * @param expectedResponseLength the expected response length.
   * @throws IllegalArgumentException - if the expected response length has wrong value.
   * @since 2.0.0
   */
  CmdSamGetChallenge(CalypsoSam.ProductType productType, byte expectedResponseLength) {
    super(command);

    if (expectedResponseLength != 0x04 && expectedResponseLength != 0x08) {
      throw new IllegalArgumentException(
          String.format("Bad challenge length! Expected 4 or 8, got %s", expectedResponseLength));
    }
    byte cla = SamUtilAdapter.getClassByte(productType);
    byte p1 = 0x00;
    byte p2 = 0x00;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, command.getInstructionByte(), p1, p2, null, expectedResponseLength)));
  }

  /**
   * (package-private)<br>
   * Gets the challenge.
   *
   * @return the challenge
   * @since 2.0.0
   */
  byte[] getChallenge() {
    return isSuccessful() ? getApduResponse().getDataOut() : null;
  }
}
