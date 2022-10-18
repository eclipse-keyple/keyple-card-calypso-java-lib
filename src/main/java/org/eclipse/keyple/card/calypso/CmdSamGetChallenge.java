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
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the Get Challenge APDU command.
 *
 * @since 2.0.1
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
   * (package-private)<br>
   * Instantiates a new CmdSamGetChallenge.
   *
   * @param calypsoSam The Calypso SAM.
   * @param expectedResponseLength the expected response length.
   * @since 2.0.1
   */
  CmdSamGetChallenge(CalypsoSamAdapter calypsoSam, int expectedResponseLength) {

    super(command, expectedResponseLength, calypsoSam);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                SamUtilAdapter.getClassByte(calypsoSam.getProductType()),
                command.getInstructionByte(),
                (byte) 0,
                (byte) 0,
                null,
                (byte) expectedResponseLength)));
  }

  /**
   * (package-private)<br>
   * Gets the challenge.
   *
   * @return the challenge
   * @since 2.0.1
   */
  byte[] getChallenge() {
    return isSuccessful() ? getApduResponse().getDataOut() : null;
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
