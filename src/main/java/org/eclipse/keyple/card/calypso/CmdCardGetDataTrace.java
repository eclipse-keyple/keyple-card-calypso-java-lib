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
 * Builds the Get data APDU commands.
 *
 * <p>This command can not be sent in session because it would generate a 6Cxx status in contact
 * mode and thus make calculation of the digest impossible.
 *
 * @since 2.0.1
 */
// TODO not used
final class CmdCardGetDataTrace extends AbstractCardCommand {

  private static final CalypsoCardCommand command = CalypsoCardCommand.GET_DATA_TRACE;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
    m.put(
        0x6A88,
        new StatusProperties(
            "Data object not found (optional mode not available).", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties(
            "P1 or P2 value not supported (<>004fh, 0062h, 006Fh, 00C0h, 00D0h, 0185h and 5F52h, according to "
                + "available optional modes).",
            CardIllegalParameterException.class));
    m.put(
        0x6283,
        new StatusProperties("Successful execution, FCI request and DF is invalidated.", null));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardGetDataTrace.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0.1
   */
  CmdCardGetDataTrace(CalypsoCardClass calypsoCardClass) {

    super(command);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(),
                command.getInstructionByte(),
                (byte) 0x01,
                (byte) 0x85,
                null,
                (byte) 0x00)));
  }

  /**
   * {@inheritDoc}
   *
   * @return False
   * @since 2.0.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return false;
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
