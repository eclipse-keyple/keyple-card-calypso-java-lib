/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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
 * Builds the SV Check APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamSvCheck extends AbstractSamCommand {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.SV_CHECK;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "No active SV transaction.", CalypsoSamAccessForbiddenException.class));
    m.put(
        0x6988,
        new StatusProperties("Incorrect SV signature.", CalypsoSamSecurityDataException.class));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdSamSvCheck to authenticate a card SV transaction.
   *
   * @param calypsoSam The Calypso SAM.
   * @param svCardSignature null if the operation is to abort the SV transaction, a 3 or 6-byte
   *     array. containing the card signature from SV Debit, SV Load or SV Undebit.
   * @since 2.0.1
   */
  CmdSamSvCheck(CalypsoSamAdapter calypsoSam, byte[] svCardSignature) {

    super(command, 0, calypsoSam);

    if (svCardSignature != null && (svCardSignature.length != 3 && svCardSignature.length != 6)) {
      throw new IllegalArgumentException("Invalid svCardSignature.");
    }

    byte cla = SamUtilAdapter.getClassByte(calypsoSam.getProductType());
    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    if (svCardSignature != null) {
      // the operation is not "abort"
      byte[] data = new byte[svCardSignature.length];
      System.arraycopy(svCardSignature, 0, data, 0, svCardSignature.length);
      setApduRequest(
          new ApduRequestAdapter(
              ApduUtil.build(cla, command.getInstructionByte(), p1, p2, data, null)));
    } else {
      setApduRequest(
          new ApduRequestAdapter(
              ApduUtil.build(
                  cla,
                  command.getInstructionByte(),
                  p1,
                  p2,
                  new byte[0],
                  null))); // Case 3 without input data.
    }
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
