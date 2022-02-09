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
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the SV Prepare Debit or Undebit APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamSvPrepareDebitOrUndebit extends AbstractSamCommand {

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
        0x6A00,
        new StatusProperties("Incorrect P1 or P2", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect incoming data.", CalypsoSamIncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: ciphering key not found", CalypsoSamDataAccessException.class));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdSamSvPrepareDebit to prepare a debit or cancel transaction.
   *
   * @param isDebitCommand True if the current card command is an "SV Debit" command, false if it is
   *     a "SV Undebit" command.
   * @param productType the SAM product type.
   * @param svGetHeader the SV Get command header.
   * @param svGetData a byte array containing the data from the SV get command and response.
   * @param svDebitOrUndebitCmdBuildData the SV debit/undebit command data.
   * @since 2.0.1
   */
  CmdSamSvPrepareDebitOrUndebit(
      boolean isDebitCommand,
      CalypsoSam.ProductType productType,
      byte[] svGetHeader,
      byte[] svGetData,
      byte[] svDebitOrUndebitCmdBuildData) {
    super(
        isDebitCommand ? CalypsoSamCommand.SV_PREPARE_DEBIT : CalypsoSamCommand.SV_PREPARE_UNDEBIT,
        0);

    byte cla = SamUtilAdapter.getClassByte(productType);
    byte p1 = (byte) 0x01;
    byte p2 = (byte) 0xFF;
    byte[] data = new byte[16 + svGetData.length]; // header(4) + SvDebit data (12) = 16 bytes

    System.arraycopy(svGetHeader, 0, data, 0, 4);
    System.arraycopy(svGetData, 0, data, 4, svGetData.length);
    System.arraycopy(
        svDebitOrUndebitCmdBuildData,
        0,
        data,
        4 + svGetData.length,
        svDebitOrUndebitCmdBuildData.length);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, data, null)));
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
