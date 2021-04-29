/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://www.calypsonet-asso.org/
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

import org.eclipse.keyple.card.calypso.sam.SamRevision;
import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private) <br>
 * Builds the SV Undebit APDU command.
 *
 * @since 2.0
 */
final class SamSvPrepareUndebitBuilder
    extends AbstractSamCommandBuilder<SamSvPrepareOperationParser> {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.SV_PREPARE_UNDEBIT;

  /**
   * Instantiates a new SamSvPrepareUndebitBuilder to prepare a transaction to cancel a previous
   * debit transaction.
   *
   * @param samRevision the SAM revision.
   * @param svGetHeader the SV Get command header.
   * @param svGetData a byte array containing the data from the SV get command and response.
   * @param svUndebitCmdBuildDebitCmdBuildData the SV undebit command builder data.
   * @since 2.0
   */
  public SamSvPrepareUndebitBuilder(
      SamRevision samRevision,
      byte[] svGetHeader,
      byte[] svGetData,
      byte[] svUndebitCmdBuildDebitCmdBuildData) {
    super(command);

    byte cla = samRevision.getClassByte();
    byte p1 = (byte) 0x01;
    byte p2 = (byte) 0xFF;
    byte[] data = new byte[16 + svGetData.length]; // header(4) + SvDebit data (12) = 16 bytes

    System.arraycopy(svGetHeader, 0, data, 0, 4);
    System.arraycopy(svGetData, 0, data, 4, svGetData.length);
    System.arraycopy(
        svUndebitCmdBuildDebitCmdBuildData,
        0,
        data,
        4 + svGetData.length,
        svUndebitCmdBuildDebitCmdBuildData.length);

    setApduRequest(
        new ApduRequest(ApduUtil.build(cla, command.getInstructionByte(), p1, p2, data, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamSvPrepareOperationParser createResponseParser(ApduResponse apduResponse) {
    return new SamSvPrepareOperationParser(apduResponse, this);
  }
}
