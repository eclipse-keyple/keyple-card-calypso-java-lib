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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the SV Prepare Load APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamSvPrepareLoad extends SamCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(SamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", SamIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied.", SamAccessForbiddenException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P1 or P2", SamIllegalParameterException.class));
    m.put(
        0x6A80,
        new StatusProperties("Incorrect incoming data.", SamIncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: ciphering key not found", SamDataAccessException.class));
    STATUS_TABLE = m;
  }

  private final SvCommandSecurityDataApiAdapter data;

  /**
   * Instantiates a new CmdSamSvPrepareLoad to prepare a load transaction.
   *
   * <p>Build the SvPrepareLoad APDU from the SvGet command and response, the SvReload partial
   * command
   *
   * @param calypsoSam The Calypso SAM.
   * @param data The SV input/output command data.
   * @since 2.0.1
   */
  CmdSamSvPrepareLoad(CalypsoSamAdapter calypsoSam, SvCommandSecurityDataApiAdapter data) {

    super(SamCommandRef.SV_PREPARE_LOAD, 0, calypsoSam);

    this.data = data;

    byte cla = calypsoSam.getClassByte();
    byte p1 = (byte) 0x01;
    byte p2 = (byte) 0xFF;
    byte[] dataIn =
        new byte[19 + data.getSvGetResponse().length]; // header(4) + SvReload data (15) = 19 bytes

    System.arraycopy(data.getSvGetRequest(), 0, dataIn, 0, 4);
    System.arraycopy(data.getSvGetResponse(), 0, dataIn, 4, data.getSvGetResponse().length);
    System.arraycopy(
        data.getSvCommandPartialRequest(),
        0,
        dataIn,
        4 + data.getSvGetResponse().length,
        data.getSvCommandPartialRequest().length);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, dataIn, null)));
  }

  @Override
  void parseApduResponse(ApduResponseApi apduResponse) throws SamCommandException {
    super.parseApduResponse(apduResponse);
    byte[] dataOut = apduResponse.getDataOut();
    data.setSerialNumber(getCalypsoSam().getSerialNumber())
        .setTerminalChallenge(Arrays.copyOfRange(dataOut, 0, 3))
        .setTransactionNumber(Arrays.copyOfRange(dataOut, 3, 6))
        .setTerminalSvMac(Arrays.copyOfRange(dataOut, 6, dataOut.length));
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
