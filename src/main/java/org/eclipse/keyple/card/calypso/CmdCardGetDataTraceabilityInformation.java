/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the Get data APDU commands for the TRACEABILITY INFORMATION tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because it would generate a
 * 6Cxx status and thus make calculation of the digest impossible.
 *
 * @since 2.1.0
 */
final class CmdCardGetDataTraceabilityInformation extends AbstractCardCommand {

  private static final CalypsoCardCommand command = CalypsoCardCommand.GET_DATA;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractCardCommand.STATUS_TABLE);
    m.put(
        0x6A88,
        new StatusProperties(
            "Data object not found (optional mode not available).", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardDataAccessException.class));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardGetDataTrace.
   *
   * @param calypsoCard The Calypso card.
   * @since 2.2.3
   */
  CmdCardGetDataTraceabilityInformation(CalypsoCardAdapter calypsoCard) {
    super(command, 0, calypsoCard);
    buildCommand(calypsoCard.getCardClass());
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardGetDataTrace.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @since 2.1.0
   */
  CmdCardGetDataTraceabilityInformation(CalypsoCardClass calypsoCardClass) {
    super(command, 0, null);
    buildCommand(calypsoCardClass);
  }

  /**
   * (private)<br>
   * Builds the command.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   */
  private void buildCommand(CalypsoCardClass calypsoCardClass) {
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
   * @since 2.2.3
   */
  @Override
  void parseApduResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.parseApduResponse(apduResponse);
    getCalypsoCard().setTraceabilityInformation(apduResponse.getDataOut());
  }

  /**
   * {@inheritDoc}
   *
   * @return False
   * @since 2.1.0
   */
  @Override
  boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
