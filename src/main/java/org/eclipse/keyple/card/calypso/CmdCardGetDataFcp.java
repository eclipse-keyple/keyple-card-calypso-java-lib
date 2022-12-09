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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the Get data APDU commands for the FCP tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because it would generate a
 * 6Cxx status and thus make calculation of the digest impossible.
 *
 * <p>The value of the Proprietary Information tag is extracted from the Select File response and
 * made available using the corresponding getter.
 *
 * @since 2.0.1
 */
final class CmdCardGetDataFcp extends CardCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6A88,
        new StatusProperties(
            "Data object not found (optional mode not available).", CardDataAccessException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardDataAccessException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CmdCardGetDataFci.
   *
   * @param calypsoCard The Calypso card.
   * @since 2.2.3
   */
  CmdCardGetDataFcp(CalypsoCardAdapter calypsoCard) {
    super(CardCommandRef.GET_DATA, 0, calypsoCard);
    buildCommand(calypsoCard.getCardClass());
  }

  /**
   * Instantiates a new CmdCardGetDataFci.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0.1
   */
  CmdCardGetDataFcp(CalypsoCardClass calypsoCardClass) {
    super(CardCommandRef.GET_DATA, 0, null);
    buildCommand(calypsoCardClass);
  }

  /**
   * Builds the command.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   */
  private void buildCommand(CalypsoCardClass calypsoCardClass) {
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(),
                getCommandRef().getInstructionByte(),
                (byte) 0x00,
                (byte) 0x62,
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
    CmdCardSelectFile.parseProprietaryInformation(apduResponse.getDataOut(), getCalypsoCard());
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
