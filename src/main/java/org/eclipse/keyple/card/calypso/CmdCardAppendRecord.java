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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the "Append Record" APDU command.
 *
 * @since 2.0.1
 */
final class CmdCardAppendRecord extends CardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardAppendRecord.class);

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardIllegalParameterException.class));
    m.put(0x6700, new StatusProperties("Lc value not supported.", CardDataAccessException.class));
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session.", CardSessionBufferOverflowException.class));
    m.put(
        0x6981,
        new StatusProperties("The current EF is not a Cyclic EF.", CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (no session, wrong key).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, DF is invalidated, etc..).",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Command not allowed (no current EF).", CardDataAccessException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    STATUS_TABLE = m;
  }

  /* Construction arguments */
  private final int sfi;
  private final byte[] data;

  /**
   * Instantiates a new CmdCardUpdateRecord.
   *
   * @param calypsoCard The Calypso card.
   * @param sfi The sfi to select.
   * @param newRecordData The new record data to write.
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.0.1
   */
  CmdCardAppendRecord(CalypsoCardAdapter calypsoCard, byte sfi, byte[] newRecordData) {

    super(CardCommandRef.APPEND_RECORD, 0, calypsoCard);

    byte cla = calypsoCard.getCardClass().getValue();

    this.sfi = sfi;
    this.data = newRecordData;

    byte p1 = (byte) 0x00;
    byte p2 = (sfi == 0) ? (byte) 0x00 : (byte) (sfi * 8);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, getCommandRef().getInstructionByte(), p1, p2, newRecordData, null)));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format("SFI:%02Xh", sfi);
      addSubName(extraInfo);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  void parseApduResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.parseApduResponse(apduResponse);
    getCalypsoCard().addCyclicContent((byte) sfi, data);
  }

  /**
   * {@inheritDoc}
   *
   * @return True
   * @since 2.0.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return true;
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
