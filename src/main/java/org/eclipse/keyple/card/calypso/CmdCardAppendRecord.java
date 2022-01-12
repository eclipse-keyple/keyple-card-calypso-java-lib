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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the "Append Record" APDU command.
 *
 * @since 2.0.1
 */
final class CmdCardAppendRecord extends AbstractCardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardAppendRecord.class);

  /** The command. */
  private static final CalypsoCardCommand command = CalypsoCardCommand.APPEND_RECORD;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
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
   * (package-private)<br>
   * Instantiates a new CmdCardUpdateRecord.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param sfi the sfi to select.
   * @param newRecordData the new record data to write.
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.0.1
   */
  CmdCardAppendRecord(CalypsoCardClass calypsoCardClass, byte sfi, byte[] newRecordData) {

    super(command);

    byte cla = calypsoCardClass.getValue();

    this.sfi = sfi;
    this.data = newRecordData;

    byte p1 = (byte) 0x00;
    byte p2 = (sfi == 0) ? (byte) 0x00 : (byte) (sfi * 8);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, newRecordData, null)));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format("SFI:%02Xh", sfi);
      addSubName(extraInfo);
    }
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
   * (package-private)<br>
   *
   * @return The SFI of the accessed file
   * @since 2.0.1
   */
  int getSfi() {
    return sfi;
  }

  /**
   * (package-private)<br>
   *
   * @return The data sent to the card
   * @since 2.0.1
   */
  byte[] getData() {
    return data;
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
