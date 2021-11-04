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
 * Builds the "Write Record" APDU command.
 *
 * @since 2.0.1
 */
final class CmdCardWriteRecord extends AbstractCardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardWriteRecord.class);

  /** The command. */
  private static final CalypsoCardCommand command = CalypsoCardCommand.WRITE_RECORD;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session", CardSessionBufferOverflowException.class));
    m.put(0x6700, new StatusProperties("Lc value not supported", CardDataAccessException.class));
    m.put(
        0x6981,
        new StatusProperties(
            "Wrong EF type (not a Linear EF, or Cyclic EF with Record Number 01h).",
            CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (no session, wrong key, encryption required)",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, DF is invalidated, etc..)",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties("Command not allowed (no current EF)", CardDataAccessException.class));
    m.put(0x6A82, new StatusProperties("File not found", CardDataAccessException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record is not found (record index is 0 or above NumRec)",
            CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P2 value not supported", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /* Construction arguments */
  private final int sfi;
  private final int recordNumber;
  private final byte[] data;

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardWriteRecord.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param sfi the sfi to select.
   * @param recordNumber the record number to write.
   * @param newRecordData the new record data to write.
   * @throws IllegalArgumentException If record number is &lt; 1
   * @throws IllegalArgumentException If the request is inconsistent
   * @since 2.0.1
   */
  CmdCardWriteRecord(
      CalypsoCardClass calypsoCardClass, byte sfi, int recordNumber, byte[] newRecordData) {

    super(command);

    byte cla = calypsoCardClass.getValue();
    this.sfi = sfi;
    this.recordNumber = recordNumber;
    this.data = newRecordData;

    byte p2 = (sfi == 0) ? (byte) 0x04 : (byte) ((byte) (sfi * 8) + 4);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, command.getInstructionByte(), (byte) recordNumber, p2, newRecordData, null)));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format("SFI:%02X, REC:%d", sfi, recordNumber);
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
   * @return the SFI of the accessed file
   * @since 2.0.1
   */
  int getSfi() {
    return sfi;
  }

  /**
   * (package-private)<br>
   *
   * @return the number of the accessed record
   * @since 2.0.1
   */
  int getRecordNumber() {
    return recordNumber;
  }

  /**
   * (package-private)<br>
   *
   * @return the data sent to the card
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
