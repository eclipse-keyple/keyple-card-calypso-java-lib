/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.calypso;

import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Update Record APDU command.
 *
 * @since 2.0
 */
final class PoUpdateRecordBuilder extends AbstractPoCommandBuilder<PoUpdateRecordParser> {
  private static final Logger logger = LoggerFactory.getLogger(PoUpdateRecordBuilder.class);

  /** The command. */
  private static final CalypsoPoCommand command = CalypsoPoCommand.UPDATE_RECORD;

  /* Construction arguments */
  private final int sfi;
  private final int recordNumber;
  private final byte[] data;

  /**
   * Instantiates a new PoUpdateRecordBuilder.
   *
   * @param poClass indicates which CLA byte should be used for the Apdu.
   * @param sfi the sfi to select.
   * @param recordNumber the record number to update.
   * @param newRecordData the new record data to write.
   * @throws IllegalArgumentException - if record number is &lt; 1
   * @throws IllegalArgumentException - if the request is inconsistent
   * @since 2.0
   */
  public PoUpdateRecordBuilder(PoClass poClass, byte sfi, int recordNumber, byte[] newRecordData) {
    super(command);

    byte cla = poClass.getValue();
    this.sfi = sfi;
    this.recordNumber = recordNumber;
    this.data = newRecordData;

    byte p2 = (sfi == 0) ? (byte) 0x04 : (byte) ((byte) (sfi * 8) + 4);

    setApduRequest(
        new ApduRequest(
            cla, command.getInstructionByte(), (byte) recordNumber, p2, newRecordData, null));

    if (logger.isDebugEnabled()) {
      String extraInfo = String.format("SFI=%02X, REC=%d", sfi, recordNumber);
      this.addSubName(extraInfo);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoUpdateRecordParser createResponseParser(ApduResponse apduResponse) {
    return new PoUpdateRecordParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command modified the contents of the PO and therefore uses the session buffer.
   *
   * @return true
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return true;
  }

  /**
   * @return the SFI of the accessed file
   * @since 2.0
   */
  public int getSfi() {
    return sfi;
  }

  /**
   * @return the number of the accessed record
   * @since 2.0
   */
  public int getRecordNumber() {
    return recordNumber;
  }

  /**
   * @return the data sent to the PO
   * @since 2.0
   */
  public byte[] getData() {
    return data;
  }
}
