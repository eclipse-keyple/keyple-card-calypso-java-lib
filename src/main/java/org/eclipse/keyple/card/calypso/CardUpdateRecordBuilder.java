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

import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Update Record APDU command.
 *
 * @since 2.0
 */
final class CardUpdateRecordBuilder extends AbstractCardCommandBuilder<CardUpdateRecordParser> {
  private static final Logger logger = LoggerFactory.getLogger(CardUpdateRecordBuilder.class);

  /** The command. */
  private static final CalypsoCardCommand command = CalypsoCardCommand.UPDATE_RECORD;

  /* Construction arguments */
  private final int sfi;
  private final int recordNumber;
  private final byte[] data;

  /**
   * Instantiates a new CardUpdateRecordBuilder.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param sfi the sfi to select.
   * @param recordNumber the record number to update.
   * @param newRecordData the new record data to write.
   * @throws IllegalArgumentException - if record number is &lt; 1
   * @throws IllegalArgumentException - if the request is inconsistent
   * @since 2.0
   */
  public CardUpdateRecordBuilder(
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
  public CardUpdateRecordParser createResponseParser(ApduResponseApi apduResponse) {
    return new CardUpdateRecordParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command modified the contents of the card and therefore uses the session buffer.
   *
   * @return True
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return true;
  }

  /**
   * @return The SFI of the accessed file
   * @since 2.0
   */
  public int getSfi() {
    return sfi;
  }

  /**
   * @return The number of the accessed record
   * @since 2.0
   */
  public int getRecordNumber() {
    return recordNumber;
  }

  /**
   * @return The data sent to the card
   * @since 2.0
   */
  public byte[] getData() {
    return data;
  }
}
