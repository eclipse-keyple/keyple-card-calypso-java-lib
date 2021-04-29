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

import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;
import org.eclipse.keyple.core.util.ApduUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Read Records APDU command.
 *
 * @since 2.0
 */
final class PoReadRecordsBuilder extends AbstractPoCommandBuilder<PoReadRecordsParser> {

  private static final Logger logger = LoggerFactory.getLogger(PoReadRecordsBuilder.class);

  private static final PoCommand command = PoCommand.READ_RECORDS;

  /** Indicates if one or multiple records */
  public enum ReadMode {
    /** read one record */
    ONE_RECORD,
    /** read multiple records */
    MULTIPLE_RECORD
  }

  // Construction arguments used for parsing
  private final int sfi;
  private final int firstRecordNumber;
  private final ReadMode readMode;

  /**
   * Instantiates a new read records cmd build.
   *
   * @param poClass indicates which CLA byte should be used for the Apdu.
   * @param sfi the sfi top select.
   * @param firstRecordNumber the record number to read (or first record to read in case of several.
   *     records)
   * @param readMode read mode, requests the reading of one or all the records.
   * @param expectedLength the expected length of the record(s).
   * @throws IllegalArgumentException - if record number &lt; 1
   * @throws IllegalArgumentException - if the request is inconsistent
   * @since 2.0
   */
  public PoReadRecordsBuilder(
      PoClass poClass, int sfi, int firstRecordNumber, ReadMode readMode, int expectedLength) {
    super(command);

    this.sfi = sfi;
    this.firstRecordNumber = firstRecordNumber;
    this.readMode = readMode;

    byte p1 = (byte) firstRecordNumber;
    byte p2 = (sfi == (byte) 0x00) ? (byte) 0x05 : (byte) ((byte) (sfi * 8) + 5);
    if (readMode == ReadMode.ONE_RECORD) {
      p2 = (byte) (p2 - (byte) 0x01);
    }
    byte le = (byte) expectedLength;
    setApduRequest(
        new ApduRequest(
            ApduUtil.build(poClass.getValue(), command.getInstructionByte(), p1, p2, null, le)));

    if (logger.isDebugEnabled()) {
      String extraInfo =
          "SFI: "
              + Integer.toHexString(sfi)
              + "h, REC: "
              + firstRecordNumber
              + ", READMODE: "
              + readMode.name()
              + ", EXPECTEDLENGTH: "
              + expectedLength;
      this.addSubName(extraInfo);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoReadRecordsParser createResponseParser(ApduResponse apduResponse) {
    return new PoReadRecordsParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command doesn't modify the contents of the PO and therefore doesn't uses the session
   * buffer.
   *
   * @return false
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * @return the SFI of the accessed file
   * @since 2.0
   */
  public int getSfi() {
    return sfi;
  }

  /**
   * @return the number of the first record to read
   * @since 2.0
   */
  public int getFirstRecordNumber() {
    return firstRecordNumber;
  }

  /**
   * @return the readJustOneRecord flag
   * @since 2.0
   */
  public ReadMode getReadMode() {
    return readMode;
  }
}
