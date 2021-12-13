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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import org.eclipse.keyple.core.util.ApduUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Read Records APDU command.
 *
 * @since 2.0.1
 */
final class CmdCardReadRecords extends AbstractCardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardReadRecords.class);

  private static final CalypsoCardCommand command = CalypsoCardCommand.READ_RECORDS;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
    m.put(
        0x6981,
        new StatusProperties("Command forbidden on binary files", CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (PIN code not presented, encryption required).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, stored value log file and a stored value operation was done during the current session).",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties("Command not allowed (no current EF)", CardDataAccessException.class));
    m.put(0x6A82, new StatusProperties("File not found", CardDataAccessException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found (record index is 0, or above NumRec", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P2 value not supported", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * Indicates if one or multiple records
   *
   * @since 2.0.1
   */
  enum ReadMode {
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
   * (package-private)<br>
   * Instantiates a new read records cmd build.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param sfi the sfi top select.
   * @param firstRecordNumber the record number to read (or first record to read in case of several.
   *     records)
   * @param readMode read mode, requests the reading of one or all the records.
   * @param expectedLength the expected length of the record(s).
   * @throws IllegalArgumentException If record number &lt; 1
   * @throws IllegalArgumentException If the request is inconsistent
   * @since 2.0.1
   */
  CmdCardReadRecords(
      CalypsoCardClass calypsoCardClass,
      int sfi,
      int firstRecordNumber,
      ReadMode readMode,
      int expectedLength) {

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
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(), command.getInstructionByte(), p1, p2, null, le)));

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
      addSubName(extraInfo);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @return false
   * @since 2.0.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return false;
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
   * @return the number of the first record to read
   * @since 2.0.1
   */
  int getFirstRecordNumber() {
    return firstRecordNumber;
  }

  /**
   * (package-private)<br>
   *
   * @return the readJustOneRecord flag
   * @since 2.0.1
   */
  ReadMode getReadMode() {
    return readMode;
  }

  /**
   * (package-private)<br>
   * Parses the Apdu response as a data record (single or multiple), retrieves the records and place
   * it in a map.
   *
   * <p>The map index follows the card specification, i.e. starts at 1 for the first record.
   *
   * <p>An empty map is returned if no data is available.
   *
   * @return a map of records
   * @since 2.0.1
   */
  SortedMap<Integer, byte[]> getRecords() {
    SortedMap<Integer, byte[]> records = new TreeMap<Integer, byte[]>();
    if (getReadMode() == CmdCardReadRecords.ReadMode.ONE_RECORD) {
      if (getApduResponse().getDataOut().length != 0) {
        records.put(getFirstRecordNumber(), getApduResponse().getDataOut());
      }
    } else {
      byte[] apdu = getApduResponse().getDataOut();
      int apduLen = apdu.length;
      int index = 0;
      while (apduLen > 0) {
        byte recordNb = apdu[index++];
        byte len = apdu[index++];
        records.put((int) recordNb, Arrays.copyOfRange(apdu, index, index + len));
        index = index + len;
        apduLen = apduLen - 2 - len;
      }
    }
    return records;
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
