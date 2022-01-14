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
 * Builds the "Read Record Multiple" APDU command.
 *
 * @since 2.0.4
 */
final class CmdCardReadRecordMultiple extends AbstractCardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardReadRecordMultiple.class);
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CardIllegalParameterException.class));
    m.put(
        0x6981,
        new StatusProperties("Incorrect EF type: Binary EF.", CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (PIN code not presented, encryption required).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, Stored Value log file and a Stored Value operation was done during the current secure session).",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Incorrect file type: the Current File is not an EF. Supersedes 6981h.",
            CardDataAccessException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect command data (incorrect Tag, incorrect Length, R. Length > RecSize, R. Offset + R. Length > RecSize, R. Length = 0).",
            CardIllegalParameterException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found (record index is 0, or above NumRec).",
            CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardIllegalParameterException.class));
    m.put(
        0x6200,
        new StatusProperties(
            "Successful execution, partial read only: issue another Read Record Multiple from record (P1 + (Size of returned data) / (R. Length)) to continue reading."));
    STATUS_TABLE = m;
  }

  private final byte sfi;
  private final byte recordNumber;
  private final byte offset;
  private final byte length;

  /**
   * (package-private)<br>
   * Constructor.
   *
   * @param calypsoCardClass The CLA field value.
   * @param sfi The SFI.
   * @param recordNumber The number of the first record to read.
   * @param offset The offset from which to read in each record.
   * @param length The number of bytes to read in each record.
   * @since 2.0.4
   */
  CmdCardReadRecordMultiple(
      CalypsoCardClass calypsoCardClass, byte sfi, byte recordNumber, byte offset, byte length) {

    super(CalypsoCardCommand.READ_RECORD_MULTIPLE);

    this.sfi = sfi;
    this.recordNumber = recordNumber;
    this.offset = offset;
    this.length = length;

    byte p2 = (byte) (sfi * 8 + 5);
    byte[] dataIn = new byte[] {0x54, 0x02, offset, length};

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(),
                getCommandRef().getInstructionByte(),
                recordNumber,
                p2,
                dataIn,
                (byte) 0)));

    if (logger.isDebugEnabled()) {
      String extraInfo =
          String.format(
              "SFI:%02Xh, RECORD_NUMBER:%d, OFFSET:%d, LENGTH:%d",
              sfi, recordNumber, offset, length);
      addSubName(extraInfo);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @return false
   * @since 2.0.4
   */
  @Override
  boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * (package-private)<br>
   *
   * @return The SFI.
   * @since 2.0.4
   */
  int getSfi() {
    return sfi;
  }

  /**
   * (package-private)<br>
   *
   * @return The offset.
   * @since 2.0.4
   */
  public byte getOffset() {
    return offset;
  }

  /**
   * (package-private)<br>
   * Parses the APDU response into a sorted map of read bytes by record number.
   *
   * @return An empty map if no data is available.
   * @since 2.0.4
   */
  SortedMap<Integer, byte[]> getResults() {
    SortedMap<Integer, byte[]> results = new TreeMap<Integer, byte[]>();
    byte[] dataOut = getApduResponse().getDataOut();
    int nbRecords = dataOut.length / length;
    for (int i = 0; i < nbRecords; i++) {
      results.put(recordNumber + i, Arrays.copyOfRange(dataOut, i * length, (i + 1) * length));
    }
    return results;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.4
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
