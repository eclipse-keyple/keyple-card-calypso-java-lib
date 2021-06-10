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

import java.util.*;
import org.calypsonet.terminal.card.ApduResponseApi;

/**
 * (package-private)<br>
 * Parses the Read Records response.
 *
 * @since 2.0
 */
final class CardReadRecordsParser extends AbstractCardResponseParser {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
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
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  protected Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * Instantiates a new CardReadRecordsParser.
   *
   * @param apduResponse the response from the card.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public CardReadRecordsParser(ApduResponseApi apduResponse, CardReadRecordsBuilder builder) {
    super(apduResponse, builder);
  }

  /**
   * Parses the Apdu response as a data record (single or multiple), retrieves the records and place
   * it in an map.
   *
   * <p>The map index follows the card specification, i.e. starts at 1 for the first record.
   *
   * <p>An empty map is returned if no data is available.
   *
   * @return a map of records
   * @since 2.0
   */
  public SortedMap<Integer, byte[]> getRecords() {
    SortedMap<Integer, byte[]> records = new TreeMap<Integer, byte[]>();
    if (((CardReadRecordsBuilder) builder).getReadMode()
        == CardReadRecordsBuilder.ReadMode.ONE_RECORD) {
      records.put(((CardReadRecordsBuilder) builder).getFirstRecordNumber(), response.getDataOut());
    } else {
      byte[] apdu = response.getDataOut();
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
}
