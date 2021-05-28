/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.card.calypso.card;

/**
 * This POJO contains all metadata of a Calypso EF.
 *
 * @since 2.0
 */
public interface FileHeader {
  /**
   * Gets the associated LID.
   *
   * @return the LID
   * @since 2.0
   */
  short getLid();

  /**
   * Gets the number of records :
   *
   * <ul>
   *   <li>For a Counter file, the number of records is always 1.<br>
   *       Extra bytes (rest of the division of the file size by 3) aren't accessible.
   *   <li>For a Binary file, the number of records is always 1.
   * </ul>
   *
   * @return the number of records
   * @since 2.0
   */
  int getRecordsNumber();

  /**
   * Gets the size of a record :
   *
   * <ul>
   *   <li>For a Counter file, the record size is the original size of the record #1.<br>
   *       Extra bytes (rest of the division of the file size by 3) aren't accessible.
   *   <li>For a Binary file, the size of the record is corresponding to the file size.
   * </ul>
   *
   * @return the size of a record
   * @since 2.0
   */
  int getRecordSize();

  /**
   * Gets the file type.
   *
   * @return a not null file type
   * @since 2.0
   */
  FileType getType();

  /**
   * Gets a reference to the access conditions.
   *
   * @return a not empty byte array reference
   * @since 2.0
   */
  byte[] getAccessConditions();

  /**
   * Gets a reference to the keys indexes.
   *
   * @return a not empty byte array reference
   * @since 2.0
   */
  byte[] getKeyIndexes();

  /**
   * Gets the DF status.
   *
   * @return the DF status byte
   * @since 2.0
   */
  byte getDfStatus();

  /**
   * Returns true if EF is a shared file.
   *
   * @return True if the EF is a shared file
   * @since 2.0
   */
  boolean isShared();

  /**
   * Gets the shared reference of a shared file.
   *
   * @return Null if file is not shared
   * @since 2.0
   */
  Short getSharedReference();

  /**
   * The different types of EF.
   *
   * @since 2.0
   */
  enum FileType {
    /**
     * A Linear EF is made of 1 to several records.
     *
     * @since 2.0
     */
    LINEAR,
    /**
     * A Binary EF contains a single continuous sequence of data bytes from byte #0 (first byte) to
     * byte #N−1 (last byte, for a binary file of N bytes).
     *
     * @since 2.0
     */
    BINARY,
    /**
     * A Cyclic EF is made of 1 to several records organized in a cycle, from the most recent
     * (record #1) to the oldest.
     *
     * @since 2.0
     */
    CYCLIC,
    /**
     * A Counters EF is made of a single record containing an ordered sequence of K counters of
     * three bytes each, from counter #1 (bytes at offsets 0, 1 and 2 of the record) to counter #K.
     *
     * @since 2.0
     */
    COUNTERS,
    /**
     * A Simulated Counter EF is a linear file with a single record.<br>
     * Simulated Counter EFs are present for compatibility with the Calypso Revision 2 access to
     * simulated individual counters.
     *
     * @since 2.0
     */
    SIMULATED_COUNTERS
  }
}
