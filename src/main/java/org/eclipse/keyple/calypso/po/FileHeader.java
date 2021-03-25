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
package org.eclipse.keyple.calypso.po;

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
   * @return true if the EF is a shared file
   * @since 2.0
   */
  boolean isShared();

  /**
   * Gets the shared reference of a shared file.
   *
   * @return null if file is not shared
   * @since 2.0
   */
  Short getSharedReference();

  /**
   * The EF type enum
   *
   * @since 2.0
   */
  public enum FileType {
    LINEAR,
    BINARY,
    CYCLIC,
    COUNTERS,
    SIMULATED_COUNTERS;
  }
}
