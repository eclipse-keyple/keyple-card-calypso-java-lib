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

import org.eclipse.keyple.core.service.selection.spi.CardSelection;

/**
 * PO specific {@link CardSelection} providing means to define commands to execute during the
 * selection phase.
 *
 * @since 2.0
 */
public interface PoCardSelection extends CardSelection {

  /**
   * Adds a command APDU to read a single record from the indicated EF.
   *
   * @param sfi the SFI of the EF to read
   * @param recordNumber the record number to read
   * @throws IllegalArgumentException if one of the provided argument is out of range
   * @since 2.0
   */
  void prepareReadRecordFile(byte sfi, int recordNumber);

  /**
   * Adds a command APDU to select file with an LID provided as a 2-byte byte array.
   *
   * @param lid LID of the EF to select as a byte array
   * @throws IllegalArgumentException if the argument is not an array of 2 bytes
   * @since 2.0
   */
  void prepareSelectFile(byte[] lid);

  /**
   * Adds a command APDU to select file with an LID provided as a short.
   *
   * @param lid A short
   * @since 2.0
   */
  void prepareSelectFile(short lid);

  /**
   * Adds a command APDU to select file according to the provided {@link SelectFileControl} enum
   * entry indicating the navigation case: FIRST, NEXT or CURRENT.
   *
   * @param selectControl A {@link SelectFileControl} enum entry
   * @since 2.0
   */
  void prepareSelectFile(SelectFileControl selectControl);
}
