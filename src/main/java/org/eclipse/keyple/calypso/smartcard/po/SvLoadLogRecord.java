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
package org.eclipse.keyple.calypso.smartcard.po;

/**
 * This POJO contains the data of a Stored Value load log.
 *
 * @since 2.0
 */
public interface SvLoadLogRecord {
  /**
   * Gets the load amount value
   *
   * @return An int
   * @since 2.0
   */
  int getAmount();

  /**
   * Gets the SV balance value
   *
   * @return An int
   * @since 2.0
   */
  int getBalance();

  /**
   * Gets the load time as an int
   *
   * @return An int
   * @since 2.0
   */
  int getLoadTime();

  /**
   * Gets the load time as an array of bytes
   *
   * @return A 2-byte byte array
   * @since 2.0
   */
  byte[] getLoadTimeBytes();

  /**
   * Gets the load date as an int
   *
   * @return An int
   * @since 2.0
   */
  int getLoadDate();

  /**
   * Gets the load date as an array of bytes
   *
   * @return A 2-byte byte array
   * @since 2.0
   */
  byte[] getLoadDateBytes();

  /**
   * Gets the free bytes as a String
   *
   * @return A 2-character Ascii string
   * @since 2.0
   */
  String getFreeByte();

  /**
   * Gets the free bytes as an array of bytes
   *
   * @return A 2-byte byte array
   * @since 2.0
   */
  byte[] getFreeByteBytes();

  /**
   * Gets the KVC of the load key (as given in the last SV Reload)
   *
   * @return A byte
   * @since 2.0
   */
  byte getKvc();

  /**
   * Gets the SAM ID value as a long
   *
   * @return A long
   * @since 2.0
   */
  long getSamId();

  /**
   * Gets the SAM ID as an array of bytes
   *
   * @return A 4-byte byte array
   * @since 2.0
   */
  byte[] getSamIdBytes();

  /**
   * Gets the SV transaction number value as an int
   *
   * @return An int
   * @since 2.0
   */
  int getSvTNum();

  /**
   * Gets the SV transaction number as an array of bytes
   *
   * @return A 2-byte byte array
   * @since 2.0
   */
  byte[] getSvTNumBytes();

  /**
   * Gets the SAM transaction number value as an int
   *
   * @return An int
   * @since 2.0
   */
  int getSamTNum();

  /**
   * Gets the SAM transaction number as an array of bytes
   *
   * @return A 3-byte byte array
   * @since 2.0
   */
  byte[] getSamTNumBytes();
}
