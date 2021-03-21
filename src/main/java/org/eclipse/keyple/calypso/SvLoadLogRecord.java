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
package org.eclipse.keyple.calypso;

import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * This POJO contains the data of a Stored Value load log.
 *
 * @since 2.0
 */
public class SvLoadLogRecord {
  final int offset;
  final byte[] poResponse;

  /**
   * Constructor
   *
   * @param poResponse the Sv Get or Read Record (SV Debit log file) response data.
   * @param offset the load log offset in the response (may change from a PO to another).
   * @since 2.0
   */
  public SvLoadLogRecord(byte[] poResponse, int offset) {
    this.poResponse = poResponse;
    this.offset = offset;
  }

  /**
   * Gets the load amount value
   *
   * @return An int
   * @since 2.0
   */
  public int getAmount() {
    return ByteArrayUtil.threeBytesSignedToInt(poResponse, offset + 8);
  }

  /**
   * Gets the SV balance value
   *
   * @return An int
   * @since 2.0
   */
  public int getBalance() {
    return ByteArrayUtil.threeBytesSignedToInt(poResponse, offset + 5);
  }

  /**
   * Gets the load time as an int
   *
   * @return An int
   * @since 2.0
   */
  public int getLoadTime() {
    return ByteArrayUtil.twoBytesToInt(getLoadTimeBytes(), 0);
  }

  /**
   * Gets the load time as an array of bytes
   *
   * @return A 2-byte byte array
   * @since 2.0
   */
  public byte[] getLoadTimeBytes() {
    final byte[] time = new byte[2];
    time[0] = poResponse[offset + 11];
    time[1] = poResponse[offset + 12];
    return time;
  }

  /**
   * Gets the load date as an int
   *
   * @return An int
   * @since 2.0
   */
  public int getLoadDate() {
    return ByteArrayUtil.twoBytesToInt(getLoadDateBytes(), 0);
  }

  /**
   * Gets the load date as an array of bytes
   *
   * @return A 2-byte byte array
   * @since 2.0
   */
  public byte[] getLoadDateBytes() {
    final byte[] date = new byte[2];
    date[0] = poResponse[offset + 0];
    date[1] = poResponse[offset + 1];
    return date;
  }

  /**
   * Gets the free bytes as a String
   *
   * @return A 2-character Ascii string
   * @since 2.0
   */
  public String getFreeByte() {
    return new String(getFreeByteBytes());
  }

  /**
   * Gets the free bytes as an array of bytes
   *
   * @return A 2-byte byte array
   * @since 2.0
   */
  public byte[] getFreeByteBytes() {
    final byte[] free = new byte[2];
    free[0] = poResponse[offset + 2];
    free[1] = poResponse[offset + 4];
    return free;
  }

  /**
   * Gets the KVC of the load key (as given in the last SV Reload)
   *
   * @return A byte
   * @since 2.0
   */
  public byte getKvc() {
    return poResponse[offset + 3];
  }

  /**
   * Gets the SAM ID value as a long
   *
   * @return A long
   * @since 2.0
   */
  public long getSamId() {
    return ByteArrayUtil.fourBytesToInt(getSamIdBytes(), 0);
  }

  /**
   * Gets the SAM ID as an array of bytes
   *
   * @return A 4-byte byte array
   * @since 2.0
   */
  public byte[] getSamIdBytes() {
    byte[] samId = new byte[4];
    System.arraycopy(poResponse, offset + 13, samId, 0, 4);
    return samId;
  }

  /**
   * Gets the SV transaction number value as an int
   *
   * @return An int
   * @since 2.0
   */
  public int getSvTNum() {
    return ByteArrayUtil.twoBytesToInt(getSvTNumBytes(), 0);
  }

  /**
   * Gets the SV transaction number as an array of bytes
   *
   * @return A 2-byte byte array
   * @since 2.0
   */
  public byte[] getSvTNumBytes() {
    final byte[] tnNum = new byte[2];
    tnNum[0] = poResponse[offset + 20];
    tnNum[1] = poResponse[offset + 21];
    return tnNum;
  }

  /**
   * Gets the SAM transaction number value as an int
   *
   * @return An int
   * @since 2.0
   */
  public int getSamTNum() {
    return ByteArrayUtil.threeBytesToInt(getSamTNumBytes(), 0);
  }

  /**
   * Gets the SAM transaction number as an array of bytes
   *
   * @return A 3-byte byte array
   * @since 2.0
   */
  public byte[] getSamTNumBytes() {
    byte[] samTNum = new byte[3];
    System.arraycopy(poResponse, offset + 17, samTNum, 0, 3);
    return samTNum;
  }

  /**
   * Gets the SV load log record a JSON formatted string
   *
   * @return A not empty String
   * @since 2.0
   */
  @Override
  public String toString() {
    return "{\"SvLoadLogRecord\":{"
        + "\"amount\":"
        + getAmount()
        + ", \"balance\":"
        + getBalance()
        + ", \"debitDate\":"
        + getLoadDate()
        + ", \"loadTime\":"
        + getLoadDate()
        + ", \"freeBytes\":"
        + ByteArrayUtil.toHex(getFreeByteBytes())
        + ", \"kvc\":"
        + getKvc()
        + ", \"samId\":"
        + ByteArrayUtil.toHex(getSamIdBytes())
        + ", \"svTransactionNumber\":"
        + getSvTNum()
        + ", \"svSamTransactionNumber\":"
        + getSamTNum()
        + "}}";
  }
}
