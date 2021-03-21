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
 * This POJO contains the data of a Stored Value debit log.
 *
 * @since 2.0
 */
public class SvDebitLogRecord {
  final int offset;
  final byte[] poResponse;

  /**
   * Constructor
   *
   * @param poResponse the Sv Get or Read Record (SV Load log file) response data.
   * @param offset the debit log offset in the response (may change from a PO to another).
   */
  public SvDebitLogRecord(byte[] poResponse, int offset) {
    this.poResponse = poResponse;
    this.offset = offset;
  }

  /**
   * Gets the debit amount value
   *
   * @return An int
   * @since 2.0
   */
  public int getAmount() {
    return ByteArrayUtil.twoBytesSignedToInt(poResponse, offset);
  }

  /**
   * Gets the SV balance value
   *
   * @return An int
   * @since 2.0
   */
  public int getBalance() {
    return ByteArrayUtil.threeBytesSignedToInt(poResponse, offset + 14);
  }

  /**
   * Gets the debit time as an int
   *
   * @return An int
   * @since 2.0
   */
  public int getDebitTime() {
    return ByteArrayUtil.twoBytesToInt(getDebitTimeBytes(), 0);
  }

  /**
   * Gets the debit time as an array of bytes
   *
   * @return A 2-byte byte array
   * @since 2.0
   */
  public byte[] getDebitTimeBytes() {
    final byte[] time = new byte[2];
    time[0] = poResponse[offset + 4];
    time[1] = poResponse[offset + 5];
    return time;
  }

  /**
   * Gets the debit date as an int
   *
   * @return An int
   * @since 2.0
   */
  public int getDebitDate() {
    return ByteArrayUtil.twoBytesToInt(getDebitDateBytes(), 0);
  }

  /**
   * Gets the debit date as an array of bytes
   *
   * @return A 2-byte byte array
   * @since 2.0
   */
  public byte[] getDebitDateBytes() {
    final byte[] date = new byte[2];
    date[0] = poResponse[offset + 2];
    date[1] = poResponse[offset + 3];
    return date;
  }

  /**
   * Gets the KVC of the load key (as given in the last SV Reload)
   *
   * @return A byte
   * @since 2.0
   */
  public byte getKvc() {
    return poResponse[offset + 6];
  }

  /**
   * Gets the SAM ID as a long
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
    System.arraycopy(poResponse, offset + 7, samId, 0, 4);
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
    tnNum[0] = poResponse[offset + 17];
    tnNum[1] = poResponse[offset + 18];
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
    System.arraycopy(poResponse, offset + 11, samTNum, 0, 3);
    return samTNum;
  }

  /**
   * Gets the SV debit log record a JSON formatted string
   *
   * @return A not empty String
   * @since 2.0
   */
  @Override
  public String toString() {
    return "{\"SvDebitLogRecord\":{"
        + "\"amount\":"
        + getAmount()
        + ", \"balance\":"
        + getBalance()
        + ", \"debitDate\":"
        + getDebitDate()
        + ", \"debitTime\":"
        + getDebitDate()
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
