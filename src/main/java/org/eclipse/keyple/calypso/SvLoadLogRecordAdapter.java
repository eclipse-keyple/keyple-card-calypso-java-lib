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

import org.eclipse.keyple.calypso.po.SvLoadLogRecord;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Implementation of {@link SvLoadLogRecord}.
 *
 * @since 2.0
 */
class SvLoadLogRecordAdapter implements SvLoadLogRecord {
  final int offset;
  final byte[] poResponse;

  /**
   * Constructor
   *
   * @param poResponse the Sv Get or Read Record (SV Debit log file) response data.
   * @param offset the load log offset in the response (may change from a PO to another).
   * @since 2.0
   */
  public SvLoadLogRecordAdapter(byte[] poResponse, int offset) {
    this.poResponse = poResponse;
    this.offset = offset;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getAmount() {
    return ByteArrayUtil.threeBytesSignedToInt(poResponse, offset + 8);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getBalance() {
    return ByteArrayUtil.threeBytesSignedToInt(poResponse, offset + 5);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getLoadTime() {
    return ByteArrayUtil.twoBytesToInt(getLoadTimeBytes(), 0);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getLoadTimeBytes() {
    final byte[] time = new byte[2];
    time[0] = poResponse[offset + 11];
    time[1] = poResponse[offset + 12];
    return time;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getLoadDate() {
    return ByteArrayUtil.twoBytesToInt(getLoadDateBytes(), 0);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getLoadDateBytes() {
    final byte[] date = new byte[2];
    date[0] = poResponse[offset + 0];
    date[1] = poResponse[offset + 1];
    return date;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public String getFreeByte() {
    return new String(getFreeByteBytes());
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getFreeByteBytes() {
    final byte[] free = new byte[2];
    free[0] = poResponse[offset + 2];
    free[1] = poResponse[offset + 4];
    return free;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte getKvc() {
    return poResponse[offset + 3];
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public long getSamId() {
    return ByteArrayUtil.fourBytesToInt(getSamIdBytes(), 0);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getSamIdBytes() {
    byte[] samId = new byte[4];
    System.arraycopy(poResponse, offset + 13, samId, 0, 4);
    return samId;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getSvTNum() {
    return ByteArrayUtil.twoBytesToInt(getSvTNumBytes(), 0);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getSvTNumBytes() {
    final byte[] tnNum = new byte[2];
    tnNum[0] = poResponse[offset + 20];
    tnNum[1] = poResponse[offset + 21];
    return tnNum;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getSamTNum() {
    return ByteArrayUtil.threeBytesToInt(getSamTNumBytes(), 0);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
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
