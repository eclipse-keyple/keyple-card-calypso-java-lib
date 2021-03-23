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

import org.eclipse.keyple.calypso.smartcard.po.SvDebitLogRecord;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Implementation of {@link SvDebitLogRecord}.
 *
 * @since 2.0
 */
class SvDebitLogRecordAdapter implements SvDebitLogRecord {
  final int offset;
  final byte[] poResponse;

  /**
   * Constructor
   *
   * @param poResponse the Sv Get or Read Record (SV Load log file) response data.
   * @param offset the debit log offset in the response (may change from a PO to another).
   */
  public SvDebitLogRecordAdapter(byte[] poResponse, int offset) {
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
    return ByteArrayUtil.twoBytesSignedToInt(poResponse, offset);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getBalance() {
    return ByteArrayUtil.threeBytesSignedToInt(poResponse, offset + 14);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getDebitTime() {
    return ByteArrayUtil.twoBytesToInt(getDebitTimeBytes(), 0);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getDebitTimeBytes() {
    final byte[] time = new byte[2];
    time[0] = poResponse[offset + 4];
    time[1] = poResponse[offset + 5];
    return time;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getDebitDate() {
    return ByteArrayUtil.twoBytesToInt(getDebitDateBytes(), 0);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getDebitDateBytes() {
    final byte[] date = new byte[2];
    date[0] = poResponse[offset + 2];
    date[1] = poResponse[offset + 3];
    return date;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte getKvc() {
    return poResponse[offset + 6];
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
    System.arraycopy(poResponse, offset + 7, samId, 0, 4);
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
    tnNum[0] = poResponse[offset + 17];
    tnNum[1] = poResponse[offset + 18];
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
