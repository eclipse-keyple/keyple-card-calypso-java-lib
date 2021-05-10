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
package org.eclipse.keyple.card.calypso;

import org.eclipse.keyple.card.calypso.card.SvDebitLogRecord;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Implementation of {@link SvDebitLogRecord}.
 *
 * @since 2.0
 */
class SvDebitLogRecordAdapter implements SvDebitLogRecord {
  final int offset;
  final byte[] cardResponse;

  /**
   * Constructor
   *
   * @param cardResponse the Sv Get or Read Record (SV Load log file) response data.
   * @param offset the debit log offset in the response (may change from a card to another).
   */
  public SvDebitLogRecordAdapter(byte[] cardResponse, int offset) {
    this.cardResponse = cardResponse;
    this.offset = offset;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getAmount() {
    return ByteArrayUtil.twoBytesSignedToInt(cardResponse, offset);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getBalance() {
    return ByteArrayUtil.threeBytesSignedToInt(cardResponse, offset + 14);
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
    time[0] = cardResponse[offset + 4];
    time[1] = cardResponse[offset + 5];
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
    date[0] = cardResponse[offset + 2];
    date[1] = cardResponse[offset + 3];
    return date;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte getKvc() {
    return cardResponse[offset + 6];
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
    System.arraycopy(cardResponse, offset + 7, samId, 0, 4);
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
    tnNum[0] = cardResponse[offset + 17];
    tnNum[1] = cardResponse[offset + 18];
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
    System.arraycopy(cardResponse, offset + 11, samTNum, 0, 3);
    return samTNum;
  }

  /**
   * Gets the object content as a Json string.
   *
   * @return A not empty string.
   * @since 2.0
   */
  @Override
  public String toString() {
    return "{\"amount\":"
        + getAmount()
        + ", \"balance\":"
        + getBalance()
        + ", \"debitDate\":"
        + getDebitDate()
        + ", \"debitTime\":"
        + getDebitDate()
        + ", \"kvc\":"
        + getKvc()
        + ", \"samId\": \""
        + ByteArrayUtil.toHex(getSamIdBytes())
        + "\", \"svTransactionNumber\":"
        + getSvTNum()
        + ", \"svSamTransactionNumber\":"
        + getSamTNum()
        + "}";
  }
}
