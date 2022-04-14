/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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

import org.calypsonet.terminal.calypso.card.SvDebitLogRecord;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;

/**
 * (package-private)<br>
 * Implementation of {@link SvDebitLogRecord}.
 *
 * @since 2.0.0
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
   * @since 2.0.0
   */
  @Override
  public byte[] getRawData() {
    return cardResponse;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public int getAmount() {
    return ByteArrayUtil.extractInt(cardResponse, offset, 2, true);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public int getBalance() {
    return ByteArrayUtil.extractInt(cardResponse, offset + 14, 3, true);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] getDebitTime() {
    final byte[] time = new byte[2];
    time[0] = cardResponse[offset + 4];
    time[1] = cardResponse[offset + 5];
    return time;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] getDebitDate() {
    final byte[] date = new byte[2];
    date[0] = cardResponse[offset + 2];
    date[1] = cardResponse[offset + 3];
    return date;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte getKvc() {
    return cardResponse[offset + 6];
  }
  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] getSamId() {
    byte[] samId = new byte[4];
    System.arraycopy(cardResponse, offset + 7, samId, 0, 4);
    return samId;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public int getSvTNum() {
    final byte[] tnNum = new byte[2];
    tnNum[0] = cardResponse[offset + 17];
    tnNum[1] = cardResponse[offset + 18];
    return ByteArrayUtil.extractInt(tnNum, 0, 2, false);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public int getSamTNum() {
    byte[] samTNum = new byte[3];
    System.arraycopy(cardResponse, offset + 11, samTNum, 0, 3);
    return ByteArrayUtil.extractInt(samTNum, 0, 3, false);
  }

  /**
   * Gets the object content as a Json string.
   *
   * @return A not empty string.
   * @since 2.0.0
   */
  @Override
  public String toString() {
    return "{\"amount\":"
        + getAmount()
        + ", \"balance\":"
        + getBalance()
        + ", \"debitDate\":"
        + HexUtil.toHex(getDebitDate())
        + ", \"debitTime\":"
        + HexUtil.toHex(getDebitDate())
        + ", \"kvc\":"
        + getKvc()
        + ", \"samId\": \""
        + HexUtil.toHex(getSamId())
        + "\", \"svTransactionNumber\":"
        + getSvTNum()
        + ", \"svSamTransactionNumber\":"
        + getSamTNum()
        + "}";
  }
}
