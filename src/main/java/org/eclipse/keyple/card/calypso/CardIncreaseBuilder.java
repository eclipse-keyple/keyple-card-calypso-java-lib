/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
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

import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Increase APDU command.
 *
 * @since 2.0
 */
final class CardIncreaseBuilder extends AbstractCardCommandBuilder<CardIncreaseParser> {

  private static final Logger logger = LoggerFactory.getLogger(CardIncreaseBuilder.class);

  /** The command. */
  private static final CalypsoCardCommand command = CalypsoCardCommand.INCREASE;

  /* Construction arguments */
  private final int sfi;
  private final int counterNumber;
  private final int incValue;

  /**
   * Instantiates a new increase cmd build from command parameters.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param sfi SFI of the file to select or 00h for current EF.
   * @param counterNumber &gt;= 01h: Counters file, number of the counter. 00h: Simulated Counter.
   *     file.
   * @param incValue Value to add to the counter (defined as a positive int &lt;= 16777215
   *     [FFFFFFh])
   * @throws IllegalArgumentException - if the decrement value is out of range
   * @throws IllegalArgumentException - if the command is inconsistent
   */
  public CardIncreaseBuilder(
      CalypsoCardClass calypsoCardClass, byte sfi, int counterNumber, int incValue) {
    super(command);

    byte cla = calypsoCardClass.getValue();
    this.sfi = sfi;
    this.counterNumber = counterNumber;
    this.incValue = incValue;

    // convert the integer value into a 3-byte buffer
    byte[] incValueBuffer = new byte[3];
    incValueBuffer[0] = (byte) ((incValue >> 16) & 0xFF);
    incValueBuffer[1] = (byte) ((incValue >> 8) & 0xFF);
    incValueBuffer[2] = (byte) (incValue & 0xFF);

    byte p2 = (byte) (sfi * 8);

    /* this is a case4 command, we set Le = 0 */
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla,
                command.getInstructionByte(),
                (byte) counterNumber,
                p2,
                incValueBuffer,
                (byte) 0x00)));

    if (logger.isDebugEnabled()) {
      String extraInfo =
          String.format("SFI:%02X, COUNTER:%d, INCREMENT:%d", sfi, counterNumber, incValue);
      this.addSubName(extraInfo);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardIncreaseParser createResponseParser(ApduResponseApi apduResponse) {
    return new CardIncreaseParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command modified the contents of the card and therefore uses the session buffer.
   *
   * @return True
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return true;
  }

  /** @return The SFI of the accessed file */
  public int getSfi() {
    return sfi;
  }

  /** @return The counter number */
  public int getCounterNumber() {
    return counterNumber;
  }

  /** @return The increment value */
  public int getIncValue() {
    return incValue;
  }
}
