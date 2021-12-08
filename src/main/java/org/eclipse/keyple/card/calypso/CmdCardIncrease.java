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

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Increase APDU command.
 *
 * @since 2.0.1
 */
final class CmdCardIncrease extends AbstractCardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardIncrease.class);

  /** The command. */
  private static final CalypsoCardCommand command = CalypsoCardCommand.INCREASE;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session.", CardSessionBufferOverflowException.class));
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CardIllegalParameterException.class));
    m.put(
        0x6981,
        new StatusProperties(
            "The current EF is not a Counters or Simulated Counter EF.",
            CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (no session, wrong key, encryption required).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, DF is invalidated, etc.)",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Command not allowed (no current EF).", CardDataAccessException.class));
    m.put(0x6A80, new StatusProperties("Overflow error.", CardDataOutOfBoundsException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardDataAccessException.class));
    m.put(
        0x6103, new StatusProperties("Successful execution (possible only in ISO7816 T=0).", null));
    STATUS_TABLE = m;
  }

  /* Construction arguments */
  private final int sfi;
  private final int counterNumber;
  private final int incValue;

  /**
   * (package-private)<br>
   * Instantiates a new increase cmd build from command parameters.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param sfi SFI of the file to select or 00h for current EF.
   * @param counterNumber &gt;= 01h: Counters file, number of the counter. 00h: Simulated Counter.
   *     file.
   * @param incValue Value to add to the counter (defined as a positive int &lt;= 16777215
   *     [FFFFFFh])
   * @throws IllegalArgumentException If the decrement value is out of range
   * @throws IllegalArgumentException If the command is inconsistent
   */
  CmdCardIncrease(CalypsoCardClass calypsoCardClass, byte sfi, int counterNumber, int incValue) {

    super(command);

    byte cla = calypsoCardClass.getValue();
    this.sfi = sfi;
    this.counterNumber = counterNumber;
    this.incValue = incValue;

    // convert the integer value into a 3-byte buffer
    // CL-COUN-DATAIN.1
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
      addSubName(extraInfo);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @return True
   * @since 2.0.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return true;
  }

  /**
   * (package-private)<br>
   *
   * @return The SFI of the accessed file
   * @since 2.0.1
   */
  int getSfi() {
    return sfi;
  }

  /**
   * (package-private)<br>
   *
   * @return The counter number
   * @since 2.0.1
   */
  int getCounterNumber() {
    return counterNumber;
  }

  /**
   * (package-private)<br>
   *
   * @return The increment value
   * @since 2.0.1
   */
  int getIncValue() {
    return incValue;
  }

  /**
   * (package-private)<br>
   * Returns the new counter value as an int between 0
   *
   * @return The new value
   * @since 2.0.1
   */
  int getNewValue() {
    byte[] newValueBuffer = getApduResponse().getDataOut();
    if (newValueBuffer.length == 3) {
      return ByteArrayUtil.threeBytesToInt(newValueBuffer, 0);
    } else {
      throw new IllegalStateException(
          "No counter value available in response to the Increase command.");
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
