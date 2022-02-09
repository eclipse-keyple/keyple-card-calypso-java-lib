/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the "Verify PIN" command.
 *
 * @since 2.0.1
 */
final class CmdCardVerifyPin extends AbstractCardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardVerifyPin.class);

  private static final CalypsoCardCommand command = CalypsoCardCommand.VERIFY_PIN;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc value not supported (only 00h, 04h or 08h are supported).",
            CardIllegalParameterException.class));
    m.put(0x6900, new StatusProperties("Transaction Counter is 0.", CardTerminatedException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (Get Challenge not done: challenge unavailable).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (a session is open or DF is invalidated).",
            CardAccessForbiddenException.class));
    m.put(
        0x63C1,
        new StatusProperties("Incorrect PIN (1 attempt remaining).", CardPinException.class));
    m.put(
        0x63C2,
        new StatusProperties("Incorrect PIN (2 attempt remaining).", CardPinException.class));
    m.put(
        0x6983,
        new StatusProperties("Presentation rejected (PIN is blocked).", CardPinException.class));
    m.put(
        0x6D00,
        new StatusProperties("PIN function not present.", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final byte cla;
  private final boolean readCounterOnly;

  /**
   * (package-private)<br>
   * Verify the PIN
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param encryptPinTransmission true if the PIN transmission has to be encrypted.
   * @param pin the PIN data. The PIN is always 4-byte long here, even in the case of an encrypted
   *     transmission (@see setCipheredPinData).
   * @since 2.0.1
   */
  CmdCardVerifyPin(CalypsoCardClass calypsoCardClass, boolean encryptPinTransmission, byte[] pin) {

    super(command, 0);

    if (pin == null
        || (!encryptPinTransmission && pin.length != 4)
        || (encryptPinTransmission && pin.length != 8)) {
      throw new IllegalArgumentException("The PIN must be 4 bytes long");
    }

    cla = calypsoCardClass.getValue();

    // CL-PIN-PP1P2.1
    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, pin, null)));

    if (logger.isDebugEnabled()) {
      addSubName(encryptPinTransmission ? "ENCRYPTED" : "PLAIN");
    }

    readCounterOnly = false;
  }

  /**
   * (package-private)<br>
   * Alternate command dedicated to the reading of the wrong presentation counter
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0.1
   */
  CmdCardVerifyPin(CalypsoCardClass calypsoCardClass) {

    super(command, 0);

    cla = calypsoCardClass.getValue();

    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, null, null)));

    if (logger.isDebugEnabled()) {
      addSubName("Read presentation counter");
    }

    readCounterOnly = true;
  }

  /**
   * {@inheritDoc}
   *
   * @return false
   * @since 2.0.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * (package-private)<br>
   * Indicates if the command is used to read the attempt counter only
   *
   * @return True if the command is used to read the attempt counter
   * @since 2.0.1
   */
  boolean isReadCounterOnly() {
    return readCounterOnly;
  }

  /**
   * (package-private)<br>
   * Determine the value of the attempt counter from the status word
   *
   * @return The remaining attempt counter value (0, 1, 2 or 3)
   * @since 2.0.1
   */
  int getRemainingAttemptCounter() {
    int attemptCounter;
    switch (getApduResponse().getStatusWord()) {
      case 0x6983:
        attemptCounter = 0;
        break;
      case 0x63C1:
        attemptCounter = 1;
        break;
      case 0x63C2:
        attemptCounter = 2;
        break;
      case 0x9000:
        attemptCounter = 3;
        break;
      default:
        throw new IllegalStateException(
            "Incorrect status word: " + String.format("%04Xh", getApduResponse().getStatusWord()));
    }
    return attemptCounter;
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
