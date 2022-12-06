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
import org.calypsonet.terminal.card.ApduResponseApi;
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
        new HashMap<Integer, StatusProperties>(AbstractCardCommand.STATUS_TABLE);
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
   * @param calypsoCard The Calypso card.
   * @param encryptPinTransmission true if the PIN transmission has to be encrypted.
   * @param pin the PIN data. The PIN is always 4-byte long here, even in the case of an encrypted
   *     transmission (@see setCipheredPinData).
   * @since 2.0.1
   */
  CmdCardVerifyPin(CalypsoCardAdapter calypsoCard, boolean encryptPinTransmission, byte[] pin) {

    super(command, 0, calypsoCard);

    if (pin == null
        || (!encryptPinTransmission && pin.length != 4)
        || (encryptPinTransmission && pin.length != 8)) {
      throw new IllegalArgumentException("The PIN must be 4 bytes long");
    }

    cla = calypsoCard.getCardClass().getValue();

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
   * @param calypsoCard The Calypso card.
   * @since 2.0.1
   */
  CmdCardVerifyPin(CalypsoCardAdapter calypsoCard) {

    super(command, 0, calypsoCard);

    cla = calypsoCard.getCardClass().getValue();

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
   * @since 2.2.3
   */
  @Override
  void parseApduResponse(ApduResponseApi apduResponse) throws CardCommandException {
    try {
      super.parseApduResponse(apduResponse);
      getCalypsoCard().setPinAttemptRemaining(3);
    } catch (CardPinException e) {
      switch (apduResponse.getStatusWord()) {
        case 0x63C2:
          getCalypsoCard().setPinAttemptRemaining(2);
          break;
        case 0x63C1:
          getCalypsoCard().setPinAttemptRemaining(1);
          break;
        case 0x6983:
          getCalypsoCard().setPinAttemptRemaining(0);
          break;
        default: // NOP
      }
      // Forward the exception if the operation do not target the reading of the attempt counter.
      // Catch it silently otherwise
      if (!readCounterOnly) {
        throw e;
      }
    }
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
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
