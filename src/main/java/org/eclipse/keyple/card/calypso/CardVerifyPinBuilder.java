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

import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Verify PIN command.
 *
 * @since 2.0.0
 */
final class CardVerifyPinBuilder extends AbstractCardCommandBuilder<CardVerifyPinParser> {
  private static final Logger logger = LoggerFactory.getLogger(CardVerifyPinBuilder.class);

  private static final CalypsoCardCommand command = CalypsoCardCommand.VERIFY_PIN;

  private final byte cla;
  private final boolean readCounterOnly;

  /**
   * Verify the PIN
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param encryptPinTransmission true if the PIN transmission has to be encrypted.
   * @param pin the PIN data. The PIN is always 4-byte long here, even in the case of a encrypted.
   *     transmission (@see setCipheredPinData).
   * @since 2.0.0
   */
  public CardVerifyPinBuilder(
      CalypsoCardClass calypsoCardClass, boolean encryptPinTransmission, byte[] pin) {
    super(command);

    if (logger.isDebugEnabled()) {
      this.addSubName(encryptPinTransmission ? "ENCRYPTED" : "PLAIN");
    }

    if (pin == null
        || (!encryptPinTransmission && pin.length != 4)
        || (encryptPinTransmission && pin.length != 8)) {
      throw new IllegalArgumentException("The PIN must be 4 bytes long");
    }

    cla = calypsoCardClass.getValue();

    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, pin, null)));

    readCounterOnly = false;
  }

  /**
   * Alternate builder dedicated to the reading of the wrong presentation counter
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   */
  public CardVerifyPinBuilder(CalypsoCardClass calypsoCardClass) {
    super(command);
    cla = calypsoCardClass.getValue();

    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, null, null)));
    if (logger.isDebugEnabled()) {
      this.addSubName("Read presentation counter");
    }

    readCounterOnly = true;
  }
  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardVerifyPinParser createResponseParser(ApduResponseApi apduResponse) {
    return new CardVerifyPinParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command doesn't modify the contents of the card and therefore doesn't uses the session
   * buffer.
   *
   * @return false
   * @since 2.0.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * Indicates if the command is used to read the attempt counter only
   *
   * @return True if the command is used to read the attempt counter
   */
  public boolean isReadCounterOnly() {
    return readCounterOnly;
  }
}
