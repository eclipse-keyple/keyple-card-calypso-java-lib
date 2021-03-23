/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://www.calypsonet-asso.org/
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

import org.eclipse.keyple.calypso.transaction.PoTransaction;
import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the Verify PIN command.
 *
 * @since 2.0
 */
final class PoVerifyPinBuilder extends AbstractPoCommandBuilder<PoVerifyPinParser> {
  private static final Logger logger = LoggerFactory.getLogger(PoVerifyPinBuilder.class);

  private static final CalypsoPoCommand command = CalypsoPoCommand.VERIFY_PIN;

  private final byte cla;
  private final boolean readCounterOnly;

  /**
   * Verify the PIN
   *
   * @param poClass indicates which CLA byte should be used for the Apdu.
   * @param pinTransmissionMode defines the way the PIN code is transmitted: in clear or encrypted.
   *     form.
   * @param pin the PIN data. The PIN is always 4-byte long here, even in the case of a encrypted.
   *     transmission (@see setCipheredPinData).
   * @since 2.0
   */
  public PoVerifyPinBuilder(
      PoClass poClass, PoTransaction.PinTransmissionMode pinTransmissionMode, byte[] pin) {
    super(command, null);

    if (pin == null
        || (pinTransmissionMode == PoTransaction.PinTransmissionMode.PLAIN && pin.length != 4)
        || (pinTransmissionMode == PoTransaction.PinTransmissionMode.ENCRYPTED
            && pin.length != 8)) {
      throw new IllegalArgumentException("The PIN must be 4 bytes long");
    }

    cla = poClass.getValue();

    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    this.request = new ApduRequest(cla, command.getInstructionByte(), p1, p2, pin, null);
    if (logger.isDebugEnabled()) {
      this.addSubName(pinTransmissionMode.toString());
    }

    readCounterOnly = false;
  }

  /**
   * Alternate builder dedicated to the reading of the wrong presentation counter
   *
   * @param poClass indicates which CLA byte should be used for the Apdu.
   */
  public PoVerifyPinBuilder(PoClass poClass) {
    super(command, null);
    cla = poClass.getValue();

    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    this.request = new ApduRequest(cla, command.getInstructionByte(), p1, p2, null, null);
    if (logger.isDebugEnabled()) {
      this.addSubName("Read presentation counter");
    }

    readCounterOnly = true;
  }
  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoVerifyPinParser createResponseParser(ApduResponse apduResponse) {
    return new PoVerifyPinParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command doesn't modify the contents of the PO and therefore doesn't uses the session
   * buffer.
   *
   * @return false
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * Indicates if the command is used to read the attempt counter only
   *
   * @return true if the command is used to read the attempt counter
   */
  public boolean isReadCounterOnly() {
    return readCounterOnly;
  }
}
