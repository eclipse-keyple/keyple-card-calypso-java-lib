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

/**
 * (package-private)<br>
 * Builds the Change PIN APDU command.
 *
 * @since 2.0.0
 */
final class CardChangePinBuilder extends AbstractCardCommandBuilder<CardChangePinParser> {
  private static final CalypsoCardCommand command = CalypsoCardCommand.CHANGE_PIN;

  /**
   * Builds a Calypso Change PIN command
   *
   * @param calypsoCardClass Indicates which CLA byte should be used for the Apdu.
   * @param isNewPinEncrypted True if the new PIN is sent encrypted.
   * @param newPinData The new PIN data either plain or encrypted. @
   * @since 2.0.0
   */
  public CardChangePinBuilder(
      CalypsoCardClass calypsoCardClass, boolean isNewPinEncrypted, byte[] newPinData) {
    super(command);

    if (newPinData == null || (newPinData.length != 0x04 && newPinData.length != 0x10)) {
      throw new IllegalArgumentException("Bad PIN data length.");
    }

    byte cla = calypsoCardClass.getValue();
    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x04;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, newPinData, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardChangePinParser createResponseParser(ApduResponseApi apduResponse) {
    return new CardChangePinParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command can't be executed in session and therefore doesn't uses the session buffer.
   *
   * @return false
   * @since 2.0.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return false;
  }
}
