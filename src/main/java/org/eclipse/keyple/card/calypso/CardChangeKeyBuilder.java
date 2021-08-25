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
 * Builds the Change key APDU command.
 *
 * @since 2.0.0
 */
final class CardChangeKeyBuilder extends AbstractCardCommandBuilder<CardChangeKeyParser> {
  private static final CalypsoCardCommand command = CalypsoCardCommand.CHANGE_KEY;

  /**
   * Change Key Calypso command
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param keyIndex index of the key of the current DF to change.
   * @param cryptogram key encrypted with Issuer key (key #1).
   * @since 2.0.0
   */
  public CardChangeKeyBuilder(CalypsoCardClass calypsoCardClass, byte keyIndex, byte[] cryptogram) {
    super(command);

    if (cryptogram == null || (cryptogram.length != 0x18 && cryptogram.length != 0x20)) {
      throw new IllegalArgumentException("Bad cryptogram value.");
    }

    byte cla = calypsoCardClass.getValue();
    byte p1 = (byte) 0x00;
    byte p2 = keyIndex;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, cryptogram, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardChangeKeyParser createResponseParser(ApduResponseApi apduResponse) {
    return new CardChangeKeyParser(apduResponse, this);
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
