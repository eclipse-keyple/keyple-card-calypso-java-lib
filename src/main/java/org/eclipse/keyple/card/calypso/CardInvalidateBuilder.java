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

import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the Invalidate command.
 *
 * @since 2.0.0
 */
final class CardInvalidateBuilder extends AbstractCardCommandBuilder<CardInvalidateParser> {

  private static final CalypsoCardCommand command = CalypsoCardCommand.INVALIDATE;

  /**
   * Instantiates a new CardInvalidateBuilder.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0.0
   */
  public CardInvalidateBuilder(CalypsoCardClass calypsoCardClass) {
    super(command);

    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(), command.getInstructionByte(), p1, p2, null, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardInvalidateParser createResponseParser(ApduResponseApi apduResponse) {
    return new CardInvalidateParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command modified the contents of the card and therefore uses the session buffer.
   *
   * @return True
   * @since 2.0.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return true;
  }
}
