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

/**
 * (package-private)<br>
 * Builds the Get Challenge APDU command.
 *
 * @since 2.0.1
 */
final class CmdCardGetChallenge extends AbstractCardCommand {

  private static final CalypsoCardCommand command = CalypsoCardCommand.GET_CHALLENGE;

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardGetChallenge.
   *
   * @param calypsoCard The Calypso card.
   * @since 2.0.1
   */
  CmdCardGetChallenge(CalypsoCardAdapter calypsoCard) {

    super(command, 0x08, calypsoCard);

    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;
    byte le = (byte) 0x08;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCard.getCardClass().getValue(),
                command.getInstructionByte(),
                p1,
                p2,
                null,
                le)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  void parseApduResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.parseApduResponse(apduResponse);
    getCalypsoCard().setCardChallenge(getApduResponse().getDataOut());
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
}
