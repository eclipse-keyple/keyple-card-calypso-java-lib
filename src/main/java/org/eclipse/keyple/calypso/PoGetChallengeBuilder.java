/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://www.calypsonet-asso.org/
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

import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * (package-private)<br>
 * Builds the Get Challenge APDU command.
 *
 * @since 2.0
 */
final class PoGetChallengeBuilder extends AbstractPoCommandBuilder<PoGetChallengeRespPars> {

  private static final PoCommand command = PoCommand.GET_CHALLENGE;

  /**
   * Instantiates a new PoGetChallengeBuilder.
   *
   * @param poClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0
   */
  public PoGetChallengeBuilder(PoClass poClass) {
    super(command);

    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;
    byte le = (byte) 0x08;

    setApduRequest(
        new ApduRequest(poClass.getValue(), command.getInstructionByte(), p1, p2, null, le));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoGetChallengeRespPars createResponseParser(ApduResponse apduResponse) {
    return new PoGetChallengeRespPars(apduResponse, this);
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
}
