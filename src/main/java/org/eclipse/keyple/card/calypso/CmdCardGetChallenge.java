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
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0.1
   */
  CmdCardGetChallenge(CalypsoCardClass calypsoCardClass) {

    super(command);

    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;
    byte le = (byte) 0x08;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(), command.getInstructionByte(), p1, p2, null, le)));
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
   * Gets the card challenge
   *
   * @return An array of bytes
   * @since 2.0.1
   */
  byte[] getCardChallenge() {
    return getApduResponse().getDataOut();
  }
}
