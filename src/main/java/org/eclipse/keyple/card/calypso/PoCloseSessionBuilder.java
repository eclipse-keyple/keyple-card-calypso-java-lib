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
package org.eclipse.keyple.card.calypso;

import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Builds the Close Secure Session APDU command.
 *
 * @since 2.0
 */
final class PoCloseSessionBuilder extends AbstractPoCommandBuilder<PoCloseSessionParser> {

  /** The command. */
  private static final PoCommand command = PoCommand.CLOSE_SESSION;

  /**
   * Instantiates a new PoCloseSessionBuilder depending of the revision of the PO.
   *
   * @param poClass indicates which CLA byte should be used for the Apdu.
   * @param ratificationAsked the ratification asked.
   * @param terminalSessionSignature the sam half session signature.
   * @throws IllegalArgumentException - if the signature is null or has a wrong length
   * @throws IllegalArgumentException - if the command is inconsistent
   * @since 2.0
   */
  public PoCloseSessionBuilder(
      PoClass poClass, boolean ratificationAsked, byte[] terminalSessionSignature) {
    super(command);
    // The optional parameter terminalSessionSignature could contain 4 or 8
    // bytes.
    if (terminalSessionSignature != null
        && terminalSessionSignature.length != 4
        && terminalSessionSignature.length != 8) {
      throw new IllegalArgumentException(
          "Invalid terminal sessionSignature: " + ByteArrayUtil.toHex(terminalSessionSignature));
    }

    byte p1 = ratificationAsked ? (byte) 0x80 : (byte) 0x00;
    /*
     * case 4: this command contains incoming and outgoing data. We define le = 0, the actual
     * length will be processed by the lower layers.
     */
    byte le = 0;

    setApduRequest(
        new ApduRequest(
            ApduUtil.build(
                poClass.getValue(),
                command.getInstructionByte(),
                p1,
                (byte) 0x00,
                terminalSessionSignature,
                le)));
  }

  /**
   * Instantiates a new PoCloseSessionBuilder based on the revision of the PO to generate an abort
   * session command (Close Secure Session with p1 = p2 = lc = 0).
   *
   * @param poClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0
   */
  public PoCloseSessionBuilder(PoClass poClass) {
    super(command);
    setApduRequest(
        new ApduRequest(
            ApduUtil.build(
                poClass.getValue(),
                command.getInstructionByte(),
                (byte) 0x00,
                (byte) 0x00,
                null,
                (byte) 0)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoCloseSessionParser createResponseParser(ApduResponse apduResponse) {
    return new PoCloseSessionParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command can't be executed in session and therefore doesn't uses the session buffer.
   *
   * @return false
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return false;
  }
}
