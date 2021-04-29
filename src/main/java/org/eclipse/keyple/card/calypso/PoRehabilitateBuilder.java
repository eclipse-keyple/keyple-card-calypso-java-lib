/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://www.calypsonet-asso.org/
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

/**
 * (package-private)<br>
 * Builds the Rehabilitate command.
 *
 * @since 2.0
 */
final class PoRehabilitateBuilder extends AbstractPoCommandBuilder<PoRehabilitateParser> {

  private static final PoCommand command = PoCommand.REHABILITATE;

  /**
   * Instantiates a new PoRehabilitateBuilder.
   *
   * @param poClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0
   */
  public PoRehabilitateBuilder(PoClass poClass) {
    super(command);

    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    setApduRequest(
        new ApduRequest(
            ApduUtil.build(poClass.getValue(), command.getInstructionByte(), p1, p2, null, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoRehabilitateParser createResponseParser(ApduResponse apduResponse) {
    return new PoRehabilitateParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command modified the contents of the PO and therefore uses the session buffer.
   *
   * @return true
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return true;
  }
}
