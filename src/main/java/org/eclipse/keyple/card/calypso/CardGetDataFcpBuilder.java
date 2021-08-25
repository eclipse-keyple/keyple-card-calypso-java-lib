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
 * Builds the Get data APDU commands for the FCP tag.
 *
 * <p>This command can not be sent in session because it would generate a 6Cxx status in contact
 * mode and thus make calculation of the digest impossible.
 *
 * @since 2.0.0
 */
final class CardGetDataFcpBuilder extends AbstractCardCommandBuilder<CardGetDataFcpParser> {

  private static final CalypsoCardCommand command = CalypsoCardCommand.GET_DATA;

  /**
   * Instantiates a new CardGetDataFciBuilder.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0.0
   */
  public CardGetDataFcpBuilder(CalypsoCardClass calypsoCardClass) {
    super(command);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(),
                command.getInstructionByte(),
                (byte) 0x00,
                (byte) 0x62,
                null,
                (byte) 0x00)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardGetDataFcpParser createResponseParser(ApduResponseApi apduResponse) {
    return new CardGetDataFcpParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command doesn't modify the contents of the card and therefore doesn't uses the session
   * buffer.
   *
   * @return False
   * @since 2.0.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return false;
  }
}
