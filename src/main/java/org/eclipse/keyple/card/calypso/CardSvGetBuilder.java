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

import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.card.calypso.card.CardRevision;
import org.eclipse.keyple.card.calypso.transaction.CardTransactionService;
import org.eclipse.keyple.core.util.ApduUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the SV Get command.
 *
 * @since 2.0
 */
final class CardSvGetBuilder extends AbstractCardCommandBuilder<CardSvGetParser> {
  private static final Logger logger = LoggerFactory.getLogger(CardSvGetBuilder.class);

  /** The command. */
  private static final CalypsoCardCommand command = CalypsoCardCommand.SV_GET;

  private final CardTransactionService.SvSettings.Operation svOperation;
  private final byte[] header;

  /**
   * Instantiates a new CardSvGetBuilder.
   *
   * @param calypsoCardClass the card class.
   * @param cardRevision the card revision.
   * @param svOperation the desired SV operation.
   * @throws IllegalArgumentException - if the command is inconsistent
   * @since 2.0
   */
  public CardSvGetBuilder(
      CalypsoCardClass calypsoCardClass,
      CardRevision cardRevision,
      CardTransactionService.SvSettings.Operation svOperation) {
    super(command);
    byte cla = calypsoCardClass.getValue();
    byte p1 = cardRevision == CardRevision.REV3_2 ? (byte) 0x01 : (byte) 0x00;
    byte p2 =
        svOperation == CardTransactionService.SvSettings.Operation.RELOAD
            ? (byte) 0x07
            : (byte) 0x09;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, null, (byte) 0x00)));
    if (logger.isDebugEnabled()) {
      this.addSubName(String.format("OPERATION=%s", svOperation.toString()));
    }
    header = new byte[4];
    header[0] = command.getInstructionByte();
    header[1] = p1;
    header[2] = p2;
    header[3] = (byte) 0x00;

    this.svOperation = svOperation;
  }

  /**
   * Gets the request SV operation (used to check the SV command sequence)
   *
   * @return The current SvSettings.Operation enum value
   * @since 2.0
   */
  public CardTransactionService.SvSettings.Operation getSvOperation() {
    return svOperation;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSvGetParser createResponseParser(ApduResponseApi apduResponse) {
    return new CardSvGetParser(header, apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command doesn't modify the contents of the card and therefore doesn't uses the session
   * buffer.
   *
   * @return False
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return false;
  }
}
