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

import static org.eclipse.keyple.card.calypso.DtoAdapters.ApduRequestAdapter;

import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.card.calypso.DtoAdapters.CommandContextDto;
import org.eclipse.keyple.card.calypso.DtoAdapters.TransactionContextDto;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds a "Ratification" command.
 *
 * <p>i.e. the command sent after closing the secure session to handle the ratification mechanism.
 *
 * <p>This particular command is not associated with any parsing since the response to this command
 * is always an error and is never checked.
 *
 * @since 2.3.2
 */
final class CmdCardRatification extends CardCommand {

  /**
   * Constructor.
   *
   * @since 2.3.2
   */
  CmdCardRatification(TransactionContextDto transactionContext, CommandContextDto commandContext) {
    super(CardCommandRef.RATIFICATION, 0, null, transactionContext, commandContext);
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                getTransactionContext().getCard().getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                (byte) 0x00,
                (byte) 0x00,
                null,
                (byte) 0x00)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void finalizeRequest() {
    // NOP
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean isCryptoServiceRequiredToFinalizeRequest() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    try {
      super.setApduResponseAndCheckStatus(apduResponse);
    } catch (CardCommandException e) {
      // NOP: ratification nominal case
    }
  }
}
