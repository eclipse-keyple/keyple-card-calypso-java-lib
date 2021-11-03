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

/**
 * (package-private)<br>
 * Superclass for all card commands.
 *
 * @since 2.0.1
 */
abstract class AbstractCardCommand extends AbstractApduCommand {

  /**
   * (package-private)<br>
   * Constructor dedicated for the building of referenced Calypso commands
   *
   * @param commandRef a command reference from the Calypso command table.
   * @since 2.0.1
   */
  AbstractCardCommand(CalypsoCardCommand commandRef) {
    super(commandRef);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  CalypsoCardCommand getCommandRef() {
    return (CalypsoCardCommand) super.getCommandRef();
  }

  /**
   * (package-private)<br>
   * Indicates if the session buffer is used when executing this command.
   *
   * <p>Allows the management of the overflow of this buffer.
   *
   * @return True if this command uses the session buffer
   * @since 2.0.1
   */
  abstract boolean isSessionBufferUsed();

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  final CalypsoApduCommandException buildCommandException(
      Class<? extends CalypsoApduCommandException> exceptionClass,
      String message,
      CardCommand commandRef,
      Integer statusWord) {

    CalypsoApduCommandException e;
    CalypsoCardCommand command = (CalypsoCardCommand) commandRef;
    if (exceptionClass == CardAccessForbiddenException.class) {
      e = new CardAccessForbiddenException(message, command, statusWord);
    } else if (exceptionClass == CardDataAccessException.class) {
      e = new CardDataAccessException(message, command, statusWord);
    } else if (exceptionClass == CardDataOutOfBoundsException.class) {
      e = new CardDataOutOfBoundsException(message, command, statusWord);
    } else if (exceptionClass == CardIllegalArgumentException.class) {
      e = new CardIllegalArgumentException(message, command);
    } else if (exceptionClass == CardIllegalParameterException.class) {
      e = new CardIllegalParameterException(message, command, statusWord);
    } else if (exceptionClass == CardPinException.class) {
      e = new CardPinException(message, command, statusWord);
    } else if (exceptionClass == CardSecurityContextException.class) {
      e = new CardSecurityContextException(message, command, statusWord);
    } else if (exceptionClass == CardSecurityDataException.class) {
      e = new CardSecurityDataException(message, command, statusWord);
    } else if (exceptionClass == CardSessionBufferOverflowException.class) {
      e = new CardSessionBufferOverflowException(message, command, statusWord);
    } else if (exceptionClass == CardTerminatedException.class) {
      e = new CardTerminatedException(message, command, statusWord);
    } else {
      e = new CardUnknownStatusException(message, command, statusWord);
    }
    return e;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  AbstractCardCommand setApduResponse(ApduResponseApi apduResponse) {
    return (AbstractCardCommand) super.setApduResponse(apduResponse);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  void checkStatus() throws CardCommandException {
    try {
      super.checkStatus();
    } catch (CalypsoApduCommandException e) {
      throw (CardCommandException) e;
    }
  }
}
