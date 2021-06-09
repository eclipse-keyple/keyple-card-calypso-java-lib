/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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
 * Superclass for all card command parsers.
 *
 * @since 2.0
 */
abstract class AbstractCardResponseParser extends AbstractApduResponseParser {

  /**
   * The generic abstract constructor to build a parser of the APDU response.
   *
   * @param response response to parse.
   * @param builder the reference of the builder that created the parser.
   * @since 2.0
   */
  protected AbstractCardResponseParser(
      ApduResponseApi response, AbstractCardCommandBuilder builder) {
    super(response, builder);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final AbstractCardCommandBuilder<AbstractCardResponseParser> getBuilder() {
    return (AbstractCardCommandBuilder<AbstractCardResponseParser>) super.getBuilder();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  protected final CalypsoApduCommandException buildCommandException(
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
   * @since 2.0
   */
  @Override
  public void checkStatus() throws CardCommandException {
    try {
      super.checkStatus();
    } catch (CalypsoApduCommandException e) {
      throw (CardCommandException) e;
    }
  }
}
