/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://www.calypsonet-asso.org/
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
    if (exceptionClass == CalypsoCardAccessForbiddenException.class) {
      e = new CalypsoCardAccessForbiddenException(message, command, statusWord);
    } else if (exceptionClass == CalypsoCardDataAccessException.class) {
      e = new CalypsoCardDataAccessException(message, command, statusWord);
    } else if (exceptionClass == CalypsoCardDataOutOfBoundsException.class) {
      e = new CalypsoCardDataOutOfBoundsException(message, command, statusWord);
    } else if (exceptionClass == CalypsoCardIllegalArgumentException.class) {
      e = new CalypsoCardIllegalArgumentException(message, command);
    } else if (exceptionClass == CalypsoCardIllegalParameterException.class) {
      e = new CalypsoCardIllegalParameterException(message, command, statusWord);
    } else if (exceptionClass == CalypsoCardPinException.class) {
      e = new CalypsoCardPinException(message, command, statusWord);
    } else if (exceptionClass == CalypsoCardSecurityContextException.class) {
      e = new CalypsoCardSecurityContextException(message, command, statusWord);
    } else if (exceptionClass == CalypsoCardSecurityDataException.class) {
      e = new CalypsoCardSecurityDataException(message, command, statusWord);
    } else if (exceptionClass == CalypsoCardSessionBufferOverflowException.class) {
      e = new CalypsoCardSessionBufferOverflowException(message, command, statusWord);
    } else if (exceptionClass == CalypsoCardTerminatedException.class) {
      e = new CalypsoCardTerminatedException(message, command, statusWord);
    } else {
      e = new CalypsoCardUnknownStatusException(message, command, statusWord);
    }
    return e;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public void checkStatus() throws CalypsoCardCommandException {
    try {
      super.checkStatus();
    } catch (CalypsoApduCommandException e) {
      throw (CalypsoCardCommandException) e;
    }
  }
}
