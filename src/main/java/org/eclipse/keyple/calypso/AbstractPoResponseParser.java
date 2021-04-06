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
package org.eclipse.keyple.calypso;

import org.eclipse.keyple.core.card.ApduResponse;

/**
 * (package-private)<br>
 * Superclass for all PO command parsers.
 *
 * @since 2.0
 */
abstract class AbstractPoResponseParser extends AbstractApduResponseParser {

  /**
   * The generic abstract constructor to build a parser of the APDU response.
   *
   * @param response response to parse.
   * @param builder the reference of the builder that created the parser.
   * @since 2.0
   */
  protected AbstractPoResponseParser(ApduResponse response, AbstractPoCommandBuilder builder) {
    super(response, builder);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final AbstractPoCommandBuilder<AbstractPoResponseParser> getBuilder() {
    return (AbstractPoCommandBuilder<AbstractPoResponseParser>) super.getBuilder();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  protected final CalypsoCardCommandException buildCommandException(
      Class<? extends CalypsoCardCommandException> exceptionClass,
      String message,
      CardCommand commandRef,
      Integer statusCode) {

    CalypsoCardCommandException e;
    PoCommand command = (PoCommand) commandRef;
    if (exceptionClass == CalypsoPoAccessForbiddenException.class) {
      e = new CalypsoPoAccessForbiddenException(message, command, statusCode);
    } else if (exceptionClass == CalypsoPoDataAccessException.class) {
      e = new CalypsoPoDataAccessException(message, command, statusCode);
    } else if (exceptionClass == CalypsoPoDataOutOfBoundsException.class) {
      e = new CalypsoPoDataOutOfBoundsException(message, command, statusCode);
    } else if (exceptionClass == CalypsoPoIllegalArgumentException.class) {
      e = new CalypsoPoIllegalArgumentException(message, command);
    } else if (exceptionClass == CalypsoPoIllegalParameterException.class) {
      e = new CalypsoPoIllegalParameterException(message, command, statusCode);
    } else if (exceptionClass == CalypsoPoPinException.class) {
      e = new CalypsoPoPinException(message, command, statusCode);
    } else if (exceptionClass == CalypsoPoSecurityContextException.class) {
      e = new CalypsoPoSecurityContextException(message, command, statusCode);
    } else if (exceptionClass == CalypsoPoSecurityDataException.class) {
      e = new CalypsoPoSecurityDataException(message, command, statusCode);
    } else if (exceptionClass == CalypsoPoSessionBufferOverflowException.class) {
      e = new CalypsoPoSessionBufferOverflowException(message, command, statusCode);
    } else if (exceptionClass == CalypsoPoTerminatedException.class) {
      e = new CalypsoPoTerminatedException(message, command, statusCode);
    } else {
      e = new CalypsoPoUnknownStatusException(message, command, statusCode);
    }
    return e;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public void checkStatus() throws CalypsoPoCommandException {
    try {
      super.checkStatus();
    } catch (CalypsoCardCommandException e) {
      throw (CalypsoPoCommandException) e;
    }
  }
}
