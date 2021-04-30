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

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * (package-private) <br>
 * Superclass for all SAM command parsers.
 *
 * @since 2.0
 */
abstract class AbstractSamResponseParser extends AbstractApduResponseParser {

  protected static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6D00,
        new StatusProperties("Instruction unknown.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6E00,
        new StatusProperties("Class not supported.", CalypsoSamIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  protected Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * Constructor to build a parser of the APDU response.
   *
   * @param response response to parse.
   * @param builder the reference of the builder that created the parser.
   */
  protected AbstractSamResponseParser(
      ApduResponse response,
      AbstractSamCommandBuilder<? extends AbstractSamResponseParser> builder) {
    super(response, builder);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final AbstractSamCommandBuilder<AbstractSamResponseParser> getBuilder() {
    return (AbstractSamCommandBuilder<AbstractSamResponseParser>) super.getBuilder();
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
      Integer statusCode) {

    CalypsoApduCommandException e;
    CalypsoSamCommand command = (CalypsoSamCommand) commandRef;
    if (exceptionClass == CalypsoSamAccessForbiddenException.class) {
      e = new CalypsoSamAccessForbiddenException(message, command, statusCode);
    } else if (exceptionClass == CalypsoSamCounterOverflowException.class) {
      e = new CalypsoSamCounterOverflowException(message, command, statusCode);
    } else if (exceptionClass == CalypsoSamDataAccessException.class) {
      e = new CalypsoSamDataAccessException(message, command, statusCode);
    } else if (exceptionClass == CalypsoSamIllegalArgumentException.class) {
      e = new CalypsoSamIllegalArgumentException(message, command);
    } else if (exceptionClass == CalypsoSamIllegalParameterException.class) {
      e = new CalypsoSamIllegalParameterException(message, command, statusCode);
    } else if (exceptionClass == CalypsoSamIncorrectInputDataException.class) {
      e = new CalypsoSamIncorrectInputDataException(message, command, statusCode);
    } else if (exceptionClass == CalypsoSamSecurityDataException.class) {
      e = new CalypsoSamSecurityDataException(message, command, statusCode);
    } else {
      e = new CalypsoSamUnknownStatusException(message, command, statusCode);
    }
    return e;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public void checkStatus() throws CalypsoSamCommandException {
    try {
      super.checkStatus();
    } catch (CalypsoApduCommandException e) {
      throw (CalypsoSamCommandException) e;
    }
  }
}
