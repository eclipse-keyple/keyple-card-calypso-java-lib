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

import java.util.HashMap;
import java.util.Map;

/**
 * (package-private)<br>
 * Superclass for all SAM command.
 *
 * @since 2.0.0
 */
abstract class AbstractSamCommand extends AbstractApduCommand {

  /**
   * (package-private)<br>
   * Default SAM product type.
   *
   * @since 2.0.0
   */
  static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
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
   * @since 2.0.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * (package-private)<br>
   * Constructor dedicated for the building of referenced Calypso commands
   *
   * @param commandRef a command reference from the Calypso command table.
   * @since 2.0.0
   */
  AbstractSamCommand(CalypsoSamCommand commandRef) {
    super(commandRef);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  CalypsoSamCommand getCommandRef() {
    return (CalypsoSamCommand) super.getCommandRef();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  final CalypsoApduCommandException buildCommandException(
      Class<? extends CalypsoApduCommandException> exceptionClass,
      String message,
      CardCommand commandRef,
      Integer statusWord) {

    CalypsoApduCommandException e;
    CalypsoSamCommand command = (CalypsoSamCommand) commandRef;
    if (exceptionClass == CalypsoSamAccessForbiddenException.class) {
      e = new CalypsoSamAccessForbiddenException(message, command, statusWord);
    } else if (exceptionClass == CalypsoSamCounterOverflowException.class) {
      e = new CalypsoSamCounterOverflowException(message, command, statusWord);
    } else if (exceptionClass == CalypsoSamDataAccessException.class) {
      e = new CalypsoSamDataAccessException(message, command, statusWord);
    } else if (exceptionClass == CalypsoSamIllegalArgumentException.class) {
      e = new CalypsoSamIllegalArgumentException(message, command);
    } else if (exceptionClass == CalypsoSamIllegalParameterException.class) {
      e = new CalypsoSamIllegalParameterException(message, command, statusWord);
    } else if (exceptionClass == CalypsoSamIncorrectInputDataException.class) {
      e = new CalypsoSamIncorrectInputDataException(message, command, statusWord);
    } else if (exceptionClass == CalypsoSamSecurityDataException.class) {
      e = new CalypsoSamSecurityDataException(message, command, statusWord);
    } else {
      e = new CalypsoSamUnknownStatusException(message, command, statusWord);
    }
    return e;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  void checkStatus() throws CalypsoSamCommandException {
    try {
      super.checkStatus();
    } catch (CalypsoApduCommandException e) {
      throw (CalypsoSamCommandException) e;
    }
  }
}
