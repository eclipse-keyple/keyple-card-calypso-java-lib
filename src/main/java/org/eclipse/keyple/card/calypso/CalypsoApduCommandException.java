/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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

/**
 * (package-private)<br>
 * This exception is the parent abstract class of all card APDU commands exceptions.
 *
 * @since 2.0.0
 */
abstract class CalypsoApduCommandException extends Exception {

  private final CardCommand command;

  private final Integer statusWord;

  /**
   * (package-private)<br>
   * Constructor allowing to set the error message and the reference to the command
   *
   * @param message the message to identify the exception context (Should not be null).
   * @param command the command.
   * @param statusWord the status word.
   * @since 2.0.0
   */
  CalypsoApduCommandException(String message, CardCommand command, Integer statusWord) {
    super(message);
    this.command = command;
    this.statusWord = statusWord;
  }

  /**
   * (package-private)<br>
   * Gets the command
   *
   * @return A not null reference.
   * @since 2.0.0
   */
  CardCommand getCommand() {
    return command;
  }

  /**
   * (package-private)<br>
   * Gets the status word
   *
   * @return A nullable reference
   * @since 2.0.0
   */
  Integer getStatusWord() {
    return statusWord;
  }
}
