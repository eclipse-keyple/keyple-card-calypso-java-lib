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
 * Parent abstract class of all Calypso card APDU commands exceptions.
 *
 * @since 2.0.0
 */
abstract class CardCommandException extends Exception {

  private final CalypsoCardCommand command;

  private final Integer statusWord;

  /**
   * (package-private)<br>
   *
   * @param message the message to identify the exception context.
   * @param command the Calypso card command.
   * @param statusWord the status word (optional).
   * @since 2.0.0
   */
  CardCommandException(String message, CalypsoCardCommand command, Integer statusWord) {
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
  CalypsoCardCommand getCommand() {
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
