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

/**
 * (package-private)<br>
 * Indicates that the data provided by the user induces a capacity overflow in the card.<br>
 * This can occur, for example, for commands that update a counter or the "Stored Value".
 *
 * @since 2.0
 */
final class CalypsoCardDataOutOfBoundsException extends CalypsoCardCommandException {

  /**
   * (package-private)<br>
   *
   * @param message the message to identify the exception context.
   * @param command the Calypso card command.
   * @param statusWord the status word.
   * @since 2.0
   */
  CalypsoCardDataOutOfBoundsException(
      String message, CalypsoCardCommand command, Integer statusWord) {
    super(message, command, statusWord);
  }
}
