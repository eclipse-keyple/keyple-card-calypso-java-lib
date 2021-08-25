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
 * Indicates that the number of transactions authorized by the card has reached its limit.<br>
 * This may occur, for example, when requesting an open secure session.
 *
 * @since 2.0.0
 */
final class CardTerminatedException extends CardCommandException {

  /**
   * (package-private)<br>
   *
   * @param message the message to identify the exception context.
   * @param command the Calypso card command.
   * @param statusWord the status word.
   * @since 2.0.0
   */
  CardTerminatedException(String message, CalypsoCardCommand command, Integer statusWord) {
    super(message, command, statusWord);
  }
}
