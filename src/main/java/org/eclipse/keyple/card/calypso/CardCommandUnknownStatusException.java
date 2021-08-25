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
 * This exception indicates that the status word is not referenced.
 *
 * @since 2.0.0
 */
class CardCommandUnknownStatusException extends CalypsoApduCommandException {

  /**
   * Constructor allowing to set a message, the command and the status word.
   *
   * @param message the message to identify the exception context (Should not be null).
   * @param command the card command (Should not be null).
   * @param statusWord the status word (Should not be null).
   * @since 2.0.0
   */
  public CardCommandUnknownStatusException(
      String message, CardCommand command, Integer statusWord) {
    super(message, command, statusWord);
  }
}
