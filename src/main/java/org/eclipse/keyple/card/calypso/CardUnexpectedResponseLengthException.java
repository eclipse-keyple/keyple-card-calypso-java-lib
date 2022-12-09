/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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
 * This exception indicates that the length of the response is not equal to the value of the LE
 * field in the request.
 *
 * @since 2.1.1
 */
final class CardUnexpectedResponseLengthException extends CardCommandException {

  /**
   * Constructor allowing to set a message, the command and the status word.
   *
   * @param message the message to identify the exception context.
   * @param command the card command.
   * @since 2.1.1
   */
  CardUnexpectedResponseLengthException(String message, CardCommandRef command) {
    super(message, command);
  }
}
