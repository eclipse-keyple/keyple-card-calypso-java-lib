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
 * Indicates that the input PIN provided is not valid. <br>
 * This can occur during the PIN verification.
 *
 * @since 2.0.0
 */
final class CardPinException extends CardCommandException {

  /**
   * @param message the message to identify the exception context.
   * @param command the Calypso card command.
   * @since 2.0.0
   */
  CardPinException(String message, CardCommandRef command) {
    super(message, command);
  }
}
