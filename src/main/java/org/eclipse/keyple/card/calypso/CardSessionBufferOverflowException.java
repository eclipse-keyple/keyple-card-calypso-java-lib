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
 * Indicates during a secure session that the card session buffer will overflow.
 *
 * @since 2.0.0
 */
final class CardSessionBufferOverflowException extends CardCommandException {

  /**
   * @param message the message to identify the exception context.
   * @param command the Calypso card command.
   * @since 2.0.0
   */
  CardSessionBufferOverflowException(String message, CardCommandRef command) {
    super(message, command);
  }
}
