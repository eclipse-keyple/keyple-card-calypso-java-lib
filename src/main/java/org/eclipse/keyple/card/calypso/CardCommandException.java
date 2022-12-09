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
 * Parent abstract class of all Calypso card APDU commands exceptions.
 *
 * @since 2.0.0
 */
abstract class CardCommandException extends Exception {

  private final CardCommandRef commandRef;

  /**
   * @param message the message to identify the exception context.
   * @param commandRef the Calypso card command.
   * @since 2.0.0
   */
  CardCommandException(String message, CardCommandRef commandRef) {
    super(message);
    this.commandRef = commandRef;
  }

  /**
   * Gets the command
   *
   * @return A not null reference.
   * @since 2.0.0
   */
  CardCommandRef getCommandRef() {
    return commandRef;
  }
}
