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
 * @since 2.0
 */
abstract class CardCommandException extends CalypsoApduCommandException {

  /**
   * @param message the message to identify the exception context.
   * @param command the Calypso card command.
   * @param statusWord the status word (optional).
   * @since 2.0
   */
  protected CardCommandException(String message, CalypsoCardCommand command, Integer statusWord) {
    super(message, command, statusWord);
  }
}
