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
 * Indicates that the security input data provided is not valid.<br>
 * This can occur, for example, during the digest authenticate operation when the card's signature
 * is incorrect.
 *
 * @since 2.0
 */
final class CalypsoSamSecurityDataException extends CalypsoSamCommandException {

  /**
   * (package-private)<br>
   *
   * @param message the message to identify the exception context.
   * @param command the Calypso SAM command.
   * @param statusWord the status word.
   * @since 2.0
   */
  CalypsoSamSecurityDataException(String message, CalypsoSamCommand command, Integer statusWord) {
    super(message, command, statusWord);
  }
}
