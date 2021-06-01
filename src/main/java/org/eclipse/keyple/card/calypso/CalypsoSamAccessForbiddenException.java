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
 * Indicates that preconditions are not satisfied (e.g. session not active,...).
 *
 * @since 2.0
 */
final class CalypsoSamAccessForbiddenException extends CalypsoSamCommandException {

  /**
   * (package-private)<br>
   *
   * @param message the message to identify the exception context.
   * @param command the Calypso SAM command.
   * @param statusWord the status word.
   * @since 2.0
   */
  CalypsoSamAccessForbiddenException(
      String message, CalypsoSamCommand command, Integer statusWord) {
    super(message, command, statusWord);
  }
}
