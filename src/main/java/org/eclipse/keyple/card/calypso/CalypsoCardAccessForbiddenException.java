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
 * Indicates that the access is forbidden (e.g. Never access mode, DF is invalidated,...).
 *
 * @since 2.0
 */
final class CalypsoCardAccessForbiddenException extends CalypsoCardCommandException {

  /**
   * (package-private)<br>
   *
   * @param message the message to identify the exception context.
   * @param command the Calypso card command.
   * @param statusCode the status code.
   * @since 2.0
   */
  CalypsoCardAccessForbiddenException(
      String message, CalypsoCardCommand command, Integer statusCode) {
    super(message, command, statusCode);
  }
}
