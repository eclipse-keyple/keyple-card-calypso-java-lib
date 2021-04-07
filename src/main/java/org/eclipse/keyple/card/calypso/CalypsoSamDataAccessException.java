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
 * Indicates that the content of the command is incompatible with the SAM's file system (e.g.
 * signing key not found,...).
 *
 * @since 2.0
 */
final class CalypsoSamDataAccessException extends CalypsoSamCommandException {

  /**
   * (package-private)<br>
   *
   * @param message the message to identify the exception context.
   * @param command the Calypso SAM command.
   * @param statusCode the status code.
   * @since 2.0
   */
  CalypsoSamDataAccessException(String message, SamCommand command, Integer statusCode) {
    super(message, command, statusCode);
  }
}
