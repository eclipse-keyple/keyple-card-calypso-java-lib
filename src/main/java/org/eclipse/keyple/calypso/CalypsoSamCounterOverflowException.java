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
package org.eclipse.keyple.calypso;

/**
 * (package-private)<br>
 * Indicates that an event counter number authorized by the SAM has reached its limit.<br>
 * This may occur, for example, during the digest init operation.
 *
 * @since 2.0
 */
final class CalypsoSamCounterOverflowException extends CalypsoSamCommandException {

  /**
   * (package-private)<br>
   *
   * @param message the message to identify the exception context.
   * @param command the Calypso SAM command.
   * @param statusCode the status code.
   * @since 2.0
   */
  CalypsoSamCounterOverflowException(
      String message, CalypsoSamCommand command, Integer statusCode) {
    super(message, command, statusCode);
  }
}
