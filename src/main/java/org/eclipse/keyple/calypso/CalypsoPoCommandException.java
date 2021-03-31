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
 * Parent abstract class of all Keyple PO APDU commands exceptions.
 *
 * @since 2.0
 */
abstract class CalypsoPoCommandException extends CalypsoCardCommandException {

  /**
   * @param message the message to identify the exception context.
   * @param command the Calypso PO command.
   * @param statusCode the status code (optional).
   * @since 2.0
   */
  protected CalypsoPoCommandException(String message, PoCommand command, Integer statusCode) {
    super(message, command, statusCode);
  }
}
