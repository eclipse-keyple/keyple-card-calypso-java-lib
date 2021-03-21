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
 * Indicates that the input PIN provided is not valid. <br>
 * This can occur during the PIN verification.
 *
 * @since 2.0
 */
public final class CalypsoPoPinException extends CalypsoPoCommandException {

  /**
   * @param message the message to identify the exception context.
   * @param command the Calypso PO command.
   * @param statusCode the status code.
   * @since 2.0
   */
  public CalypsoPoPinException(String message, CalypsoPoCommand command, Integer statusCode) {
    super(message, command, statusCode);
  }
}
