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
package org.eclipse.keyple.card.calypso.transaction;

/** Indicates a communication error with the card. */
public class CalypsoCardIOException extends CalypsoCardTransactionException {

  /** @param message the message to identify the exception context */
  public CalypsoCardIOException(String message) {
    super(message);
  }

  /**
   * Encapsulates a lower level exception
   *
   * @param message message to identify the exception context.
   * @param cause the cause.
   */
  public CalypsoCardIOException(String message, Throwable cause) {
    super(message, cause);
  }
}
