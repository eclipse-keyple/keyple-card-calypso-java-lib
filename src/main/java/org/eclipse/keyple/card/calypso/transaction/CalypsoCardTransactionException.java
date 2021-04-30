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

/**
 * The exception {@code CalypsoCardTransactionException} is the parent abstract class of all Calypso
 * card transaction functional exceptions.
 */
public abstract class CalypsoCardTransactionException extends RuntimeException {

  /** @param message the message to identify the exception context */
  protected CalypsoCardTransactionException(String message) {
    super(message);
  }

  /**
   * Encapsulates a lower level card transaction exception
   *
   * @param message message to identify the exception context.
   * @param cause the cause.
   */
  protected CalypsoCardTransactionException(String message, Throwable cause) {
    super(message, cause);
  }
}
