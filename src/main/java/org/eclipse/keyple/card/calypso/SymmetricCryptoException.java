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
 * Indicates that an error occurred when processing a command.
 *
 * @since 2.3.1
 */
class SymmetricCryptoException extends Exception {

  /**
   * @param message The message to identify the exception context.
   * @since 2.3.1
   */
  public SymmetricCryptoException(String message) {
    super(message);
  }

  /**
   * Encapsulates a lower level exception.
   *
   * @param message Message to identify the exception context.
   * @param cause The cause.
   * @since 2.3.1
   */
  public SymmetricCryptoException(String message, Throwable cause) {
    super(message, cause);
  }
}
