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
package org.eclipse.keyple.calypso.transaction;

/**
 * Indicates that the PO has refused the secure session closing.<br>
 * This is usually due to an incorrect SAM signature, or that the secure session has been altered by
 * other APDU commands that would have interfered with it.<br>
 * In this case, the PO has rollbacked the data set by cancelling all updates except for PIN
 * verification attempts.
 */
public class CalypsoPoCloseSecureSessionException extends CalypsoPoTransactionException {

  /**
   * @param message message to identify the exception context.
   * @param cause the cause.
   */
  public CalypsoPoCloseSecureSessionException(String message, Exception cause) {
    super(message, cause);
  }
}
