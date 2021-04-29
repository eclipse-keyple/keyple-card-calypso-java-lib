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
 * Indicates an inconsistency in the card data.<br>
 * This can occur, for example, if data read in session is different from data read outside the
 * session.
 */
public class CalypsoInconsistencyDataException extends CalypsoCardTransactionException {

  /** @param message the message to identify the exception context */
  public CalypsoInconsistencyDataException(String message) {
    super(message);
  }
}
