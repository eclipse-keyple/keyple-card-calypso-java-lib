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
 * Indicates that the input user data do not allow to build a syntactically correct command (e.g.
 * SFI too large, record number out of bounds,...).
 *
 * @since 2.0
 */
public final class CalypsoPoIllegalArgumentException extends CalypsoPoCommandException {

  /**
   * @param message the message to identify the exception context.
   * @param command the Calypso PO command.
   * @since 2.0
   */
  public CalypsoPoIllegalArgumentException(String message, CalypsoPoCommand command) {
    super(message, command, null);
  }
}
