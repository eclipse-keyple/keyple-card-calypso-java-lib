/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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
 * Indicates that the security conditions are not fulfilled (e.g. busy status).
 *
 * @since 2.2.0
 */
final class SamSecurityContextException extends SamCommandException {

  /**
   * @param message the message to identify the exception context.
   * @since 2.2.0
   */
  SamSecurityContextException(String message) {
    super(message);
  }
}
