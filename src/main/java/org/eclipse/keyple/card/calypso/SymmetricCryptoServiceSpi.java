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

import java.util.List;

/**
 * Calypso card symmetric key cryptography service.
 *
 * <p>This interface defines the API needed by a terminal to perform the cryptographic operations
 * required by a Calypso card when using symmetric keys.
 *
 * @since x.y.z
 */
interface SymmetricCryptoServiceSpi {

  boolean isExtendedModeSupported();

  /**
   * @param cardKeyDiversifier The card key diversifier to use for the coming cryptographic
   *     computations.
   * @param useExtendedMode Request the use of the extended mode if supported by the crypto service.
   * @param transactionAuditData The reference of the list where the transaction audit data are
   *     recorded.
   * @return A new instance of {@link SymmetricCryptoTransactionManagerSpi}.
   * @throws IllegalStateException If the extended mode is not supported.
   * @since x.y.z
   */
  SymmetricCryptoTransactionManagerSpi createTransactionManager(
      byte[] cardKeyDiversifier, boolean useExtendedMode, List<byte[]> transactionAuditData);
}
