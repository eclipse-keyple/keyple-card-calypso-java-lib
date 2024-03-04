/* **************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/
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

import org.eclipse.keypop.calypso.card.transaction.*;
import org.eclipse.keypop.card.*;

/**
 * Adapter of {@link SecureTransactionManager}.
 *
 * @param <T> The type of the lowest level child object.
 * @since 3.0.0
 */
abstract class SecureTransactionManagerAdapter<T extends SecureTransactionManager<T>>
    extends TransactionManagerAdapter<T> implements SecureTransactionManager<T> {

  private static final String MSG_SECURE_SESSION_NOT_OPEN = "Secure session not open";
  private static final String MSG_SECURE_SESSION_OPEN = "Secure session open";

  boolean isSecureSessionOpen; // package-private for perf optimization

  /**
   * Builds a new instance.
   *
   * @param cardReader The card reader to be used.
   * @param card The selected card on which to operate the transaction.
   * @since 3.0.0
   */
  SecureTransactionManagerAdapter(ProxyReaderApi cardReader, CalypsoCardAdapter card) {
    super(cardReader, card);
  }

  /**
   * Resets the command context.
   *
   * @since 3.0.0
   */
  abstract void resetCommandContext();

  /**
   * Checks if a secure session is open.
   *
   * @throws IllegalStateException If no secure session is open.
   * @since 3.0.0
   */
  final void checkSecureSession() {
    if (!isSecureSessionOpen) {
      throw new IllegalStateException(MSG_SECURE_SESSION_NOT_OPEN);
    }
  }

  /**
   * Checks if no secure session is open.
   *
   * @throws IllegalStateException If a secure session is open.
   */
  void checkNoSecureSession() {
    if (isSecureSessionOpen) {
      throw new IllegalStateException(MSG_SECURE_SESSION_OPEN);
    }
  }

  /**
   * Clears the info associated with the "pre-open" mode.
   *
   * @since 3.0.0
   */
  final void disablePreOpenMode() {
    card.setPreOpenWriteAccessLevel(null);
    card.setPreOpenDataOut(null);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public final T prepareCancelSecureSession() {
    try {
      commands.add(
          new CommandCloseSecureSession(getTransactionContext(), getCommandContext(), true));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    } finally {
      resetCommandContext();
      disablePreOpenMode();
    }
    return currentInstance;
  }
}
