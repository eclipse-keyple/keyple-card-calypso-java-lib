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

import org.calypsonet.terminal.calypso.transaction.CommonSignatureVerificationData;

/**
 * (package-private)<br>
 * Implementation of {@link CommonSignatureVerificationData}.
 *
 * @param <T> The type of the lowest level child object.
 * @since 2.2.0
 */
abstract class CommonSignatureVerificationDataAdapter<T extends CommonSignatureVerificationData<T>>
    implements CommonSignatureVerificationData<T> {

  private final T currentInstance = (T) this;
  private byte[] data;
  private byte[] signature;
  private byte kif;
  private byte kvc;
  private byte[] keyDiversifier;
  private Boolean isSignatureValid;

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public T setData(byte[] data, byte[] signature, byte kif, byte kvc) {
    this.data = data;
    this.signature = signature;
    this.kif = kif;
    this.kvc = kvc;
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public T setKeyDiversifier(byte[] diversifier) {
    this.keyDiversifier = diversifier;
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public boolean isSignatureValid() {
    if (isSignatureValid == null) {
      throw new IllegalStateException("The command has not yet been processed");
    }
    return isSignatureValid;
  }

  /**
   * (package-private)<br>
   *
   * @return A not empty array of data. It is required to check input data first.
   * @since 2.2.0
   */
  byte[] getData() {
    return data;
  }

  /**
   * (package-private)<br>
   *
   * @return A not empty array of the signature to check. It is required to check input data first.
   * @since 2.2.0
   */
  byte[] getSignature() {
    return signature;
  }

  /**
   * (package-private)<br>
   *
   * @return The KIF. It is required to check input data first.
   * @since 2.2.0
   */
  byte getKif() {
    return kif;
  }

  /**
   * (package-private)<br>
   *
   * @return The KVC. It is required to check input data first.
   * @since 2.2.0
   */
  byte getKvc() {
    return kvc;
  }

  /**
   * (package-private)<br>
   *
   * @return Null if the key diversifier is not set.
   * @since 2.2.0
   */
  byte[] getKeyDiversifier() {
    return keyDiversifier;
  }

  /**
   * (package-private)<br>
   * Sets the signature verification status.
   *
   * @param isSignatureValid True if the signature is valid.
   * @since 2.2.0
   */
  void setSignatureValid(boolean isSignatureValid) {
    this.isSignatureValid = isSignatureValid;
  }
}
