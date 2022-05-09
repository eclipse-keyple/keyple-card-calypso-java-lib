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

import org.calypsonet.terminal.calypso.transaction.CommonSignatureComputationData;

/**
 * (package-private)<br>
 * Implementation of {@link CommonSignatureComputationData}.
 *
 * @param <T> The type of the lowest level child object.
 * @since 2.2.0
 */
abstract class CommonSignatureComputationDataAdapter<T extends CommonSignatureComputationData<T>>
    implements CommonSignatureComputationData<T> {

  private final T currentInstance = (T) this;
  private byte[] data;
  private byte kif;
  private byte kvc;
  private int signatureSize = 8;
  private byte[] keyDiversifier;
  private byte[] signature;

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public T setData(byte[] data, byte kif, byte kvc) {
    this.data = data;
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
  public T setSignatureSize(int size) {
    this.signatureSize = size;
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
  public byte[] getSignature() {
    if (signature == null) {
      throw new IllegalStateException("The command has not yet been processed");
    }
    return signature;
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
   * @return The signature size.
   * @since 2.2.0
   */
  int getSignatureSize() {
    return signatureSize;
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
   * Sets the computed signature.
   *
   * @param signature The computed signature.
   * @since 2.2.0
   */
  void setSignature(byte[] signature) {
    this.signature = signature;
  }
}
