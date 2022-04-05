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

import org.calypsonet.terminal.calypso.transaction.SignatureComputationData;

/**
 * (package-private)<br>
 * Implementation of {@link SignatureComputationData}.
 *
 * @since 2.2.0
 */
final class SignatureComputationDataAdapter implements SignatureComputationData {

  private byte[] data;
  private byte kif;
  private byte kvc;
  private int signatureSize = 8;
  private byte[] keyDiversifier;
  private boolean isSamTraceabilityMode;
  private int traceabilityOffset;
  private boolean isPartialSamSerialNumber;
  private boolean isBusyMode = true;
  private byte[] signedData;
  private byte[] signature;

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SignatureComputationData setData(byte[] data, byte kif, byte kvc) {
    this.data = data;
    this.kif = kif;
    this.kvc = kvc;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SignatureComputationData setSignatureSize(int size) {
    this.signatureSize = size;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SignatureComputationData setKeyDiversifier(byte[] diversifier) {
    this.keyDiversifier = diversifier;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SignatureComputationData withSamTraceabilityMode(
      int offset, boolean usePartialSamSerialNumber) {
    this.isSamTraceabilityMode = true;
    this.traceabilityOffset = offset;
    this.isPartialSamSerialNumber = usePartialSamSerialNumber;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SignatureComputationData withoutBusyMode() {
    this.isBusyMode = false;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public byte[] getSignedData() {
    if (signedData == null) {
      throw new IllegalStateException("The command has not yet been processed");
    }
    return signedData;
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
   *
   * @return True if the "SAM traceability" mode is enabled.
   * @since 2.2.0
   */
  boolean isSamTraceabilityMode() {
    return isSamTraceabilityMode;
  }

  /**
   * (package-private)<br>
   *
   * @return The offset associated to the "SAM traceability" mode. It is required to check if the
   *     "SAM traceability" mode is enabled first.
   * @since 2.2.0
   */
  int getTraceabilityOffset() {
    return traceabilityOffset;
  }

  /**
   * (package-private)<br>
   *
   * @return True if it is requested to use the partial SAM serial number with the "SAM
   *     traceability" mode. It is required to check if the "SAM traceability" mode is enabled
   *     first.
   * @since 2.2.0
   */
  boolean isPartialSamSerialNumber() {
    return isPartialSamSerialNumber;
  }

  /**
   * (package-private)<br>
   *
   * @return True if the "Busy" mode is enabled.
   * @since 2.2.0
   */
  boolean isBusyMode() {
    return isBusyMode;
  }

  /**
   * (package-private)<br>
   * Sets the data used for signature computation.
   *
   * @param signedData The signed data.
   * @return The current instance.
   * @since 2.2.0
   */
  SignatureComputationDataAdapter setSignedData(byte[] signedData) {
    this.signedData = signedData;
    return this;
  }

  /**
   * (package-private)<br>
   * Sets the computed signature.
   *
   * @param signature The computed signature.
   * @return The current instance.
   * @since 2.2.0
   */
  SignatureComputationDataAdapter setSignature(byte[] signature) {
    this.signature = signature;
    return this;
  }
}
