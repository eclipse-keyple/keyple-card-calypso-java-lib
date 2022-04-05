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

import org.calypsonet.terminal.calypso.transaction.SignatureVerificationData;

/**
 * (package-private)<br>
 * Implementation of {@link SignatureVerificationData}.
 *
 * @since 2.2.0
 */
final class SignatureVerificationDataAdapter implements SignatureVerificationData {

  private byte[] data;
  private byte[] signature;
  private byte kif;
  private byte kvc;
  private byte[] keyDiversifier;
  private boolean isSamTraceabilityMode;
  private int traceabilityOffset;
  private boolean isPartialSamSerialNumber;
  private boolean isSamRevocationStatusVerificationRequested;
  private boolean isBusyMode = true;
  private Boolean isSignatureValid;

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SignatureVerificationData setData(byte[] data, byte[] signature, byte kif, byte kvc) {
    this.data = data;
    this.signature = signature;
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
  public SignatureVerificationData setKeyDiversifier(byte[] diversifier) {
    this.keyDiversifier = diversifier;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SignatureVerificationData withSamTraceabilityMode(
      int offset, boolean isPartialSamSerialNumber, boolean checkSamRevocationStatus) {
    this.isSamTraceabilityMode = true;
    this.traceabilityOffset = offset;
    this.isPartialSamSerialNumber = isPartialSamSerialNumber;
    this.isSamRevocationStatusVerificationRequested = checkSamRevocationStatus;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SignatureVerificationData withoutBusyMode() {
    this.isBusyMode = false;
    return this;
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
   * @return True if the verification of the SAM revocation status is requested. It is required to
   *     check if the "SAM traceability" mode is enabled first.
   * @since 2.2.0
   */
  boolean isSamRevocationStatusVerificationRequested() {
    return isSamRevocationStatusVerificationRequested;
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
   * Sets the signature verification status.
   *
   * @param isSignatureValid True if the signature is valid.
   * @since 2.2.0
   */
  void setSignatureValid(boolean isSignatureValid) {
    this.isSignatureValid = isSignatureValid;
  }
}
