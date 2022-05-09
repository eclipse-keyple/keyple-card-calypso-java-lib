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

import org.calypsonet.terminal.calypso.transaction.TraceableSignatureComputationData;

/**
 * (package-private)<br>
 * Implementation of {@link TraceableSignatureComputationData}.
 *
 * @since 2.2.0
 */
final class TraceableSignatureComputationDataAdapter
    extends CommonSignatureComputationDataAdapter<TraceableSignatureComputationData>
    implements TraceableSignatureComputationData {

  private boolean isSamTraceabilityMode;
  private int traceabilityOffset;
  private boolean isPartialSamSerialNumber;
  private boolean isBusyMode = true;
  private byte[] signedData;

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public TraceableSignatureComputationData withSamTraceabilityMode(
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
  public TraceableSignatureComputationData withoutBusyMode() {
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
   * @since 2.2.0
   */
  void setSignedData(byte[] signedData) {
    this.signedData = signedData;
  }
}
