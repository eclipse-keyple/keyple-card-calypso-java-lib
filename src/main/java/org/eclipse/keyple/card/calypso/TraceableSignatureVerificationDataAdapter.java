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

import org.calypsonet.terminal.calypso.transaction.TraceableSignatureVerificationData;

/**
 * (package-private)<br>
 * Implementation of {@link TraceableSignatureVerificationData}.
 *
 * @since 2.2.0
 */
final class TraceableSignatureVerificationDataAdapter
    extends CommonSignatureVerificationDataAdapter<TraceableSignatureVerificationData>
    implements TraceableSignatureVerificationData {

  private boolean isSamTraceabilityMode;
  private int traceabilityOffset;
  private boolean isPartialSamSerialNumber;
  private boolean isSamRevocationStatusVerificationRequested;
  private boolean isBusyMode = true;

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public TraceableSignatureVerificationData withSamTraceabilityMode(
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
  public TraceableSignatureVerificationData withoutBusyMode() {
    this.isBusyMode = false;
    return this;
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
}
