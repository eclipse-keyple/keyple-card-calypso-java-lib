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

import org.calypsonet.terminal.calypso.transaction.BasicSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.BasicSignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.SamRevokedException;
import org.calypsonet.terminal.calypso.transaction.TraceableSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.TraceableSignatureVerificationData;

interface LegacySamCardTransactionCryptoExtension extends CardTransactionCryptoExtension {

  /**
   * Schedules the execution of a "Data Cipher" or "PSO Compute Signature" SAM command.
   *
   * <p>Once the command is processed, the result will be available in the provided input/output
   * {@link BasicSignatureComputationData} or {@link TraceableSignatureComputationData} objects.
   *
   * <p>The signature may be used for many purposes, for example:
   *
   * <ul>
   *   <li>To add a signature to data recorded in a contactless card or ticket.<br>
   *       <u>Remark</u>: to speed up processing, it is recommended to use a constant signing key
   *       (which is not diversified before ciphering). Instead, the serial number of the card or
   *       ticket should be inserted at the beginning of the data to sign.
   *   <li>To sign some data reported from a terminal to a central system.<br>
   *       <u>Remark</u>: in this case, the terminal SAM contains a signing work key diversified
   *       with its own serial number, guarantying that the data has indeed been signed by this SAM.
   *       The central system SAM uses the master signing key, diversified before signing with the
   *       diversifier set previously by "Select Diversifier" command.
   * </ul>
   *
   * @param data The input/output data containing the parameters of the command.
   * @return The current instance.
   * @throws IllegalArgumentException If the input data is inconsistent.
   * @see CommonSignatureComputationData
   * @see BasicSignatureComputationData
   * @see TraceableSignatureComputationData
   * @since x.y.z
   */
  LegacySamCardTransactionCryptoExtension prepareComputeSignature(
      CommonSignatureComputationData<?> data);

  /**
   * Schedules the execution of a "Data Cipher" or "PSO Verify Signature" SAM command.
   *
   * <p>Once the command is processed, the result will be available in the provided input/output
   * {@link BasicSignatureVerificationData} or {@link TraceableSignatureVerificationData} objects.
   *
   * @param data The input/output data containing the parameters of the command.
   * @return The current instance.
   * @throws IllegalArgumentException If the input data is inconsistent.
   * @throws SamRevokedException If the signature has been computed in "SAM traceability" mode and
   *     the SAM revocation status check has been requested and the SAM is revoked (for traceable
   *     signature only).
   * @see CommonSignatureVerificationData
   * @see BasicSignatureVerificationData
   * @see TraceableSignatureVerificationData
   * @since x.y.z
   */
  LegacySamCardTransactionCryptoExtension prepareVerifySignature(
      CommonSignatureVerificationData<?> data);
}
