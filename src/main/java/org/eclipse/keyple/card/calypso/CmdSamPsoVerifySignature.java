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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the "PSO Verify Signature" SAM command.
 *
 * @since 2.2.0
 */
final class CmdSamPsoVerifySignature extends AbstractSamCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Busy status: the command is temporarily unavailable.",
            CalypsoSamSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied.", CalypsoSamAccessForbiddenException.class));
    m.put(
        0x6988,
        new StatusProperties("Incorrect signature.", CalypsoSamSecurityDataException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect parameters in incoming data.", CalypsoSamIncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: signing key not found.", CalypsoSamDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("Incorrect P1 or P2.", CalypsoSamIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final TraceableSignatureVerificationDataAdapter data;

  /**
   * (package-private)<br>
   * Builds a new instance based on the provided signature verification data.
   *
   * @param productType The SAM product type.
   * @param data The signature verification data.
   * @since 2.2.0
   */
  CmdSamPsoVerifySignature(
      CalypsoSam.ProductType productType, TraceableSignatureVerificationDataAdapter data) {

    super(CalypsoSamCommand.PSO_VERIFY_SIGNATURE, 0);
    this.data = data;

    final byte cla = SamUtilAdapter.getClassByte(productType);
    final byte inst = getCommandRef().getInstructionByte();
    final byte p1 = (byte) 0x00;
    final byte p2 = (byte) 0xA8;

    // DataIn
    final int messageOffset = data.isSamTraceabilityMode() ? 6 : 4;
    final int messageSize = data.getData().length;
    final int signatureSize = data.getSignature().length;
    final byte[] dataIn = new byte[messageOffset + messageSize + signatureSize];

    // SignKeyNum: Selection of the key by KIF and KVC given in the incoming data.
    dataIn[0] = (byte) 0xFF;

    // SignKeyRef: KIF and KVC of the signing key.
    dataIn[1] = data.getKif();
    dataIn[2] = data.getKvc();

    // OpMode: Operating mode, equal to XYh, with:
    // X: Mode
    byte opMode = (byte) 0; // %0000 Normal mode
    if (data.isSamTraceabilityMode()) {
      if (data.isPartialSamSerialNumber()) {
        opMode |= 4; // %x100
      } else {
        opMode |= 6; // %x110
      }
    }
    if (data.isBusyMode()) {
      opMode |= 8; // %1xx0
    }
    opMode <<= 4;
    // Y: Signature size (in bytes)
    opMode |= signatureSize;
    dataIn[3] = opMode;

    // TraceOffset (optional): Bit offset in MessageIn of the SAM traceability data.
    if (data.isSamTraceabilityMode()) {
      dataIn[4] = (byte) (data.getTraceabilityOffset() >> 8);
      dataIn[5] = (byte) data.getTraceabilityOffset();
    }

    // MessageIn: Message to sign.
    System.arraycopy(data.getData(), 0, dataIn, messageOffset, messageSize);

    // Signature
    System.arraycopy(data.getSignature(), 0, dataIn, dataIn.length - signatureSize, signatureSize);

    setApduRequest(new ApduRequestAdapter(ApduUtil.build(cla, inst, p1, p2, dataIn, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  void parseApduResponse(ApduResponseApi apduResponse) throws CalypsoSamCommandException {
    try {
      super.parseApduResponse(apduResponse);
      data.setSignatureValid(true);
    } catch (CalypsoSamSecurityDataException e) {
      data.setSignatureValid(false);
      throw e;
    }
  }
}
