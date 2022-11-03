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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Builds the "PSO Compute Signature" SAM command.
 *
 * @since 2.2.0
 */
final class CmdSamPsoComputeSignature extends AbstractSamCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", CalypsoSamCounterOverflowException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied.", CalypsoSamAccessForbiddenException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect value in the incoming data.", CalypsoSamIncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: signing key not found.", CalypsoSamDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("Incorrect P1 or P2.", CalypsoSamIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final TraceableSignatureComputationDataAdapter data;

  /**
   * (package-private)<br>
   * Builds a new instance based on the provided signature computation data.
   *
   * @param calypsoSam The Calypso SAM.
   * @param data The signature computation data.
   * @since 2.2.0
   */
  CmdSamPsoComputeSignature(
      CalypsoSamAdapter calypsoSam, TraceableSignatureComputationDataAdapter data) {

    super(CalypsoSamCommand.PSO_COMPUTE_SIGNATURE, 0, calypsoSam);
    this.data = data;

    final byte cla = SamUtilAdapter.getClassByte(calypsoSam.getProductType());
    final byte inst = getCommandRef().getInstructionByte();
    final byte p1 = (byte) 0x9E;
    final byte p2 = (byte) 0x9A;

    // DataIn
    final int messageOffset = data.isSamTraceabilityMode() ? 6 : 4;
    final int messageSize = data.getData().length;
    final byte[] dataIn = new byte[messageOffset + messageSize];

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
    opMode |= data.getSignatureSize();
    dataIn[3] = opMode;

    // TraceOffset (optional): Bit offset in MessageIn of the SAM traceability data.
    if (data.isSamTraceabilityMode()) {
      ByteArrayUtil.copyBytes(data.getTraceabilityOffset(), dataIn, 4, 2);
    }

    // MessageIn: Message to sign.
    System.arraycopy(data.getData(), 0, dataIn, messageOffset, messageSize);

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
    super.parseApduResponse(apduResponse);
    if (apduResponse.getDataOut().length > 0) {
      if (data.isSamTraceabilityMode()) {
        data.setSignedData(Arrays.copyOf(apduResponse.getDataOut(), data.getData().length));
      } else {
        data.setSignedData(data.getData());
      }
      data.setSignature(
          Arrays.copyOfRange(
              apduResponse.getDataOut(),
              apduResponse.getDataOut().length - data.getSignatureSize(),
              apduResponse.getDataOut().length));
    }
  }
}
