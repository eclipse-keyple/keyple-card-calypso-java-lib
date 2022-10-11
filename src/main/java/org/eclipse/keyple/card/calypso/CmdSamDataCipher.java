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
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the "Data Cipher" SAM command.
 *
 * @since 2.2.0
 */
final class CmdSamDataCipher extends AbstractSamCommand {

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
            "Preconditions not satisfied:\n"
                + "- The SAM is locked.\n"
                + "- Cipher or sign forbidden (DataCipherEnableBit of PAR5 is 0).\n"
                + "- Ciphering or signing mode, and ciphering forbidden (CipherEnableBit of PAR1 is 0).\n"
                + "- Decipher mode, and deciphering forbidden (DecipherDataEnableBit of PAR1 is 0).\n"
                + "- AES key.",
            CalypsoSamAccessForbiddenException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: ciphering key not found.", CalypsoSamDataAccessException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1.", CalypsoSamIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final BasicSignatureComputationDataAdapter signatureComputationData;
  private final BasicSignatureVerificationDataAdapter signatureVerificationData;

  /**
   * (package-private)<br>
   * Builds a new instance based on the provided data.
   *
   * @param productType The SAM product type.
   * @param signatureComputationData The signature computation data (optional).
   * @param signatureVerificationData The signature computation data (optional).
   * @since 2.2.0
   */
  CmdSamDataCipher(
      CalypsoSam.ProductType productType,
      BasicSignatureComputationDataAdapter signatureComputationData,
      BasicSignatureVerificationDataAdapter signatureVerificationData) {

    super(CalypsoSamCommand.DATA_CIPHER, 0);

    this.signatureComputationData = signatureComputationData;
    this.signatureVerificationData = signatureVerificationData;

    final byte cla = SamUtilAdapter.getClassByte(productType);
    final byte inst = getCommandRef().getInstructionByte();
    final byte p1 = (byte) 0x40; // TODO implement the other modes (cipher, decipher)
    final byte p2 = (byte) 0x00;

    final byte[] dataIn;
    if (signatureComputationData != null) {
      dataIn = new byte[2 + signatureComputationData.getData().length];
      dataIn[0] = signatureComputationData.getKif();
      dataIn[1] = signatureComputationData.getKvc();
      System.arraycopy(
          signatureComputationData.getData(),
          0,
          dataIn,
          2,
          signatureComputationData.getData().length);
    } else if (signatureVerificationData != null) {
      dataIn = new byte[2 + signatureVerificationData.getData().length];
      dataIn[0] = signatureVerificationData.getKif();
      dataIn[1] = signatureVerificationData.getKvc();
      System.arraycopy(
          signatureVerificationData.getData(),
          0,
          dataIn,
          2,
          signatureVerificationData.getData().length);
    } else {
      dataIn = null;
    }

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
      if (signatureComputationData != null) {
        signatureComputationData.setSignature(
            Arrays.copyOfRange(
                apduResponse.getDataOut(), 0, signatureComputationData.getSignatureSize()));
      } else if (signatureVerificationData != null) {
        byte[] computedSignature =
            Arrays.copyOfRange(
                apduResponse.getDataOut(), 0, signatureVerificationData.getSignature().length);
        signatureVerificationData.setSignatureValid(
            Arrays.equals(computedSignature, signatureVerificationData.getSignature()));
      }
      if (signatureVerificationData != null && !signatureVerificationData.isSignatureValid()) {
        throw new CalypsoSamSecurityDataException("Incorrect signature.", getCommandRef(), 0);
      }
    }
  }
}
