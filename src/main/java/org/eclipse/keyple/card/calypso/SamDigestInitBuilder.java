/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
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

import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private) <br>
 * Builds the Digest Init APDU command.
 *
 * @since 2.0.0
 */
final class SamDigestInitBuilder extends AbstractSamCommandBuilder<SamDigestInitParser> {

  /** The command. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.DIGEST_INIT;

  /**
   * Instantiates a new SamDigestInitBuilder.
   *
   * @param revision of the SAM.
   * @param verificationMode the verification mode.
   * @param confidentialSessionMode the confidential session mode (rev 3.2).
   * @param workKif from the AbstractCardOpenSessionBuilder response.
   * @param workKvc from the AbstractCardOpenSessionBuilder response.
   * @param digestData all data out from the AbstractCardOpenSessionBuilder response.
   * @throws IllegalArgumentException - if the work key record number
   * @throws IllegalArgumentException - if the digest data is null
   * @throws IllegalArgumentException - if the request is inconsistent
   * @since 2.0.0
   */
  public SamDigestInitBuilder(
      CalypsoSam.ProductType revision,
      boolean verificationMode,
      boolean confidentialSessionMode,
      byte workKif,
      byte workKvc,
      byte[] digestData) {
    super(command);
    if (revision != null) {
      this.defaultProductType = revision;
    }

    if (workKif == 0x00 || workKvc == 0x00) {
      throw new IllegalArgumentException("Bad key record number, kif or kvc!");
    }
    if (digestData == null) {
      throw new IllegalArgumentException("Digest data is null!");
    }
    byte cla = SamUtilAdapter.getClassByte(defaultProductType);
    byte p1 = 0x00;
    if (verificationMode) {
      p1 = (byte) (p1 + 1);
    }
    if (confidentialSessionMode) {
      p1 = (byte) (p1 + 2);
    }

    byte p2 = (byte) 0xFF;

    byte[] dataIn = new byte[2 + digestData.length];
    dataIn[0] = workKif;
    dataIn[1] = workKvc;
    System.arraycopy(digestData, 0, dataIn, 2, digestData.length);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, dataIn, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public SamDigestInitParser createResponseParser(ApduResponseApi apduResponse) {
    return new SamDigestInitParser(apduResponse, this);
  }
}
