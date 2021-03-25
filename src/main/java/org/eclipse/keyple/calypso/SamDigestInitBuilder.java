/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.calypso;

import org.eclipse.keyple.calypso.sam.SamRevision;
import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * Builds the Digest Init APDU command.
 *
 * @since 2.0
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
   * @param workKeyRecordNumber the work key record number.
   * @param workKeyKif from the AbstractPoOpenSessionBuilder response.
   * @param workKeyKVC from the AbstractPoOpenSessionBuilder response.
   * @param digestData all data out from the AbstractPoOpenSessionBuilder response.
   * @throws IllegalArgumentException - if the work key record number
   * @throws IllegalArgumentException - if the digest data is null
   * @throws IllegalArgumentException - if the request is inconsistent
   * @since 2.0
   */
  public SamDigestInitBuilder(
      SamRevision revision,
      boolean verificationMode,
      boolean confidentialSessionMode,
      byte workKeyRecordNumber,
      byte workKeyKif,
      byte workKeyKVC,
      byte[] digestData) {
    super(command, null);
    if (revision != null) {
      this.defaultRevision = revision;
    }

    if (workKeyRecordNumber == 0x00 && (workKeyKif == 0x00 || workKeyKVC == 0x00)) {
      throw new IllegalArgumentException("Bad key record number, kif or kvc!");
    }
    if (digestData == null) {
      throw new IllegalArgumentException("Digest data is null!");
    }
    byte cla = SamRevision.S1D.equals(this.defaultRevision) ? (byte) 0x94 : (byte) 0x80;
    byte p1 = 0x00;
    if (verificationMode) {
      p1 = (byte) (p1 + 1);
    }
    if (confidentialSessionMode) {
      p1 = (byte) (p1 + 2);
    }

    byte p2 = (byte) 0xFF;
    if (workKeyKif == (byte) 0xFF) {
      p2 = workKeyRecordNumber;
    }

    byte[] dataIn;

    if (p2 == (byte) 0xFF) {
      dataIn = new byte[2 + digestData.length];
      dataIn[0] = workKeyKif;
      dataIn[1] = workKeyKVC;
      System.arraycopy(digestData, 0, dataIn, 2, digestData.length);
    } else {
      dataIn = digestData;
    }

    request = new ApduRequest(cla, command.getInstructionByte(), p1, p2, dataIn, null);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamDigestInitParser createResponseParser(ApduResponse apduResponse) {
    return new SamDigestInitParser(apduResponse, this);
  }
}
