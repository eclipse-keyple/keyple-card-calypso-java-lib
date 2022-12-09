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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the Digest Init APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamDigestInit extends SamCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(SamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", SamIllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", SamCounterOverflowException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied.", SamAccessForbiddenException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P2.", SamIllegalParameterException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: signing key not found.", SamDataAccessException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CmdSamDigestInit.
   *
   * @param calypsoSam The Calypso SAM.
   * @param verificationMode the verification mode.
   * @param confidentialSessionMode the confidential session mode (rev 3.2).
   * @param workKif from the card response.
   * @param workKvc from the card response.
   * @param digestData all data out from the card response.
   * @throws IllegalArgumentException If the KIF or KVC is 0
   * @throws IllegalArgumentException If the digest data is null
   * @throws IllegalArgumentException If the request is inconsistent
   * @since 2.0.1
   */
  CmdSamDigestInit(
      CalypsoSamAdapter calypsoSam,
      boolean verificationMode,
      boolean confidentialSessionMode,
      byte workKif,
      byte workKvc,
      byte[] digestData) {

    super(SamCommandRef.DIGEST_INIT, 0, calypsoSam);

    if (workKif == 0x00 || workKvc == 0x00) {
      throw new IllegalArgumentException("Bad kif or kvc!");
    }
    if (digestData == null) {
      throw new IllegalArgumentException("Digest data is null!");
    }
    byte cla = calypsoSam.getClassByte();
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
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, dataIn, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
