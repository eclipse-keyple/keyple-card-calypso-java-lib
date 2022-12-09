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
 * Builds the Digest Authenticate APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamDigestAuthenticate extends SamCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(SamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", SamIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied.", SamAccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("Incorrect signature.", SamSecurityDataException.class));
    STATUS_TABLE = m;
  }

  /**
   * Instantiates a new CmdSamDigestAuthenticate .
   *
   * @param calypsoSam The Calypso SAM.
   * @param signature the signature.
   * @throws IllegalArgumentException If the signature is null or has a wrong length.
   * @since 2.0.1
   */
  CmdSamDigestAuthenticate(CalypsoSamAdapter calypsoSam, byte[] signature) {

    super(SamCommandRef.DIGEST_AUTHENTICATE, 0, calypsoSam);

    if (signature == null) {
      throw new IllegalArgumentException("Signature can't be null");
    }
    if (signature.length != 4 && signature.length != 8 && signature.length != 16) {
      throw new IllegalArgumentException(
          "Signature is not the right length : length is " + signature.length);
    }
    byte cla = calypsoSam.getClassByte();
    byte p1 = 0x00;
    byte p2 = (byte) 0x00;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, signature, null)));
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
