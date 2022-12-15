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

import static org.eclipse.keyple.card.calypso.DtoAdapters.ApduRequestAdapter;

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the Digest Internal Authenticate APDU command.
 *
 * <p>This outgoing command generates the signature to send to the card in a Manage Secure Session
 * command during a secure session in Extended Mode.
 *
 * @since 2.3.1
 */
final class CmdSamDigestInternalAuthenticate extends SamCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(SamCommand.STATUS_TABLE);
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied:\n"
                + "- Session not in “ongoing” state.\n"
                + "- Session not opened in Extended mode.\n"
                + "- Session opened in Verification mode.\n"
                + "- Authentication not allowed by the key (not an AES key).\n"
                + "- 250th occurrence since session start.",
            SamAccessForbiddenException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1.", SamIllegalParameterException.class));

    STATUS_TABLE = m;
  }

  private byte[] terminalSignature;

  /**
   * Instantiates a new CmdSamDigestInternalAuthenticate.
   *
   * @param calypsoSam The Calypso SAM.
   * @since 2.3.1
   */
  CmdSamDigestInternalAuthenticate(CalypsoSamAdapter calypsoSam) {

    super(SamCommandRef.DIGEST_INTERNAL_AUTHENTICATE, 8, calypsoSam);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoSam.getClassByte(),
                getCommandRef().getInstructionByte(),
                (byte) 0x80,
                (byte) 0x00,
                null,
                (byte) 8)));
  }

  /**
   * Gets the terminal signature.
   *
   * @return An 8-byte byte array.
   * @since 2.3.1
   */
  byte[] getTerminalSignature() {
    return terminalSignature;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  void parseApduResponse(ApduResponseApi apduResponse) throws SamCommandException {
    super.parseApduResponse(apduResponse);
    terminalSignature = apduResponse.getDataOut();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
