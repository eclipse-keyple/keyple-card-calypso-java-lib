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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the Digest Update APDU command.
 *
 * @since 2.0.0 This command have to be sent twice for each command executed during a session. First
 *     time for the command sent and second time for the answer received
 */
final class CmdSamDigestUpdate extends AbstractSamCommand {

  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.DIGEST_UPDATE;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied.", CalypsoSamAccessForbiddenException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect value in the incoming data: session in Rev.3.2 mode with encryption/decryption active and not enough data (less than 5 bytes for and odd occurrence or less than 2 bytes for an even occurrence).",
            CalypsoSamIncorrectInputDataException.class));
    m.put(
        0x6B00,
        new StatusProperties("Incorrect P1 or P2.", CalypsoSamIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdSamDigestUpdate.
   *
   * @param productType of the SAM.
   * @param encryptedSession the encrypted session flag, true if encrypted.
   * @param digestData all bytes from command sent by the card or response from the command.
   * @throws IllegalArgumentException - if the digest data is null or has a length &gt; 255
   * @since 2.0.0
   */
  CmdSamDigestUpdate(
      CalypsoSam.ProductType productType, boolean encryptedSession, byte[] digestData) {
    super(command);

    byte cla = SamUtilAdapter.getClassByte(productType);
    byte p1 = (byte) 0x00;
    byte p2 = encryptedSession ? (byte) 0x80 : (byte) 0x00;

    if (digestData == null || digestData.length > 255) {
      throw new IllegalArgumentException("Digest data null or too long!");
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, digestData, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
