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
package org.eclipse.keyple.card.calypso;

import org.eclipse.keyple.card.calypso.sam.SamRevision;
import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * (package-private) <br>
 * Builds the Digest Update APDU command.
 *
 * @since 2.0 This command have to be sent twice for each command executed during a session. First
 *     time for the command sent and second time for the answer received
 */
final class SamDigestUpdateBuilder extends AbstractSamCommandBuilder<SamDigestUpdateParser> {

  /** The command reference. */
  private static final SamCommand command = SamCommand.DIGEST_UPDATE;

  /**
   * Instantiates a new SamDigestUpdateBuilder.
   *
   * @param revision of the SAM.
   * @param encryptedSession the encrypted session flag, true if encrypted.
   * @param digestData all bytes from command sent by the PO or response from the command.
   * @throws IllegalArgumentException - if the digest data is null or has a length &gt; 255
   * @since 2.0
   */
  public SamDigestUpdateBuilder(SamRevision revision, boolean encryptedSession, byte[] digestData) {
    super(command);
    if (revision != null) {
      this.defaultRevision = revision;
    }
    byte cla = this.defaultRevision.getClassByte();
    byte p1 = (byte) 0x00;
    byte p2 = encryptedSession ? (byte) 0x80 : (byte) 0x00;

    if (digestData == null || digestData.length > 255) {
      throw new IllegalArgumentException("Digest data null or too long!");
    }

    setApduRequest(new ApduRequest(cla, command.getInstructionByte(), p1, p2, digestData, null));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamDigestUpdateParser createResponseParser(ApduResponse apduResponse) {
    return new SamDigestUpdateParser(apduResponse, this);
  }
}
