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
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private) <br>
 * Builds the SAM Digest Update Multiple APDU command.
 *
 * @since 2.0
 */
final class SamDigestUpdateMultipleBuilder
    extends AbstractSamCommandBuilder<SamDigestUpdateMultipleParser> {

  /** The command. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.DIGEST_UPDATE_MULTIPLE;

  /**
   * Instantiates a new SamDigestUpdateMultipleBuilder.
   *
   * @param revision the revision.
   * @param encryptedSession the encrypted session flag, true if encrypted.
   * @param digestData the digest data.
   * @since 2.0
   */
  public SamDigestUpdateMultipleBuilder(
      SamRevision revision, boolean encryptedSession, byte[] digestData) {
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

    setApduRequest(
        new ApduRequest(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, digestData, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamDigestUpdateMultipleParser createResponseParser(ApduResponse apduResponse) {
    return new SamDigestUpdateMultipleParser(apduResponse, this);
  }
}
