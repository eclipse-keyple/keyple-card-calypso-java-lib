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

import org.eclipse.keyple.calypso.smartcard.sam.SamRevision;
import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * Builds the Digest Close APDU command.
 *
 * @since 2.0
 */
final class SamDigestCloseBuilder extends AbstractSamCommandBuilder<SamDigestCloseParser> {

  /** The command. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.DIGEST_CLOSE;

  /**
   * Instantiates a new SamDigestCloseBuilder .
   *
   * @param revision of the SAM.
   * @param expectedResponseLength the expected response length.
   * @throws IllegalArgumentException - if the expected response length is wrong.
   * @since 2.0
   */
  public SamDigestCloseBuilder(SamRevision revision, byte expectedResponseLength) {
    super(command, null);
    if (revision != null) {
      this.defaultRevision = revision;
    }
    if (expectedResponseLength != 0x04 && expectedResponseLength != 0x08) {
      throw new IllegalArgumentException(
          String.format("Bad digest length! Expected 4 or 8, got %s", expectedResponseLength));
    }

    byte cla = this.defaultRevision.getClassByte();
    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    request =
        new ApduRequest(cla, command.getInstructionByte(), p1, p2, null, expectedResponseLength);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamDigestCloseParser createResponseParser(ApduResponse apduResponse) {
    return new SamDigestCloseParser(apduResponse, this);
  }
}
