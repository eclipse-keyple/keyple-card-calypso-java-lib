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
 * Builds the SAM Select Diversifier APDU command.
 *
 * @since 2.0
 */
final class SamSelectDiversifierBuilder
    extends AbstractSamCommandBuilder<SamSelectDiversifierParser> {

  /** The command. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.SELECT_DIVERSIFIER;

  /**
   * Instantiates a new SamSelectDiversifierBuilder.
   *
   * @param revision the SAM revision.
   * @param diversifier the application serial number.
   * @throws IllegalArgumentException - if the diversifier is null or has a wrong length
   * @since 2.0
   */
  public SamSelectDiversifierBuilder(SamRevision revision, byte[] diversifier) {
    super(command, null);
    if (revision != null) {
      this.defaultRevision = revision;
    }
    if (diversifier == null || (diversifier.length != 4 && diversifier.length != 8)) {
      throw new IllegalArgumentException("Bad diversifier value!");
    }

    byte cla = this.defaultRevision.getClassByte();
    byte p1 = 0x00;
    byte p2 = 0x00;

    request = new ApduRequest(cla, command.getInstructionByte(), p1, p2, diversifier, null);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamSelectDiversifierParser createResponseParser(ApduResponse apduResponse) {
    return new SamSelectDiversifierParser(apduResponse, this);
  }
}
