/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://www.calypsonet-asso.org/
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
 * (package-private) <br>
 * Builds the Write Key APDU command.
 *
 * @since 2.0
 */
final class SamWriteKeyBuilder extends AbstractSamCommandBuilder<SamWriteKeyParser> {
  /** The command reference. */
  private static final SamCommand command = SamCommand.WRITE_KEY;

  /**
   * Builder constructor
   *
   * @param revision the SAM revision.
   * @param writingMode the writing mode (P1).
   * @param keyReference the key reference (P2).
   * @param keyData the key data.
   * @since 2.0
   */
  public SamWriteKeyBuilder(
      SamRevision revision, byte writingMode, byte keyReference, byte[] keyData) {
    super(command);
    if (revision != null) {
      this.defaultRevision = revision;
    }
    byte cla = this.defaultRevision.getClassByte();

    if (keyData == null) {
      throw new IllegalArgumentException("Key data null!");
    }

    if (keyData.length < 48 || keyData.length > 80) {
      throw new IllegalArgumentException("Key data should be between 40 and 80 bytes long!");
    }

    setApduRequest(
        new ApduRequest(
            cla, command.getInstructionByte(), writingMode, keyReference, keyData, null));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamWriteKeyParser createResponseParser(ApduResponse apduResponse) {
    return new SamWriteKeyParser(apduResponse, this);
  }
}
