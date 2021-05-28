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
package org.eclipse.keyple.card.calypso;

import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.card.calypso.sam.SamRevision;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private) <br>
 * Builds the Give Random APDU command.
 *
 * @since 2.0
 */
final class SamGiveRandomBuilder extends AbstractSamCommandBuilder<SamGiveRandomParser> {

  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.GIVE_RANDOM;

  /**
   * Instantiates a new SamDigestUpdateBuilder.
   *
   * @param revision of the SAM.
   * @param random the random data.
   * @throws IllegalArgumentException - if the random data is null or has a length not equal to 8
   *     TODO implement specific settings for rev less than 3
   * @since 2.0
   */
  public SamGiveRandomBuilder(SamRevision revision, byte[] random) {
    super(command);
    if (revision != null) {
      this.defaultRevision = revision;
    }
    byte cla = this.defaultRevision.getClassByte();
    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    if (random == null || random.length != 8) {
      throw new IllegalArgumentException("Random value should be an 8 bytes long");
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, random, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamGiveRandomParser createResponseParser(ApduResponseApi apduResponse) {
    return new SamGiveRandomParser(apduResponse, this);
  }
}
