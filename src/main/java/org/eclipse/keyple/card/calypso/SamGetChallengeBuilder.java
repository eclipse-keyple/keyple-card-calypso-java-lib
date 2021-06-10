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

import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private) <br>
 * Builds the Get Challenge APDU command.
 *
 * @since 2.0
 */
final class SamGetChallengeBuilder extends AbstractSamCommandBuilder<SamGetChallengeParser> {

  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.GET_CHALLENGE;

  /**
   * Instantiates a new SamGetChallengeBuilder.
   *
   * @param revision of the SAM (SAM).
   * @param expectedResponseLength the expected response length.
   * @throws IllegalArgumentException - if the expected response length has wrong value.
   * @since 2.0
   */
  public SamGetChallengeBuilder(CalypsoSam.ProductType revision, byte expectedResponseLength) {
    super(command);
    if (revision != null) {
      this.defaultProductType = revision;
    }
    if (expectedResponseLength != 0x04 && expectedResponseLength != 0x08) {
      throw new IllegalArgumentException(
          String.format("Bad challenge length! Expected 4 or 8, got %s", expectedResponseLength));
    }
    byte cla = SamUtilAdapter.getClassByte(this.defaultProductType);
    byte p1 = 0x00;
    byte p2 = 0x00;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, command.getInstructionByte(), p1, p2, null, expectedResponseLength)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamGetChallengeParser createResponseParser(ApduResponseApi apduResponse) {
    return new SamGetChallengeParser(apduResponse, this);
  }
}
