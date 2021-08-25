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
 * Builds the SAM Select Diversifier APDU command.
 *
 * @since 2.0.0
 */
final class SamSelectDiversifierBuilder
    extends AbstractSamCommandBuilder<SamSelectDiversifierParser> {

  /** The command. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.SELECT_DIVERSIFIER;

  /**
   * Instantiates a new SamSelectDiversifierBuilder.
   *
   * @param productType the SAM product type.
   * @param diversifier the application serial number.
   * @throws IllegalArgumentException - if the diversifier is null or has a wrong length
   * @since 2.0.0
   */
  public SamSelectDiversifierBuilder(CalypsoSam.ProductType productType, byte[] diversifier) {
    super(command);
    if (productType != null) {
      this.defaultProductType = productType;
    }
    if (diversifier == null || (diversifier.length != 4 && diversifier.length != 8)) {
      throw new IllegalArgumentException("Bad diversifier value!");
    }

    byte cla = SamUtilAdapter.getClassByte(this.defaultProductType);
    byte p1 = 0x00;
    byte p2 = 0x00;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, diversifier, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public SamSelectDiversifierParser createResponseParser(ApduResponseApi apduResponse) {
    return new SamSelectDiversifierParser(apduResponse, this);
  }
}
