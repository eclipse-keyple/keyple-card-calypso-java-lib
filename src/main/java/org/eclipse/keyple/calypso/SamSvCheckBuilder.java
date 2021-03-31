/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://www.calypsonet-asso.org/
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
 * Builds the SV Check APDU command.
 *
 * @since 2.0
 */
final class SamSvCheckBuilder extends AbstractSamCommandBuilder<AbstractSamResponseParser> {
  /** The command reference. */
  private static final SamCommand command = SamCommand.SV_CHECK;

  /**
   * Instantiates a new SamSvCheckBuilder to authenticate a card SV transaction.
   *
   * @param revision of the SAM.
   * @param svPoSignature null if the operation is to abort the SV transaction, a 3 or 6-byte array.
   *     containing the PO signature from SV Debit, SV Load or SV Undebit.
   * @since 2.0
   */
  public SamSvCheckBuilder(SamRevision revision, byte[] svPoSignature) {
    super(command);
    if (svPoSignature != null && (svPoSignature.length != 3 && svPoSignature.length != 6)) {
      throw new IllegalArgumentException("Invalid svPoSignature.");
    }

    if (revision != null) {
      this.defaultRevision = revision;
    }

    byte cla = this.defaultRevision.getClassByte();
    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    if (svPoSignature != null) {
      // the operation is not "abort"
      byte[] data = new byte[svPoSignature.length];
      System.arraycopy(svPoSignature, 0, data, 0, svPoSignature.length);
      setApduRequest(new ApduRequest(cla, command.getInstructionByte(), p1, p2, data, null));
    } else {
      setApduRequest(new ApduRequest(cla, command.getInstructionByte(), p1, p2, null, (byte) 0x00));
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamSvCheckParser createResponseParser(ApduResponse apduResponse) {
    return new SamSvCheckParser(apduResponse, this);
  }
}
