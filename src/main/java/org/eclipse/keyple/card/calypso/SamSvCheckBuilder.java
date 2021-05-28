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
package org.eclipse.keyple.card.calypso;

import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.card.calypso.sam.SamRevision;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private) <br>
 * Builds the SV Check APDU command.
 *
 * @since 2.0
 */
final class SamSvCheckBuilder extends AbstractSamCommandBuilder<AbstractSamResponseParser> {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.SV_CHECK;

  /**
   * Instantiates a new SamSvCheckBuilder to authenticate a card SV transaction.
   *
   * @param revision of the SAM.
   * @param svCardSignature null if the operation is to abort the SV transaction, a 3 or 6-byte
   *     array. containing the card signature from SV Debit, SV Load or SV Undebit.
   * @since 2.0
   */
  public SamSvCheckBuilder(SamRevision revision, byte[] svCardSignature) {
    super(command);
    if (svCardSignature != null && (svCardSignature.length != 3 && svCardSignature.length != 6)) {
      throw new IllegalArgumentException("Invalid svCardSignature.");
    }

    if (revision != null) {
      this.defaultRevision = revision;
    }

    byte cla = this.defaultRevision.getClassByte();
    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    if (svCardSignature != null) {
      // the operation is not "abort"
      byte[] data = new byte[svCardSignature.length];
      System.arraycopy(svCardSignature, 0, data, 0, svCardSignature.length);
      setApduRequest(
          new ApduRequestAdapter(
              ApduUtil.build(cla, command.getInstructionByte(), p1, p2, data, null)));
    } else {
      setApduRequest(
          new ApduRequestAdapter(
              ApduUtil.build(cla, command.getInstructionByte(), p1, p2, null, (byte) 0x00)));
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamSvCheckParser createResponseParser(ApduResponseApi apduResponse) {
    return new SamSvCheckParser(apduResponse, this);
  }
}
