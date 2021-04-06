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

import org.eclipse.keyple.calypso.po.PoRevision;
import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Open Session command for a PO revision 3.2.
 *
 * @since 2.0
 */
final class PoOpenSession32Builder
    extends AbstractPoOpenSessionBuilder<AbstractPoOpenSessionParser> {

  private static final Logger logger = LoggerFactory.getLogger(PoOpenSession32Builder.class);

  // Construction arguments used for parsing
  private final int sfi;
  private final int recordNumber;

  /**
   * Instantiates a new AbstractPoOpenSessionBuilder.
   *
   * @param keyIndex the key index.
   * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
   * @param sfi the sfi to select.
   * @param recordNumber the record number to read.
   * @throws IllegalArgumentException - if the request is inconsistent
   * @since 2.0
   */
  public PoOpenSession32Builder(byte keyIndex, byte[] samChallenge, int sfi, int recordNumber) {
    super(PoRevision.REV3_2);

    this.sfi = sfi;
    this.recordNumber = recordNumber;

    byte p1 = (byte) ((recordNumber * 8) + keyIndex);
    byte p2 = (byte) ((sfi * 8) + 2);
    /*
     * case 4: this command contains incoming and outgoing data. We define le = 0, the actual
     * length will be processed by the lower layers.
     */
    byte le = 0;

    byte[] dataIn = new byte[samChallenge.length + 1];
    dataIn[0] = (byte) 0x00;
    System.arraycopy(samChallenge, 0, dataIn, 1, samChallenge.length);

    setApduRequest(
        new ApduRequest(
            PoClass.ISO.getValue(),
            PoCommand.getOpenSessionForRev(PoRevision.REV3_2).getInstructionByte(),
            p1,
            p2,
            dataIn,
            le));

    if (logger.isDebugEnabled()) {
      String extraInfo =
          String.format("KEYINDEX=%d, SFI=%02X, REC=%d", keyIndex, sfi, recordNumber);
      this.addSubName(extraInfo);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoOpenSession32Parser createResponseParser(ApduResponse apduResponse) {
    return new PoOpenSession32Parser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command can't be executed in session and therefore doesn't uses the session buffer.
   *
   * @return false
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getSfi() {
    return sfi;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getRecordNumber() {
    return recordNumber;
  }
}
