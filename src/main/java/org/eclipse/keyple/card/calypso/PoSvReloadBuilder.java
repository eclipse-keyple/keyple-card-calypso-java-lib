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

import org.eclipse.keyple.card.calypso.po.PoRevision;
import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the SV Reload command.
 *
 * @since 2.0
 */
final class PoSvReloadBuilder extends AbstractPoCommandBuilder<PoSvReloadParser> {

  /** The command. */
  private static final PoCommand command = PoCommand.SV_RELOAD;

  private final PoClass poClass;
  private final PoRevision poRevision;
  /** apdu data array */
  private final byte[] dataIn;

  /**
   * Instantiates a new PoSvReloadBuilder.
   *
   * <p>The process is carried out in two steps: first to check and store the PO and application
   * data, then to create the final APDU with the data from the SAM (see finalizeBuilder).
   *
   * @param poClass the PO class.
   * @param poRevision the PO revision.
   * @param amount amount to debit (signed integer from -8388608 to 8388607).
   * @param kvc debit key KVC (not checked by the PO).
   * @param date debit date (not checked by the PO).
   * @param time debit time (not checked by the PO).
   * @param free 2 free bytes stored in the log but not processed by the PO.
   * @throws IllegalArgumentException - if the command is inconsistent
   * @since 2.0
   */
  public PoSvReloadBuilder(
      PoClass poClass,
      PoRevision poRevision,
      int amount,
      byte kvc,
      byte[] date,
      byte[] time,
      byte[] free) {
    super(command);

    if (amount < -8388608 || amount > 8388607) {
      throw new IllegalArgumentException(
          "Amount is outside allowed boundaries (-8388608 <= amount <=  8388607)");
    }
    if (date == null || time == null || free == null) {
      throw new IllegalArgumentException("date, time and free cannot be null");
    }
    if (date.length != 2 || time.length != 2 || free.length != 2) {
      throw new IllegalArgumentException("date, time and free must be 2-byte arrays");
    }

    // keeps a copy of these fields until the builder is finalized
    this.poRevision = poRevision;
    this.poClass = poClass;

    // handle the dataIn size with signatureHi length according to PO revision (3.2 rev have a
    // 10-byte signature)
    dataIn = new byte[18 + (poRevision == PoRevision.REV3_2 ? 10 : 5)];

    // dataIn[0] will be filled in at the finalization phase.
    dataIn[1] = date[0];
    dataIn[2] = date[1];
    dataIn[3] = free[0];
    dataIn[4] = kvc;
    dataIn[5] = free[1];
    dataIn[6] = (byte) ((amount >> 16) & 0xFF);
    dataIn[7] = (byte) ((amount >> 8) & 0xFF);
    dataIn[8] = (byte) (amount & 0xFF);
    dataIn[9] = time[0];
    dataIn[10] = time[1];
    // dataIn[11]..dataIn[11+7+sigLen] will be filled in at the finalization phase.
  }

  /**
   * Complete the construction of the APDU to be sent to the PO with the elements received from the
   * SAM:
   *
   * <p>4-byte SAM id
   *
   * <p>3-byte challenge
   *
   * <p>3-byte transaction number
   *
   * <p>5 or 10 byte signature (hi part)
   *
   * @param reloadComplementaryData the sam id and the data out from the SvPrepareReload SAM
   *     command.
   * @since 2.0
   */
  public void finalizeBuilder(byte[] reloadComplementaryData) {
    if ((poRevision == PoRevision.REV3_2 && reloadComplementaryData.length != 20)
        || (poRevision != PoRevision.REV3_2 && reloadComplementaryData.length != 15)) {
      throw new IllegalArgumentException("Bad SV prepare load data length.");
    }

    byte p1 = reloadComplementaryData[4];
    byte p2 = reloadComplementaryData[5];

    dataIn[0] = reloadComplementaryData[6];
    System.arraycopy(reloadComplementaryData, 0, dataIn, 11, 4);
    System.arraycopy(reloadComplementaryData, 7, dataIn, 15, 3);
    System.arraycopy(reloadComplementaryData, 10, dataIn, 18, reloadComplementaryData.length - 10);

    setApduRequest(
        new ApduRequest(
            ApduUtil.build(
                poClass.getValue(), command.getInstructionByte(), p1, p2, dataIn, null)));
  }

  /**
   * Gets the SV Reload part of the data to include in the SAM SV Prepare Load command
   *
   * @return a byte array containing the SV reload data
   * @since 2.0
   */
  public byte[] getSvReloadData() {
    byte[] svReloadData = new byte[15];
    svReloadData[0] = command.getInstructionByte();
    // svReloadData[1,2] / P1P2 not set because ignored
    // Lc is 5 bytes longer in revision 3.2
    svReloadData[3] = poRevision == PoRevision.REV3_2 ? (byte) 0x1C : (byte) 0x17;
    // appends the fixed part of dataIn
    System.arraycopy(dataIn, 0, svReloadData, 4, 11);
    return svReloadData;
  }

  /**
   * Create the response parser.
   *
   * <p>A check is made to see if the object has been finalized. If not, an exception {@link
   * IllegalStateException} is thrown.
   *
   * @param apduResponse the response data from the the card.
   * @return a {@link PoSvReloadParser} object
   * @since 2.0
   */
  @Override
  public PoSvReloadParser createResponseParser(ApduResponse apduResponse) {
    return new PoSvReloadParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command modified the contents of the PO and therefore uses the session buffer.
   *
   * @return true
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return true;
  }
}
