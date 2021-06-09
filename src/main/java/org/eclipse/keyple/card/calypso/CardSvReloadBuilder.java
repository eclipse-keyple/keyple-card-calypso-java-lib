/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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

import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the SV Reload command.
 *
 * @since 2.0
 */
final class CardSvReloadBuilder extends AbstractCardCommandBuilder<CardSvReloadParser> {

  /** The command. */
  private static final CalypsoCardCommand command = CalypsoCardCommand.SV_RELOAD;

  private final CalypsoCard calypsoCard;
  /** apdu data array */
  private final byte[] dataIn;

  /**
   * Instantiates a new CardSvReloadBuilder.
   *
   * <p>The process is carried out in two steps: first to check and store the card and application
   * data, then to create the final APDU with the data from the SAM (see finalizeBuilder).
   *
   * @param calypsoCard the Calypso card.
   * @param amount amount to debit (signed integer from -8388608 to 8388607).
   * @param kvc debit key KVC (not checked by the card).
   * @param date debit date (not checked by the card).
   * @param time debit time (not checked by the card).
   * @param free 2 free bytes stored in the log but not processed by the card.
   * @throws IllegalArgumentException - if the command is inconsistent
   * @since 2.0
   */
  public CardSvReloadBuilder(
      CalypsoCard calypsoCard, int amount, byte kvc, byte[] date, byte[] time, byte[] free) {
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
    this.calypsoCard = calypsoCard;

    // handle the dataIn size with signatureHi length according to card revision (3.2 rev have a
    // 10-byte signature)
    dataIn = new byte[18 + (calypsoCard.isConfidentialSessionModeSupported() ? 10 : 5)];

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
   * Complete the construction of the APDU to be sent to the card with the elements received from
   * the SAM:
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
    if ((calypsoCard.isConfidentialSessionModeSupported() && reloadComplementaryData.length != 20)
        || (!calypsoCard.isConfidentialSessionModeSupported()
            && reloadComplementaryData.length != 15)) {
      throw new IllegalArgumentException("Bad SV prepare load data length.");
    }

    byte p1 = reloadComplementaryData[4];
    byte p2 = reloadComplementaryData[5];

    dataIn[0] = reloadComplementaryData[6];
    System.arraycopy(reloadComplementaryData, 0, dataIn, 11, 4);
    System.arraycopy(reloadComplementaryData, 7, dataIn, 15, 3);
    System.arraycopy(reloadComplementaryData, 10, dataIn, 18, reloadComplementaryData.length - 10);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                ((CalypsoCardAdapter) calypsoCard).getCardClass().getValue(),
                command.getInstructionByte(),
                p1,
                p2,
                dataIn,
                null)));
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
    svReloadData[3] = calypsoCard.isConfidentialSessionModeSupported() ? (byte) 0x1C : (byte) 0x17;
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
   * @return a {@link CardSvReloadParser} object
   * @since 2.0
   */
  @Override
  public CardSvReloadParser createResponseParser(ApduResponseApi apduResponse) {
    return new CardSvReloadParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command modified the contents of the card and therefore uses the session buffer.
   *
   * @return True
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return true;
  }
}
