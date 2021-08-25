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
 * Builds the SV Debit command.
 *
 * <p>Note: {@link CardSvDebitBuilder} and {@link CardSvUndebitBuilder} shares the same parser
 * {@link CardSvDebitParser}
 *
 * @since 2.0.0
 */
final class CardSvDebitBuilder extends AbstractCardCommandBuilder<CardSvDebitParser> {

  /** The command. */
  private static final CalypsoCardCommand command = CalypsoCardCommand.SV_DEBIT;

  private final CalypsoCard calypsoCard;
  /** apdu data array */
  private final byte[] dataIn;

  /**
   * Instantiates a new CardSvDebitBuilder.
   *
   * @param calypsoCard the Calypso card.
   * @param amount amount to debit (positive integer from 0 to 32767).
   * @param kvc the KVC.
   * @param date debit date (not checked by the card).
   * @param time debit time (not checked by the card).
   * @throws IllegalArgumentException - if the command is inconsistent
   * @since 2.0.0
   */
  public CardSvDebitBuilder(
      CalypsoCard calypsoCard, int amount, byte kvc, byte[] date, byte[] time) {
    super(command);

    /* @see Calypso Layer ID 8.02 (200108) */
    if (amount < 0 || amount > 32767) {
      throw new IllegalArgumentException(
          "Amount is outside allowed boundaries (0 <= amount <= 32767)");
    }
    if (date == null || time == null) {
      throw new IllegalArgumentException("date and time cannot be null");
    }
    if (date.length != 2 || time.length != 2) {
      throw new IllegalArgumentException("date and time must be 2-byte arrays");
    }

    // keeps a copy of these fields until the builder is finalized
    this.calypsoCard = calypsoCard;

    // handle the dataIn size with signatureHi length according to card revision (3.2 rev have a
    // 10-byte signature)
    dataIn = new byte[15 + (calypsoCard.isExtendedModeSupported() ? 10 : 5)];

    // dataIn[0] will be filled in at the finalization phase.
    short amountShort = (short) -amount;
    dataIn[1] = (byte) ((amountShort >> 8) & 0xFF);
    dataIn[2] = (byte) (amountShort & 0xFF);
    dataIn[3] = date[0];
    dataIn[4] = date[1];
    dataIn[5] = time[0];
    dataIn[6] = time[1];
    dataIn[7] = kvc;
    // dataIn[8]..dataIn[8+7+sigLen] will be filled in at the finalization phase.
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
   * @param debitComplementaryData the data out from the SvPrepareDebit SAM command.
   * @since 2.0.0
   */
  public void finalizeBuilder(byte[] debitComplementaryData) {
    if ((calypsoCard.isExtendedModeSupported() && debitComplementaryData.length != 20)
        || (!calypsoCard.isExtendedModeSupported() && debitComplementaryData.length != 15)) {
      throw new IllegalArgumentException("Bad SV prepare load data length.");
    }

    byte p1 = debitComplementaryData[4];
    byte p2 = debitComplementaryData[5];

    dataIn[0] = debitComplementaryData[6];
    System.arraycopy(debitComplementaryData, 0, dataIn, 8, 4);
    System.arraycopy(debitComplementaryData, 7, dataIn, 12, 3);
    System.arraycopy(debitComplementaryData, 10, dataIn, 15, debitComplementaryData.length - 10);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                ((CalypsoCardAdapter) calypsoCard).getCardClass() == CalypsoCardClass.LEGACY
                    ? CalypsoCardClass.LEGACY_STORED_VALUE.getValue()
                    : CalypsoCardClass.ISO.getValue(),
                command.getInstructionByte(),
                p1,
                p2,
                dataIn,
                null)));
  }

  /**
   * Gets the SV Debit part of the data to include in the SAM SV Prepare Debit command
   *
   * @return a byte array containing the SV debit data
   * @since 2.0.0
   */
  public byte[] getSvDebitData() {
    byte[] svDebitData = new byte[12];
    svDebitData[0] = command.getInstructionByte();
    // svDebitData[1,2] / P1P2 not set because ignored
    // Lc is 5 bytes longer in revision 3.2
    svDebitData[3] = calypsoCard.isExtendedModeSupported() ? (byte) 0x19 : (byte) 0x14;
    // appends the fixed part of dataIn
    System.arraycopy(dataIn, 0, svDebitData, 4, 8);
    return svDebitData;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSvDebitParser createResponseParser(ApduResponseApi apduResponse) {
    return new CardSvDebitParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command modified the contents of the card and therefore uses the session buffer.
   *
   * @return True
   * @since 2.0.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return true;
  }
}
