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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the SV Debit command.
 *
 * <p>See specs: Calypso Stored Value balance (signed binaries' coding based on the two's complement
 * method)
 *
 * <p>balance - 3 bytes signed binary - Integer from -8,388,608 to 8,388,607
 *
 * <pre>
 * -8,388,608           %10000000.00000000.00000000
 * -8,388,607           %10000000.00000000.00000001
 * -8,388,606           %10000000.00000000.00000010
 *
 * -3           %11111111.11111111.11111101
 * -2           %11111111.11111111.11111110
 * -1           %11111111.11111111.11111111
 * 0           %00000000.00000000.00000000
 * 1           %00000000.00000000.00000001
 * 2           %00000000.00000000.00000010
 * 3           %00000000.00000000.00000011
 *
 * 8,388,605           %01111111.11111111.11111101
 * 8,388,606           %01111111.11111111.11111110
 * 8,388,607           %01111111.11111111.11111111
 * </pre>
 *
 * amount - 2 bytes signed binary
 *
 * <p>amount for debit - Integer 0..32767 =&gt; for negative value
 *
 * <pre>
 * -32767           %10000000.00000001
 * -32766           %10000000.00000010
 * -3           %11111111.11111101
 * -2           %11111111.11111110
 * -1           %11111111.11111111
 * 0           %00000000.00000000
 *
 * Notice: -32768 (%10000000.00000000) is not allowed.
 * </pre>
 *
 * @since 2.0.1
 */
final class CmdCardSvDebit extends AbstractCardCommand {

  /** The command. */
  private static final CalypsoCardCommand command = CalypsoCardCommand.SV_DEBIT;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session.", CardSessionBufferOverflowException.class));
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CardIllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "Transaction counter is 0 or SV TNum is FFFEh or FFFFh.",
            CalypsoSamCounterOverflowException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied.", CalypsoSamAccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("Incorrect signatureHi.", CardSecurityDataException.class));
    m.put(
        0x6200,
        new StatusProperties(
            "Successful execution, response data postponed until session closing.", null));
    STATUS_TABLE = m;
  }

  private final CalypsoCard calypsoCard;
  /** apdu data array */
  private final byte[] dataIn;

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardSvDebit.
   *
   * @param calypsoCard the Calypso card.
   * @param amount amount to debit (positive integer from 0 to 32767).
   * @param kvc the KVC.
   * @param date debit date (not checked by the card).
   * @param time debit time (not checked by the card).
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.0.1
   */
  CmdCardSvDebit(CalypsoCard calypsoCard, int amount, byte kvc, byte[] date, byte[] time) {

    super(command);

    /* @see Calypso Layer ID 8.02 (200108) */
    // CL-SV-DEBITVAL.1
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

    // keeps a copy of these fields until the command is finalized
    this.calypsoCard = calypsoCard;

    // handle the dataIn size with signatureHi length according to card product type (3.2 rev have a
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
   * (package-private)<br>
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
   * @since 2.0.1
   */
  void finalizeCommand(byte[] debitComplementaryData) {
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
   * (package-private)<br>
   * Gets the SV Debit part of the data to include in the SAM SV Prepare Debit command
   *
   * @return a byte array containing the SV debit data
   * @since 2.0.1
   */
  byte[] getSvDebitData() {
    byte[] svDebitData = new byte[12];
    svDebitData[0] = command.getInstructionByte();
    // svDebitData[1,2] / P1P2 not set because ignored
    // Lc is 5 bytes longer in product type 3.2
    svDebitData[3] = calypsoCard.isExtendedModeSupported() ? (byte) 0x19 : (byte) 0x14;
    // appends the fixed part of dataIn
    System.arraycopy(dataIn, 0, svDebitData, 4, 8);
    return svDebitData;
  }

  /**
   * {@inheritDoc}
   *
   * @return True
   * @since 2.0.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The permitted lengths are 0 (in session), 3 (not 3.2) or 6 (3.2)
   *
   * @throws IllegalStateException If the length is incorrect.
   * @since 2.0.1
   */
  @Override
  CmdCardSvDebit setApduResponse(ApduResponseApi apduResponse) {
    super.setApduResponse(apduResponse);
    if (apduResponse.getDataOut().length != 0
        && apduResponse.getDataOut().length != 3
        && apduResponse.getDataOut().length != 6) {
      throw new IllegalStateException("Bad length in response to SV Debit command.");
    }
    return this;
  }

  /**
   * (package-private)<br>
   * Gets the SV signature. <br>
   * The signature can be empty here in the case of a secure session where the transmission of the
   * signature is postponed until the end of the session.
   *
   * @return a byte array containing the signature
   * @since 2.0.1
   */
  byte[] getSignatureLo() {
    return getApduResponse().getDataOut();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
