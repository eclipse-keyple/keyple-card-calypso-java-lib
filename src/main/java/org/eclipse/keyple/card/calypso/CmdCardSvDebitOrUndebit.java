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
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the SV Debit or SV Undebit command.
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
final class CmdCardSvDebitOrUndebit extends AbstractCardCommand {

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

  private final CalypsoCardClass calypsoCardClass;
  private final boolean useExtendedMode;
  /** apdu data array */
  private final byte[] dataIn;

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardSvDebitOrUndebit.
   *
   * @param isDebitCommand True if it is an "SV Debit" command, false if it is a "SV Undebit"
   *     command.
   * @param calypsoCardClass Indicates which CLA byte should be used for the Apdu.
   * @param amount amount to debit or undebit (positive integer from 0 to 32767).
   * @param kvc the KVC.
   * @param date operation date (not checked by the card).
   * @param time operation time (not checked by the card).
   * @param useExtendedMode True if the extended mode must be used.
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.0.1
   */
  CmdCardSvDebitOrUndebit(
      boolean isDebitCommand,
      CalypsoCardClass calypsoCardClass,
      int amount,
      byte kvc,
      byte[] date,
      byte[] time,
      boolean useExtendedMode) {

    super(isDebitCommand ? CalypsoCardCommand.SV_DEBIT : CalypsoCardCommand.SV_UNDEBIT, 0);

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
    this.calypsoCardClass = calypsoCardClass;
    this.useExtendedMode = useExtendedMode;

    // handle the dataIn size with signatureHi length according to card product type (3.2 rev have a
    // 10-byte signature)
    dataIn = new byte[15 + (useExtendedMode ? 10 : 5)];

    // dataIn[0] will be filled in at the finalization phase.
    short amountShort = isDebitCommand ? (short) -amount : (short) amount;
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
   * @param debitOrUndebitComplementaryData the data out from the SvPrepareDebit SAM command.
   * @since 2.0.1
   */
  void finalizeCommand(byte[] debitOrUndebitComplementaryData) {
    if ((useExtendedMode && debitOrUndebitComplementaryData.length != 20)
        || (!useExtendedMode && debitOrUndebitComplementaryData.length != 15)) {
      throw new IllegalArgumentException("Bad SV prepare load data length.");
    }

    byte p1 = debitOrUndebitComplementaryData[4];
    byte p2 = debitOrUndebitComplementaryData[5];

    dataIn[0] = debitOrUndebitComplementaryData[6];
    System.arraycopy(debitOrUndebitComplementaryData, 0, dataIn, 8, 4);
    System.arraycopy(debitOrUndebitComplementaryData, 7, dataIn, 12, 3);
    System.arraycopy(
        debitOrUndebitComplementaryData,
        10,
        dataIn,
        15,
        debitOrUndebitComplementaryData.length - 10);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass == CalypsoCardClass.LEGACY
                    ? CalypsoCardClass.LEGACY_STORED_VALUE.getValue()
                    : CalypsoCardClass.ISO.getValue(),
                getCommandRef().getInstructionByte(),
                p1,
                p2,
                dataIn,
                null)));
  }

  /**
   * (package-private)<br>
   * Gets the SV Debit/Undebit part of the data to include in the SAM SV Prepare Debit command
   *
   * @return A byte array containing the SV debit/undebit data
   * @since 2.0.1
   */
  byte[] getSvDebitOrUndebitData() {
    byte[] svDebitOrUndebitData = new byte[12];
    svDebitOrUndebitData[0] = getCommandRef().getInstructionByte();
    // svDebitOrUndebitData[1,2] / P1P2 not set because ignored
    // Lc is 5 bytes longer in product type 3.2
    svDebitOrUndebitData[3] = useExtendedMode ? (byte) 0x19 : (byte) 0x14;
    // appends the fixed part of dataIn
    System.arraycopy(dataIn, 0, svDebitOrUndebitData, 4, 8);
    return svDebitOrUndebitData;
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
  CmdCardSvDebitOrUndebit setApduResponse(ApduResponseApi apduResponse) {
    super.setApduResponse(apduResponse);
    if (apduResponse.getDataOut().length != 0
        && apduResponse.getDataOut().length != 3
        && apduResponse.getDataOut().length != 6) {
      throw new IllegalStateException("Bad length in response to SV Debit/Undebit command.");
    }
    return this;
  }

  /**
   * (package-private)<br>
   * Gets the SV signature. <br>
   * The signature can be empty here in the case of a secure session where the transmission of the
   * signature is postponed until the end of the session.
   *
   * @return A byte array containing the SV signature
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
