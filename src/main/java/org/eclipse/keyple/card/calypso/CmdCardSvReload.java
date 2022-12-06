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
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Builds the SV Reload command.
 *
 * <p>See specs: Calypso Stored Value balance (signed binaries' coding based on the two's complement
 * method)
 *
 * <p>balance - 3 bytes signed binary - Integer from -8,388,608 to 8,388,607
 *
 * <p>amount for reload, 3 bytes signed binary - Integer from -8,388,608 to 8,388,607
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
 * @since 2.0.1
 */
final class CmdCardSvReload extends AbstractCardCommand {

  /** The command. */
  private static final CalypsoCardCommand command = CalypsoCardCommand.SV_RELOAD;

  private static final int SW_POSTPONED_DATA = 0x6200;
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractCardCommand.STATUS_TABLE);
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
            CardTerminatedException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied.", CardAccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("Incorrect signatureHi.", CardSecurityDataException.class));
    m.put(
        SW_POSTPONED_DATA,
        new StatusProperties(
            "Successful execution, response data postponed until session closing."));
    STATUS_TABLE = m;
  }

  private final boolean isExtendedModeAllowed;
  /** apdu data array */
  private final byte[] dataIn;

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardSvReload.
   *
   * <p>The process is carried out in two steps: first to check and store the card and application
   * data, then to create the final APDU with the data from the SAM (see finalizeCommand).
   *
   * @param calypsoCard The Calypso card.
   * @param amount amount to debit (signed integer from -8388608 to 8388607).
   * @param date debit date (not checked by the card).
   * @param time debit time (not checked by the card).
   * @param free 2 free bytes stored in the log but not processed by the card.
   * @param isExtendedModeAllowed True if the extended mode is allowed.
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.0.1
   */
  CmdCardSvReload(
      CalypsoCardAdapter calypsoCard,
      int amount,
      byte[] date,
      byte[] time,
      byte[] free,
      boolean isExtendedModeAllowed) {

    super(command, 0, calypsoCard);

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
    this.isExtendedModeAllowed = isExtendedModeAllowed;

    // handle the dataIn size with signatureHi length according to card revision (3.2 rev have a
    // 10-byte signature)
    dataIn = new byte[18 + (isExtendedModeAllowed ? 10 : 5)];

    // dataIn[0] will be filled in at the finalization phase.
    dataIn[1] = date[0];
    dataIn[2] = date[1];
    dataIn[3] = free[0];
    dataIn[4] = calypsoCard.getSvKvc();
    dataIn[5] = free[1];
    ByteArrayUtil.copyBytes(amount, dataIn, 6, 3);
    dataIn[9] = time[0];
    dataIn[10] = time[1];
    // dataIn[11]..dataIn[11+7+sigLen] will be filled in at the finalization phase.
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
   * @param svCommandSecurityData the sam id and the data out from the SvPrepareReload SAM command.
   * @since 2.0.1
   */
  void finalizeCommand(SvCommandSecurityDataApiAdapter svCommandSecurityData) {

    byte p1 = svCommandSecurityData.getTerminalChallenge()[0];
    byte p2 = svCommandSecurityData.getTerminalChallenge()[1];
    dataIn[0] = svCommandSecurityData.getTerminalChallenge()[2];
    System.arraycopy(svCommandSecurityData.getSerialNumber(), 0, dataIn, 11, 4);
    System.arraycopy(svCommandSecurityData.getTransactionNumber(), 0, dataIn, 15, 3);
    System.arraycopy(
        svCommandSecurityData.getTerminalSvMac(),
        0,
        dataIn,
        18,
        svCommandSecurityData.getTerminalSvMac().length);

    setApduRequest(
        new ApduRequestAdapter(
                ApduUtil.build(
                    getCalypsoCard().getCardClass() == CalypsoCardClass.LEGACY
                        ? CalypsoCardClass.LEGACY_STORED_VALUE.getValue()
                        : CalypsoCardClass.ISO.getValue(),
                    command.getInstructionByte(),
                    p1,
                    p2,
                    dataIn,
                    null))
            .addSuccessfulStatusWord(SW_POSTPONED_DATA));
  }

  /**
   * (package-private)<br>
   * Gets the SV Reload part of the data to include in the SAM SV Prepare Load command
   *
   * @return a byte array containing the SV reload data
   * @since 2.0.1
   */
  byte[] getSvReloadData() {
    byte[] svReloadData = new byte[15];
    svReloadData[0] = command.getInstructionByte();
    // svReloadData[1,2] / P1P2 not set because ignored
    // Lc is 5 bytes longer in revision 3.2
    svReloadData[3] = isExtendedModeAllowed ? (byte) 0x1C : (byte) 0x17;
    // appends the fixed part of dataIn
    System.arraycopy(dataIn, 0, svReloadData, 4, 11);
    return svReloadData;
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
  void parseApduResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.parseApduResponse(apduResponse);
    if (apduResponse.getDataOut().length != 0
        && apduResponse.getDataOut().length != 3
        && apduResponse.getDataOut().length != 6) {
      throw new IllegalStateException("Bad length in response to SV Reload command.");
    }
    getCalypsoCard().setSvOperationSignature(apduResponse.getDataOut());
  }

  /**
   * (package-private)<br>
   * Gets the SV signature. <br>
   * The signature can be empty here in the case of a secure session where the transmission of the
   * signature is postponed until the end of the session.
   *
   * @return A byte array containing the signature
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
