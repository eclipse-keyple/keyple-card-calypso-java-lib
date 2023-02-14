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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.transaction.CardSignatureNotVerifiableException;
import org.calypsonet.terminal.calypso.transaction.InvalidCardSignatureException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
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
final class CmdCardSvDebitOrUndebit extends CardCommand {

  private static final String MSG_CARD_SV_MAC_NOT_VERIFIABLE =
      "Unable to verify the card SV MAC associated to the SV operation.";
  public static final String MSG_INVALID_CARD_SESSION_MAC = "Invalid card session MAC";
  private static final int SW_POSTPONED_DATA = 0x6200;
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
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

  private final int amount;
  private final boolean isDebitCommand;
  private final boolean isExtendedModeAllowed;
  private final boolean isSvNegativeBalanceAuthorized;
  /** apdu data array */
  private final byte[] dataIn;

  /**
   * Instantiates a new CmdCardSvDebitOrUndebit.
   *
   * @param isDebitCommand True if it is an "SV Debit" command, false if it is a "SV Undebit"
   *     command.
   * @param calypsoCard The Calypso card.
   * @param amount amount to debit or undebit (positive integer from 0 to 32767).
   * @param date operation date (not checked by the card).
   * @param time operation time (not checked by the card).
   * @param isExtendedModeAllowed True if the extended mode is allowed.
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.0.1
   * @deprecated
   */
  @Deprecated
  CmdCardSvDebitOrUndebit(
      boolean isDebitCommand,
      CalypsoCardAdapter calypsoCard,
      int amount,
      byte[] date,
      byte[] time,
      boolean isExtendedModeAllowed) {

    super(
        isDebitCommand ? CardCommandRef.SV_DEBIT : CardCommandRef.SV_UNDEBIT, 0, calypsoCard, null);

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
    this.amount = amount;
    this.isDebitCommand = isDebitCommand;
    this.isExtendedModeAllowed = isExtendedModeAllowed;
    this.isSvNegativeBalanceAuthorized = true;

    // handle the dataIn size with signatureHi length according to card product type (3.2 rev have a
    // 10-byte signature)
    dataIn = new byte[15 + (isExtendedModeAllowed ? 10 : 5)];

    // dataIn[0] will be filled in at the finalization phase.
    short amountShort = isDebitCommand ? (short) -amount : (short) amount;
    ByteArrayUtil.copyBytes(amountShort, dataIn, 1, 2);
    dataIn[3] = date[0];
    dataIn[4] = date[1];
    dataIn[5] = time[0];
    dataIn[6] = time[1];
    dataIn[7] = calypsoCard.getSvKvc();
    // dataIn[8]..dataIn[8+7+sigLen] will be filled in at the finalization phase.
  }

  /**
   * Instantiates a new CmdCardSvDebitOrUndebit.
   *
   * @param isDebitCommand True if it is an "SV Debit" command, false if it is a "SV Undebit"
   *     command.
   * @param context The context.
   * @param amount amount to debit or undebit (positive integer from 0 to 32767).
   * @param date operation date (not checked by the card).
   * @param time operation time (not checked by the card).
   * @param isExtendedModeAllowed True if the extended mode is allowed.
   * @param isSvNegativeBalanceAuthorized True if the negative balance is authorized.
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.3.2
   */
  CmdCardSvDebitOrUndebit(
      boolean isDebitCommand,
      CommandContextDto context,
      int amount,
      byte[] date,
      byte[] time,
      boolean isExtendedModeAllowed,
      boolean isSvNegativeBalanceAuthorized) {

    super(isDebitCommand ? CardCommandRef.SV_DEBIT : CardCommandRef.SV_UNDEBIT, 0, null, context);

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
    this.amount = amount;
    this.isDebitCommand = isDebitCommand;
    this.isExtendedModeAllowed = isExtendedModeAllowed;
    this.isSvNegativeBalanceAuthorized = isSvNegativeBalanceAuthorized;

    // handle the dataIn size with signatureHi length according to card product type (3.2 rev have a
    // 10-byte signature)
    dataIn = new byte[15 + (isExtendedModeAllowed ? 10 : 5)];

    // dataIn[0] will be filled in at the finalization phase.
    short amountShort = isDebitCommand ? (short) -amount : (short) amount;
    ByteArrayUtil.copyBytes(amountShort, dataIn, 1, 2);
    dataIn[3] = date[0];
    dataIn[4] = date[1];
    dataIn[5] = time[0];
    dataIn[6] = time[1];
    dataIn[7] = context.getCard().getSvKvc();
    // dataIn[8]..dataIn[8+7+sigLen] will be filled in at the finalization phase.
    // add dummy apdu request to ensure it exists when checking the session buffer usage
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build((byte) 0, (byte) 0, (byte) 0, (byte) 0, dataIn, null)));
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
   * @param svCommandSecurityData the data out from the SvPrepareDebit SAM command.
   * @since 2.0.1
   */
  void finalizeCommand(SvCommandSecurityDataApiAdapter svCommandSecurityData) {

    CalypsoCardAdapter card = getContext() != null ? getContext().getCard() : getCalypsoCard();
    byte p1 = svCommandSecurityData.getTerminalChallenge()[0];
    byte p2 = svCommandSecurityData.getTerminalChallenge()[1];
    dataIn[0] = svCommandSecurityData.getTerminalChallenge()[2];
    System.arraycopy(svCommandSecurityData.getSerialNumber(), 0, dataIn, 8, 4);
    System.arraycopy(svCommandSecurityData.getTransactionNumber(), 0, dataIn, 12, 3);
    System.arraycopy(
        svCommandSecurityData.getTerminalSvMac(),
        0,
        dataIn,
        15,
        svCommandSecurityData.getTerminalSvMac().length);

    setApduRequest(
        new ApduRequestAdapter(
                ApduUtil.build(
                    card.getCardClass() == CalypsoCardClass.LEGACY
                        ? CalypsoCardClass.LEGACY_STORED_VALUE.getValue()
                        : CalypsoCardClass.ISO.getValue(),
                    getCommandRef().getInstructionByte(),
                    p1,
                    p2,
                    dataIn,
                    null))
            .addSuccessfulStatusWord(SW_POSTPONED_DATA));
  }

  /**
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
    svDebitOrUndebitData[3] = isExtendedModeAllowed ? (byte) 0x19 : (byte) 0x14;
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
   * @since 2.3.2
   */
  @Override
  void finalizeRequest() {
    if (isDebitCommand
        && !isSvNegativeBalanceAuthorized
        && (getContext().getCard().getSvBalance() - amount) < 0) {
      throw new IllegalStateException("Negative balances not allowed");
    }
    SvCommandSecurityDataApiAdapter svCommandSecurityData = new SvCommandSecurityDataApiAdapter();
    svCommandSecurityData.setSvGetRequest(getContext().getCard().getSvGetHeader());
    svCommandSecurityData.setSvGetResponse(getContext().getCard().getSvGetData());
    svCommandSecurityData.setSvCommandPartialRequest(getSvDebitOrUndebitData());
    try {
      getContext()
          .getSymmetricCryptoTransactionManagerSpi()
          .computeSvCommandSecurityData(svCommandSecurityData);
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    } catch (SymmetricCryptoIOException e) {
      throw (RuntimeException) e.getCause();
    }
    finalizeCommand(svCommandSecurityData);
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean isCryptoServiceRequiredToFinalizeRequest() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    super.setApduResponseAndCheckStatus(apduResponse);
    if (apduResponse.getDataOut().length != 0
        && apduResponse.getDataOut().length != 3
        && apduResponse.getDataOut().length != 6) {
      throw new IllegalStateException("Bad length in response to SV Debit/Undebit command.");
    }
    getContext().getCard().setSvOperationSignature(apduResponse.getDataOut());
    updateTerminalSessionMacIfNeeded();
    if (!getContext().isSecureSessionOpen()) {
      try {
        if (!getContext()
            .getSymmetricCryptoTransactionManagerSpi()
            .isCardSvMacValid(getContext().getCard().getSvOperationSignature())) {
          throw new InvalidCardSignatureException(MSG_INVALID_CARD_SESSION_MAC);
        }
      } catch (SymmetricCryptoIOException e) {
        throw new CardSignatureNotVerifiableException(MSG_CARD_SV_MAC_NOT_VERIFIABLE, e);
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      }
    }
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
  void setApduResponseAndCheckStatus(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);
    if (apduResponse.getDataOut().length != 0
        && apduResponse.getDataOut().length != 3
        && apduResponse.getDataOut().length != 6) {
      throw new IllegalStateException("Bad length in response to SV Debit/Undebit command.");
    }
    getCalypsoCard().setSvOperationSignature(apduResponse.getDataOut());
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
