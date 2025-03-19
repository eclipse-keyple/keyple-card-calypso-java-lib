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
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keypop.calypso.card.transaction.*;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoIOException;
import org.eclipse.keypop.card.ApduResponseApi;

/**
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
final class CommandSvReload extends Command {

  private static final String MSG_CARD_SV_MAC_NOT_VERIFIABLE =
      "Unable to verify the card SV MAC associated to the SV operation";
  public static final String MSG_INVALID_CARD_SESSION_MAC = "Invalid card session MAC";
  private static final int SW_POSTPONED_DATA = 0x6200;
  private static final Map<Integer, StatusProperties> STATUS_TABLE;
  private final int amount;

  static {
    Map<Integer, StatusProperties> m = new HashMap<>(Command.STATUS_TABLE);
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session", CardSessionBufferOverflowException.class));
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported", CardIllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "Transaction counter is 0 or SV TNum is FFFEh or FFFFh",
            CardTerminatedException.class));
    m.put(
        0x6985,
        new StatusProperties("Preconditions not satisfied", CardAccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("Incorrect signatureHi", CardSecurityDataException.class));
    m.put(
        SW_POSTPONED_DATA,
        new StatusProperties(
            "Successful execution, response data postponed until session closing"));
    STATUS_TABLE = m;
  }

  private final boolean isExtendedModeAllowed;

  /** apdu data array */
  private final byte[] dataIn;

  /**
   * Instantiates a new CommandSvReload.
   *
   * <p>The process is carried out in two steps: first to check and store the card and application
   * data, then to create the final APDU with the data from the SAM (see finalizeCommand).
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param amount amount to debit (signed integer from -8388608 to 8388607).
   * @param date debit date (not checked by the card).
   * @param time debit time (not checked by the card).
   * @param free 2 free bytes stored in the log but not processed by the card.
   * @param isExtendedModeAllowed True if the extended mode is allowed.
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.3.2
   */
  CommandSvReload(
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      int amount,
      byte[] date,
      byte[] time,
      byte[] free,
      boolean isExtendedModeAllowed) {

    super(
        CardCommandRef.SV_RELOAD,
        computeExpectedResponseLength(commandContext, isExtendedModeAllowed),
        transactionContext,
        commandContext);

    // keeps a copy of these fields until the builder is finalized
    this.isExtendedModeAllowed = isExtendedModeAllowed;
    this.amount = amount;

    // handle the dataIn size with signatureHi length according to card revision (3.2 rev have a
    // 10-byte signature)
    dataIn = new byte[18 + (isExtendedModeAllowed ? 10 : 5)];

    // dataIn[0] will be filled in at the finalization phase.
    dataIn[1] = date[0];
    dataIn[2] = date[1];
    dataIn[3] = free[0];
    dataIn[4] = transactionContext.getCard().getSvKvc();
    dataIn[5] = free[1];
    ByteArrayUtil.copyBytes(amount, dataIn, 6, 3);
    dataIn[9] = time[0];
    dataIn[10] = time[1];
    // dataIn[11]..dataIn[11+7+sigLen] will be filled in at the finalization phase.
    // add dummy apdu request to ensure it exists when checking the session buffer usage
    // APDU Case 3 (in session) or 4 (outside session)
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                (byte) 0,
                (byte) 0,
                (byte) 0,
                (byte) 0,
                dataIn,
                computeLe(commandContext, isExtendedModeAllowed))));
  }

  private static int computeExpectedResponseLength(
      CommandContextDto commandContext, boolean isExtendedModeAllowed) {
    if (commandContext.isSecureSessionOpen()) {
      return 0;
    } else {
      return isExtendedModeAllowed ? 6 : 3;
    }
  }

  private static Byte computeLe(CommandContextDto commandContext, boolean isExtendedModeAllowed) {
    if (commandContext.isSecureSessionOpen()) {
      return null;
    } else {
      return (byte) (isExtendedModeAllowed ? 6 : 3);
    }
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

    // APDU Case 3 (in session) or 4 (outside session)
    setApduRequest(
        new ApduRequestAdapter(
                ApduUtil.build(
                    getTransactionContext().getCard().getCardClass() == CalypsoCardClass.LEGACY
                        ? CalypsoCardClass.LEGACY_STORED_VALUE.getValue()
                        : CalypsoCardClass.ISO.getValue(),
                    getCommandRef().getInstructionByte(),
                    p1,
                    p2,
                    dataIn,
                    computeLe(getCommandContext(), isExtendedModeAllowed)))
            .addSuccessfulStatusWord(SW_POSTPONED_DATA));
  }

  /**
   * Gets the SV Reload part of the data to include in the SAM SV Prepare Load command
   *
   * @return a byte array containing the SV reload data
   * @since 2.0.1
   */
  byte[] getSvReloadData() {
    byte[] svReloadData = new byte[15];
    svReloadData[0] = getCommandRef().getInstructionByte();
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
   * @since 2.3.2
   */
  @Override
  void finalizeRequest() {
    SvCommandSecurityDataApiAdapter svCommandSecurityData = new SvCommandSecurityDataApiAdapter();
    svCommandSecurityData.setSvGetRequest(getTransactionContext().getCard().getSvGetHeader());
    svCommandSecurityData.setSvGetResponse(getTransactionContext().getCard().getSvGetData());
    svCommandSecurityData.setSvCommandPartialRequest(getSvReloadData());
    try {
      getTransactionContext()
          .getSymmetricCryptoCardTransactionManagerSpi()
          .computeSvCommandSecurityData(svCommandSecurityData);
    } catch (SymmetricCryptoException e) {
      throw new CryptoException(e.getMessage(), e);
    } catch (SymmetricCryptoIOException e) {
      throw new CryptoIOException(e.getMessage(), e);
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
      throw new IllegalStateException("Bad length in response to SV Reload command");
    }
    CalypsoCardAdapter calypsoCard = getTransactionContext().getCard();
    calypsoCard.setSvOperationSignature(apduResponse.getDataOut());
    updateCalypsoCardSvHistory(calypsoCard);
    updateTerminalSessionIfNeeded();
    if (!getCommandContext().isSecureSessionOpen()) {
      try {
        if (!getTransactionContext()
            .getSymmetricCryptoCardTransactionManagerSpi()
            .isCardSvMacValid(getTransactionContext().getCard().getSvOperationSignature())) {
          throw new InvalidCardSignatureException(MSG_INVALID_CARD_SESSION_MAC);
        }
      } catch (SymmetricCryptoIOException e) {
        throw new CardSignatureNotVerifiableException(MSG_CARD_SV_MAC_NOT_VERIFIABLE, e);
      } catch (SymmetricCryptoException e) {
        throw new CryptoIOException(e.getMessage(), e);
      }
    }
  }

  /**
   * Updates the Calypso card with the SV Reload data to update the SV balance and the SV reload
   * log.
   *
   * @param calypsoCard The Calypso card.
   */
  private void updateCalypsoCardSvHistory(CalypsoCardAdapter calypsoCard) {
    int balance = calypsoCard.getSvBalance() + amount;
    calypsoCard.updateSvData(balance, calypsoCard.getSvLastTNum() + 1);
    byte[] reloadLog = new byte[22];
    System.arraycopy(getApduRequest().getApdu(), 6, reloadLog, 0, 5);
    ByteArrayUtil.copyBytes(balance, reloadLog, 5, 3);
    ByteArrayUtil.copyBytes(amount, reloadLog, 8, 3);
    System.arraycopy(getApduRequest().getApdu(), 14, reloadLog, 11, 9);
    ByteArrayUtil.copyBytes(calypsoCard.getSvLastTNum(), reloadLog, 20, 2);
    calypsoCard.addCyclicContent(CalypsoCardConstant.SV_RELOAD_LOG_FILE_SFI, reloadLog);
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
