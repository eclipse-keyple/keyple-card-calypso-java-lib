/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keypop.calypso.card.transaction.CardSignatureNotVerifiableException;
import org.eclipse.keypop.calypso.card.transaction.CryptoException;
import org.eclipse.keypop.calypso.card.transaction.CryptoIOException;
import org.eclipse.keypop.calypso.card.transaction.InvalidCardSignatureException;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.symmetric.SymmetricCryptoIOException;
import org.eclipse.keypop.card.ApduResponseApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the Close Secure Session APDU command.
 *
 * @since 2.0.1
 */
final class CommandCloseSecureSession extends Command {
  private static final Logger logger = LoggerFactory.getLogger(CommandCloseSecureSession.class);

  private static final String MSG_CARD_SESSION_MAC_NOT_VERIFIABLE =
      "Unable to verify the card session MAC associated to the successfully closed secure session.";
  private static final String MSG_CARD_SV_MAC_NOT_VERIFIABLE =
      "Unable to verify the card SV MAC associated to the SV operation.";
  private static final String MSG_INVALID_CARD_SESSION_MAC = "Invalid card session MAC";
  private static final String MSG_THE_CARD_SIGNATURE_VERIFICATION_FAILED =
      "The card signature verification failed";

  private static final CardCommandRef commandRef = CardCommandRef.CLOSE_SECURE_SESSION;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>(Command.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc signatureLo not supported (e.g. Lc=4 with a Revision 3.2 mode for Open Secure Session).",
            CardIllegalParameterException.class));
    m.put(
        0x6B00,
        new StatusProperties(
            "P1 or P2 signatureLo not supported.", CardIllegalParameterException.class));
    m.put(
        0x6985, new StatusProperties("No session was opened.", CardAccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("incorrect signatureLo.", CardSecurityDataException.class));
    STATUS_TABLE = m;
  }

  private final boolean isAutoRatificationAsked;
  private final boolean isAbortSecureSession;
  private final int svPostponedDataIndex;

  /** The postponed data. */
  private final List<byte[]> postponedData = new ArrayList<byte[]>(0);

  /**
   * Constructor.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param commandContext The local command context specific to each command.
   * @param isAutoRatificationAsked "true" if the auto ratification is asked.
   * @param svPostponedDataIndex The index of the SV postponed data or -1 if there is no SV
   *     postponed data.
   * @since 2.3.2
   */
  CommandCloseSecureSession(
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      boolean isAutoRatificationAsked,
      int svPostponedDataIndex) {
    super(commandRef, 0, transactionContext, commandContext);
    this.isAutoRatificationAsked = isAutoRatificationAsked;
    this.isAbortSecureSession = false;
    this.svPostponedDataIndex = svPostponedDataIndex;
  }

  /**
   * Instantiates a new command based on the product type of the card to generate either an "Abort
   * Secure Session" command or a "Close Secure Session" in PKI mode.
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param context The command context.
   * @param isAbort true for creating an abort session command.
   * @since 2.3.2
   */
  CommandCloseSecureSession(
      TransactionContextDto transactionContext, CommandContextDto context, boolean isAbort) {
    super(commandRef, 0, transactionContext, context);
    this.isAutoRatificationAsked = true;
    this.svPostponedDataIndex = -1;
    if (transactionContext.isPkiMode()) {
      // this a close in PKI mode.
      // in this case, set the APDU earlier since there is no call to finalizeRequest
      setApduRequest(
          new ApduRequestAdapter(
              ApduUtil.build(
                  getTransactionContext().getCard().getCardClass().getValue(),
                  commandRef.getInstructionByte(),
                  (byte) 0x00,
                  (byte) 0x00,
                  null,
                  isAbort ? (byte) 0 : (byte) 0x40)));
      this.isAbortSecureSession = isAbort;
    } else {
      // this is a non PKI session abort
      this.isAbortSecureSession = true;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void finalizeRequest() {
    if (isAbortSecureSession) {
      // Abort secure session
      // CL-CSS-ABORTCMD.1
      setApduRequest(
          new ApduRequestAdapter(
              ApduUtil.build(
                  getTransactionContext().getCard().getCardClass().getValue(),
                  commandRef.getInstructionByte(),
                  (byte) 0x00,
                  (byte) 0x00,
                  null,
                  (byte) 0)));
    } else {
      // Close secure session
      byte[] terminalSessionMac;
      try {
        terminalSessionMac =
            getTransactionContext()
                .getSymmetricCryptoCardTransactionManagerSpi()
                .finalizeTerminalSessionMac();
      } catch (SymmetricCryptoException e) {
        throw new CryptoException(e.getMessage(), e);
      } catch (SymmetricCryptoIOException e) {
        throw new CryptoIOException(e.getMessage(), e);
      }
      setApduRequest(
          new ApduRequestAdapter(
              ApduUtil.build(
                  getTransactionContext().getCard().getCardClass().getValue(),
                  commandRef.getInstructionByte(),
                  isAutoRatificationAsked ? (byte) 0x80 : (byte) 0x00,
                  (byte) 0x00,
                  terminalSessionMac,
                  (byte) 0)));
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean isCryptoServiceRequiredToFinalizeRequest() {
    return !isAbortSecureSession;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  boolean synchronizeCryptoServiceBeforeCardProcessing() {
    return isAbortSecureSession;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  void parseResponse(ApduResponseApi apduResponse) throws CardCommandException {
    if (isAbortSecureSession) {
      processAbort(apduResponse);
      return;
    }
    super.setApduResponseAndCheckStatus(apduResponse);
    byte[] responseData = getApduResponse().getDataOut();
    if (getTransactionContext().isPkiMode()) {
      parseResponseInAsymmetricMode(responseData);
    } else {
      parseResponseInSymmetricMode(responseData);
    }
  }

  /**
   * Aborts the secure session.
   *
   * @param apduResponse The response from the APDU command.
   */
  private void processAbort(ApduResponseApi apduResponse) {
    try {
      super.setApduResponseAndCheckStatus(apduResponse);
      logger.info("Secure session successfully aborted");
      getTransactionContext().getCard().restoreFiles();
    } catch (CardCommandException e) {
      logger.debug("Secure session abortion error: {}", e.getMessage());
    }
  }

  /**
   * Parses the response in symmetric crypto mode to verify the card MAC.
   *
   * @param responseData The byte array containing the response data.
   */
  private void parseResponseInSymmetricMode(byte[] responseData) {
    // Retrieve the postponed data
    int cardSessionMacLength = getTransactionContext().getCard().isExtendedModeSupported() ? 8 : 4;
    int i = 0;
    while (i < responseData.length - cardSessionMacLength) {
      byte[] data = Arrays.copyOfRange(responseData, i + 1, i + responseData[i]);
      postponedData.add(data);
      i += responseData[i];
    }
    // Check the card session MAC (CL-CSS-MACVERIF.1)
    byte[] cardSessionMac = Arrays.copyOfRange(responseData, i, responseData.length);
    try {
      if (!getTransactionContext()
          .getSymmetricCryptoCardTransactionManagerSpi()
          .isCardSessionMacValid(cardSessionMac)) {
        throw new InvalidCardSignatureException(MSG_INVALID_CARD_SESSION_MAC);
      }
    } catch (SymmetricCryptoIOException e) {
      throw new CardSignatureNotVerifiableException(MSG_CARD_SESSION_MAC_NOT_VERIFIABLE, e);
    } catch (SymmetricCryptoException e) {
      throw new CryptoException(e.getMessage(), e);
    }
    if (svPostponedDataIndex != -1) {
      // CL-SV-POSTPON.1
      try {
        if (!getTransactionContext()
            .getSymmetricCryptoCardTransactionManagerSpi()
            .isCardSvMacValid(postponedData.get(svPostponedDataIndex))) {
          throw new InvalidCardSignatureException(MSG_INVALID_CARD_SESSION_MAC);
        }
      } catch (SymmetricCryptoIOException e) {
        throw new CardSignatureNotVerifiableException(MSG_CARD_SV_MAC_NOT_VERIFIABLE, e);
      } catch (SymmetricCryptoException e) {
        throw new CryptoException(e.getMessage(), e);
      }
    }
  }

  /**
   * Parses the response in PKI mode to verify the card signature.
   *
   * @param responseData The byte array containing the response data.
   */
  private void parseResponseInAsymmetricMode(byte[] responseData) {
    boolean isSessionValid;
    try {
      isSessionValid =
          getTransactionContext()
              .getAsymmetricCryptoCardTransactionManagerSpi()
              .isCardPkiSessionValid(responseData);
    } catch (AsymmetricCryptoException e) {
      throw new InvalidCardSignatureException(MSG_THE_CARD_SIGNATURE_VERIFICATION_FAILED, e);
    }
    if (!isSessionValid) {
      throw new InvalidCardSignatureException(MSG_THE_CARD_SIGNATURE_VERIFICATION_FAILED);
    }
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
