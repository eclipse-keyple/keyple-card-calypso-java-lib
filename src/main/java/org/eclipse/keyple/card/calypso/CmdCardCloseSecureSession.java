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
import org.eclipse.keypop.calypso.card.transaction.CardMacNotVerifiableException;
import org.eclipse.keypop.calypso.card.transaction.InvalidCardMacException;
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
final class CmdCardCloseSecureSession extends CardCommand {
  private static final Logger logger = LoggerFactory.getLogger(CmdCardCloseSecureSession.class);

  private static final String MSG_CARD_SESSION_MAC_NOT_VERIFIABLE =
      "Unable to verify the card session MAC associated to the successfully closed secure session.";
  private static final String MSG_CARD_SV_MAC_NOT_VERIFIABLE =
      "Unable to verify the card SV MAC associated to the SV operation.";
  public static final String MSG_INVALID_CARD_SESSION_MAC = "Invalid card session MAC";

  private static final CardCommandRef commandRef = CardCommandRef.CLOSE_SECURE_SESSION;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
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

  /** The signatureLo. */
  private byte[] signatureLo;

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
  CmdCardCloseSecureSession(
      TransactionContextDto transactionContext,
      CommandContextDto commandContext,
      boolean isAutoRatificationAsked,
      int svPostponedDataIndex) {
    super(commandRef, 0, null, transactionContext, commandContext);
    this.isAutoRatificationAsked = isAutoRatificationAsked;
    this.isAbortSecureSession = false;
    this.svPostponedDataIndex = svPostponedDataIndex;
  }

  /**
   * Instantiates a new command based on the product type of the card to generate an abort session
   * command (Close Secure Session with p1 = p2 = lc = 0).
   *
   * @param transactionContext The global transaction context common to all commands.
   * @param context The command context.
   * @since 2.3.2
   */
  CmdCardCloseSecureSession(TransactionContextDto transactionContext, CommandContextDto context) {
    super(commandRef, 0, null, transactionContext, context);
    this.isAutoRatificationAsked = true;
    this.isAbortSecureSession = true;
    this.svPostponedDataIndex = -1;
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
                .getSymmetricCryptoTransactionManagerSpi()
                .finalizeTerminalSessionMac();
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      } catch (SymmetricCryptoIOException e) {
        throw (RuntimeException) e.getCause();
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
      getTransactionContext().setSecureSessionOpen(false);
      try {
        super.setApduResponseAndCheckStatus(apduResponse);
        logger.info("Secure session successfully aborted");
        getTransactionContext().getCard().restoreFiles();
      } catch (CardCommandException e) {
        logger.debug("Secure session abortion error: {}", e.getMessage());
      }
      return;
    }
    super.setApduResponseAndCheckStatus(apduResponse);
    getTransactionContext().setSecureSessionOpen(false);
    byte[] responseData = getApduResponse().getDataOut();
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
          .getSymmetricCryptoTransactionManagerSpi()
          .isCardSessionMacValid(cardSessionMac)) {
        throw new InvalidCardMacException(MSG_INVALID_CARD_SESSION_MAC);
      }
    } catch (SymmetricCryptoIOException e) {
      throw new CardMacNotVerifiableException(MSG_CARD_SESSION_MAC_NOT_VERIFIABLE, e);
    } catch (SymmetricCryptoException e) {
      throw (RuntimeException) e.getCause();
    }
    if (svPostponedDataIndex != -1) {
      // CL-SV-POSTPON.1
      try {
        if (!getTransactionContext()
            .getSymmetricCryptoTransactionManagerSpi()
            .isCardSvMacValid(postponedData.get(svPostponedDataIndex))) {
          throw new InvalidCardMacException(MSG_INVALID_CARD_SESSION_MAC);
        }
      } catch (SymmetricCryptoIOException e) {
        throw new CardMacNotVerifiableException(MSG_CARD_SV_MAC_NOT_VERIFIABLE, e);
      } catch (SymmetricCryptoException e) {
        throw (RuntimeException) e.getCause();
      }
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>Checks the card response length; the admissible lengths are 0, 4 or 8 bytes.
   *
   * @since 2.0.1
   */
  @Override
  void setApduResponseAndCheckStatus(ApduResponseApi apduResponse) throws CardCommandException {
    super.setApduResponseAndCheckStatus(apduResponse);
    byte[] responseData = getApduResponse().getDataOut();
    if (responseData.length > 0) {
      int signatureLength = getCalypsoCard().isExtendedModeSupported() ? 8 : 4;
      int i = 0;
      while (i < responseData.length - signatureLength) {
        byte[] data = Arrays.copyOfRange(responseData, i + 1, i + responseData[i]);
        postponedData.add(data);
        i += responseData[i];
      }
      signatureLo = Arrays.copyOfRange(responseData, i, responseData.length);
    } else {
      // session abort case
      signatureLo = new byte[0];
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
