/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.transaction.SamTransactionManager;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Card Control SAM Transaction Manager.
 *
 * @since 2.2.0
 */
final class CardControlSamTransactionManagerAdapter
    extends CommonControlSamTransactionManagerAdapter {

  private final CalypsoSamAdapter controlSam;
  private final CalypsoCardAdapter targetCard;
  private final CardSecuritySettingAdapter cardSecuritySetting;

  private DigestManager digestManager;

  /**
   * (package-private)<br>
   * Creates a new instance to control a card.
   *
   * @param targetCard The target card to control provided by the selection process.
   * @param securitySetting The associated card security settings.
   * @param transactionAuditData The original transaction data to fill.
   * @since 2.2.0
   */
  CardControlSamTransactionManagerAdapter(
      CalypsoCardAdapter targetCard,
      CardSecuritySettingAdapter securitySetting,
      List<byte[]> transactionAuditData) {
    // CL-SAM-CSN.1
    super(
        targetCard, securitySetting, targetCard.getCalypsoSerialNumberFull(), transactionAuditData);
    this.controlSam = securitySetting.getControlSam();
    this.targetCard = targetCard;
    this.cardSecuritySetting = securitySetting;
  }

  /**
   * (package-private)<br>
   * Returns the KVC to use according to the provided write access and the card's KVC.
   *
   * @param writeAccessLevel The write access level.
   * @param kvc The card KVC value.
   * @return Null if the card did not provide a KVC value and if there's no default KVC value.
   * @since 2.2.0
   */
  Byte computeKvc(WriteAccessLevel writeAccessLevel, Byte kvc) {
    if (kvc != null) {
      return kvc;
    }
    return cardSecuritySetting.getDefaultKvc(writeAccessLevel);
  }

  /**
   * (package-private)<br>
   * Returns the KIF to use according to the provided write access level and KVC.
   *
   * @param writeAccessLevel The write access level.
   * @param kif The card KIF value.
   * @param kvc The previously computed KVC value.
   * @return Null if the card did not provide a KIF value and if there's no default KIF value.
   * @since 2.2.0
   */
  Byte computeKif(WriteAccessLevel writeAccessLevel, Byte kif, Byte kvc) {
    // CL-KEY-KIF.1
    if ((kif != null && kif != (byte) 0xFF) || (kvc == null)) {
      return kif;
    }
    // CL-KEY-KIFUNK.1
    Byte result = cardSecuritySetting.getKif(writeAccessLevel, kvc);
    if (result == null) {
      result = cardSecuritySetting.getDefaultKif(writeAccessLevel);
    }
    return result;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SamTransactionManager processCommands() {
    // If there are pending SAM commands and the secure session is open and the "Digest Init"
    // command is not already executed, then we need to flush the session pending commands by
    // executing the pending "digest" commands "BEFORE" the other SAM commands to make sure that
    // between the session "Get Challenge" and the "Digest Init", there is no other command
    // inserted.
    if (!getSamCommands().isEmpty() && digestManager != null && !digestManager.isDigestInitDone) {
      List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>(getSamCommands());
      getSamCommands().clear();
      digestManager.prepareDigestInit();
      getSamCommands().addAll(samCommands);
    }
    return super.processCommands();
  }

  /**
   * (package-private)<br>
   * Prepares a "Get Challenge" SAM command.
   *
   * @return The reference to the prepared command.
   * @since 2.2.0
   */
  CmdSamGetChallenge prepareGetChallenge() {
    prepareSelectDiversifierIfNeeded();
    CmdSamGetChallenge cmd =
        new CmdSamGetChallenge(controlSam, targetCard.isExtendedModeSupported() ? 8 : 4);
    getSamCommands().add(cmd);
    return cmd;
  }

  /**
   * (package-private)<br>
   * Prepares a "Give Random" SAM command.
   *
   * @since 2.2.0
   */
  void prepareGiveRandom() {
    prepareSelectDiversifierIfNeeded();
    getSamCommands().add(new CmdSamGiveRandom(controlSam, targetCard.getCardChallenge()));
  }

  /**
   * (package-private)<br>
   * Prepares a "Card Generate Key" SAM command.
   *
   * @param cipheringKif The KIF of the key used for encryption.
   * @param cipheringKvc The KVC of the key used for encryption.
   * @param sourceKif The KIF of the key to encrypt.
   * @param sourceKvc The KVC of the key to encrypt.
   * @return The reference to the prepared command.
   * @since 2.2.0
   */
  CmdSamCardGenerateKey prepareCardGenerateKey(
      byte cipheringKif, byte cipheringKvc, byte sourceKif, byte sourceKvc) {
    CmdSamCardGenerateKey cmd =
        new CmdSamCardGenerateKey(controlSam, cipheringKif, cipheringKvc, sourceKif, sourceKvc);
    getSamCommands().add(cmd);
    return cmd;
  }

  /**
   * (package-private)<br>
   * Prepares a "Card Cipher Pin" SAM command.
   *
   * @param currentPin the current PIN value.
   * @param newPin the new PIN value (set to null if the operation is a PIN presentation).
   * @return The reference to the prepared command.
   * @since 2.2.0
   */
  CmdSamCardCipherPin prepareCardCipherPin(byte[] currentPin, byte[] newPin) {
    byte pinCipheringKif;
    byte pinCipheringKvc;
    if (digestManager != null && digestManager.sessionKif != 0) {
      // the current work key has been set (a secure session is open)
      pinCipheringKif = digestManager.sessionKif;
      pinCipheringKvc = digestManager.sessionKvc;
    } else {
      // no current work key is available (outside secure session)
      if (newPin == null) {
        // PIN verification
        if (cardSecuritySetting.getPinVerificationCipheringKif() == null
            || cardSecuritySetting.getPinVerificationCipheringKvc() == null) {
          throw new IllegalStateException(
              "No KIF or KVC defined for the PIN verification ciphering key");
        }
        pinCipheringKif = cardSecuritySetting.getPinVerificationCipheringKif();
        pinCipheringKvc = cardSecuritySetting.getPinVerificationCipheringKvc();
      } else {
        // PIN modification
        if (cardSecuritySetting.getPinModificationCipheringKif() == null
            || cardSecuritySetting.getPinModificationCipheringKvc() == null) {
          throw new IllegalStateException(
              "No KIF or KVC defined for the PIN modification ciphering key");
        }
        pinCipheringKif = cardSecuritySetting.getPinModificationCipheringKif();
        pinCipheringKvc = cardSecuritySetting.getPinModificationCipheringKvc();
      }
    }
    CmdSamCardCipherPin cmd =
        new CmdSamCardCipherPin(controlSam, pinCipheringKif, pinCipheringKvc, currentPin, newPin);
    getSamCommands().add(cmd);
    return cmd;
  }

  /**
   * (package-private)<br>
   * Prepares a "SV Prepare Load" SAM command.
   *
   * @param svGetHeader The SV Get command header.
   * @param svGetData The SV Get command response data.
   * @param cmdCardSvReload The SvDebit command providing the SvReload partial data.
   * @return The reference to the prepared command.
   * @since 2.2.0
   */
  CmdSamSvPrepareLoad prepareSvPrepareLoad(
      byte[] svGetHeader, byte[] svGetData, CmdCardSvReload cmdCardSvReload) {
    prepareSelectDiversifierIfNeeded();
    CmdSamSvPrepareLoad cmd =
        new CmdSamSvPrepareLoad(
            controlSam, svGetHeader, svGetData, cmdCardSvReload.getSvReloadData());
    getSamCommands().add(cmd);
    return cmd;
  }

  /**
   * (package-private)<br>
   * Prepares a "SV Prepare Debit/Undebit" SAM command.
   *
   * @param isDebitCommand True if the command is a DEBIT, false for UNDEBIT.
   * @param svGetHeader the SV Get command header.
   * @param svGetData the SV Get command response data.
   * @param cmdCardSvDebitOrUndebit The SvDebit or SvUndebit command providing the partial data.
   * @return The reference to the prepared command.
   * @since 2.2.0
   */
  CmdSamSvPrepareDebitOrUndebit prepareSvPrepareDebitOrUndebit(
      boolean isDebitCommand,
      byte[] svGetHeader,
      byte[] svGetData,
      CmdCardSvDebitOrUndebit cmdCardSvDebitOrUndebit) {
    prepareSelectDiversifierIfNeeded();
    CmdSamSvPrepareDebitOrUndebit cmd =
        new CmdSamSvPrepareDebitOrUndebit(
            isDebitCommand,
            controlSam,
            svGetHeader,
            svGetData,
            cmdCardSvDebitOrUndebit.getSvDebitOrUndebitData());
    getSamCommands().add(cmd);
    return cmd;
  }

  /**
   * (package-private)<br>
   * Prepares a "SV Check" SAM command.
   *
   * @param svOperationData The data of the SV operation performed.
   * @since 2.2.0
   */
  void prepareSvCheck(byte[] svOperationData) {
    getSamCommands().add(new CmdSamSvCheck(controlSam, svOperationData));
  }

  /**
   * (package-private)<br>
   * Opens a new session by initializing the digest manager. It will store all digest operations
   * (Digest Init, Digest Update) until the session closing. At this moment, all SAM Apdu will be
   * processed at once.
   *
   * @param openSecureSessionDataOut The data out of the "Open Secure Session" card command.
   * @param kif The KIF to use.
   * @param kvc The KVC to use.
   * @param isSessionEncrypted True if the session is encrypted.
   * @param isVerificationMode True if the verification mode is enabled.
   * @since 2.2.0
   */
  void initializeSession(
      byte[] openSecureSessionDataOut,
      byte kif,
      byte kvc,
      boolean isSessionEncrypted,
      boolean isVerificationMode) {
    digestManager =
        new DigestManager(
            openSecureSessionDataOut, kif, kvc, isSessionEncrypted, isVerificationMode);
  }

  /**
   * (package-private)<br>
   * Updates the session with the exchanged card APDUs.
   *
   * @param requests The card requests.
   * @param responses The associated card responses.
   * @param startIndex The index of the request from which to start.
   * @since 2.2.0
   */
  void updateSession(
      List<ApduRequestSpi> requests, List<ApduResponseApi> responses, int startIndex) {
    digestManager.updateSession(requests, responses, startIndex);
  }

  /**
   * (package-private)<br>
   * Prepares all pending digest commands in order to close the session.
   *
   * @return The reference to the prepared "Digest Close" SAM command.
   * @since 2.2.0
   */
  CmdSamDigestClose prepareSessionClosing() {
    digestManager.prepareCommands();
    digestManager = null;
    return (CmdSamDigestClose) getSamCommands().get(getSamCommands().size() - 1);
  }

  /**
   * (package-private)<br>
   * Prepares a "Digest Authenticate" SAM command.
   *
   * @param cardSignatureLo The card signature LO part.
   * @since 2.2.0
   */
  void prepareDigestAuthenticate(byte[] cardSignatureLo) {
    getSamCommands().add(new CmdSamDigestAuthenticate(controlSam, cardSignatureLo));
  }

  /**
   * (private)<br>
   * The manager of the digest session.
   */
  private class DigestManager {

    private final byte[] openSecureSessionDataOut;
    private final byte sessionKif;
    private final byte sessionKvc;
    private final boolean isSessionEncrypted;
    private final boolean isVerificationMode;
    private final List<byte[]> cardApdus = new ArrayList<byte[]>();
    private boolean isDigestInitDone;

    /**
     * (private)<br>
     * Creates a new digest manager.
     *
     * @param openSecureSessionDataOut The data out of the "Open Secure Session" card command.
     * @param kif The KIF to use.
     * @param kvc The KVC to use.
     * @param isSessionEncrypted True if the session is encrypted.
     * @param isVerificationMode True if the verification mode is enabled.
     */
    private DigestManager(
        byte[] openSecureSessionDataOut,
        byte kif,
        byte kvc,
        boolean isSessionEncrypted,
        boolean isVerificationMode) {
      this.openSecureSessionDataOut = openSecureSessionDataOut;
      this.sessionKif = kif;
      this.sessionKvc = kvc;
      this.isSessionEncrypted = isSessionEncrypted;
      this.isVerificationMode = isVerificationMode;
    }

    /**
     * (private)<br>
     * Add one or more exchanged card APDUs to the buffer.
     *
     * @param requests The requests.
     * @param responses The associated responses.
     * @param startIndex The index of the request from which to start.
     */
    private void updateSession(
        List<ApduRequestSpi> requests, List<ApduResponseApi> responses, int startIndex) {
      for (int i = startIndex; i < requests.size(); i++) {
        // If the request is of case4 type, LE must be excluded from the digest computation. In this
        // case, we remove here the last byte of the command buffer.
        // CL-C4-MAC.1
        ApduRequestSpi request = requests.get(i);
        cardApdus.add(
            ApduUtil.isCase4(request.getApdu())
                ? Arrays.copyOfRange(request.getApdu(), 0, request.getApdu().length - 1)
                : request.getApdu());
        ApduResponseApi response = responses.get(i);
        cardApdus.add(response.getApdu());
      }
    }

    /**
     * (private)<br>
     * Prepares all pending digest commands.
     */
    private void prepareCommands() {
      // Prepare the "Digest Init" command if not already done.
      if (!isDigestInitDone) {
        prepareDigestInit();
      }
      // Prepare the "Digest Update" commands and flush the buffer.
      prepareDigestUpdate();
      cardApdus.clear();
      // Prepare the "Digest Close" command.
      prepareDigestClose();
    }

    /**
     * (private)<br>
     * Prepares the "Digest Init" SAM command.
     */
    private void prepareDigestInit() {
      // CL-SAM-DINIT.1
      getSamCommands()
          .add(
              new CmdSamDigestInit(
                  controlSam,
                  isVerificationMode,
                  targetCard.isExtendedModeSupported(),
                  sessionKif,
                  sessionKvc,
                  openSecureSessionDataOut));
      isDigestInitDone = true;
    }

    /**
     * (private)<br>
     * Prepares the "Digest Update" SAM command.
     */
    private void prepareDigestUpdate() {
      if (cardApdus.isEmpty()) {
        return;
      }
      // CL-SAM-DUPDATE.1
      if (controlSam.getProductType() == CalypsoSam.ProductType.SAM_C1) {
        // Digest Update Multiple
        // Construct list of DataIn
        List<byte[]> digestDataList = new ArrayList<byte[]>(1);
        byte[] buffer = new byte[255];
        int i = 0;
        for (byte[] cardApdu : cardApdus) {
          if (i + cardApdu.length > 254) {
            // Copy buffer to digestDataList and reset buffer
            digestDataList.add(Arrays.copyOf(buffer, i));
            i = 0;
          }
          // Add [length][apdu] to current buffer
          buffer[i++] = (byte) cardApdu.length;
          System.arraycopy(cardApdu, 0, buffer, i, cardApdu.length);
          i += cardApdu.length;
        }
        // Copy buffer to digestDataList
        digestDataList.add(Arrays.copyOf(buffer, i));
        // Add commands
        for (byte[] dataIn : digestDataList) {
          getSamCommands().add(new CmdSamDigestUpdateMultiple(controlSam, dataIn));
        }
      } else {
        // Digest Update (simple)
        for (byte[] cardApdu : cardApdus) {
          getSamCommands().add(new CmdSamDigestUpdate(controlSam, isSessionEncrypted, cardApdu));
        }
      }
    }

    /**
     * (private)<br>
     * Prepares the "Digest Close" SAM command.
     */
    private void prepareDigestClose() {
      // CL-SAM-DCLOSE.1
      getSamCommands()
          .add(new CmdSamDigestClose(controlSam, targetCard.isExtendedModeSupported() ? 8 : 4));
    }
  }
}
