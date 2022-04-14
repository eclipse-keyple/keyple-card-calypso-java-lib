/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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
import org.calypsonet.terminal.calypso.transaction.InconsistentDataException;
import org.calypsonet.terminal.card.*;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * The SamCommandProcessor class is dedicated to the management of commands sent to the SAM.
 *
 * <p>In particular, it manages the cryptographic computations related to the secure session (digest
 * computation).
 *
 * <p>It also will integrate the SAM commands used for Stored Value and PIN/key management. In
 * session, these commands need to be carefully synchronized with the digest calculation.
 *
 * @since 2.0.0
 */
class SamCommandProcessor {

  private static final Logger logger = LoggerFactory.getLogger(SamCommandProcessor.class);

  private static final byte KIF_UNDEFINED = (byte) 0xFF;
  private static final byte CHALLENGE_LENGTH_REV_INF_32 = (byte) 0x04;
  private static final byte CHALLENGE_LENGTH_REV32 = (byte) 0x08;
  private static final byte SIGNATURE_LENGTH_REV_INF_32 = (byte) 0x04;
  private static final byte SIGNATURE_LENGTH_REV32 = (byte) 0x08;

  private final ProxyReaderApi samReader;
  private final CardSecuritySettingAdapter securitySetting;
  private final CalypsoCardAdapter card;
  private final byte[] samSerialNumber;
  private final CalypsoSam.ProductType samProductType;
  private boolean isSessionEncrypted;
  private boolean isVerificationMode;
  private byte kif;
  private byte kvc;
  private boolean isDigesterInitialized;
  private boolean isDiversificationDone;
  private boolean isDigestInitDone;
  private final List<byte[]> cardDigestDataCache = new ArrayList<byte[]>();
  private final List<byte[]> transactionAuditData;

  /**
   * (package-private)<br>
   * Constructor
   *
   * @param card The initial card data provided by the selection process.
   * @param securitySetting The security settings from the application layer.
   * @param transactionAuditData The transaction audit data list to fill.
   * @since 2.0.0
   */
  SamCommandProcessor(
      CalypsoCardAdapter card,
      CardSecuritySettingAdapter securitySetting,
      List<byte[]> transactionAuditData) {

    Assert.getInstance()
        .notNull(securitySetting.getControlSamReader(), "controlSamReader")
        .notNull(securitySetting.getControlSam(), "controlSam");

    this.card = card;
    this.securitySetting = securitySetting;
    CalypsoSam sam = securitySetting.getControlSam();
    this.samProductType = sam.getProductType();
    this.samSerialNumber = sam.getSerialNumber();
    this.samReader = securitySetting.getControlSamReader();
    this.transactionAuditData = transactionAuditData;
  }

  /**
   * Gets the SAM challenge
   *
   * <p>Performs key diversification if necessary by sending the SAM Select Diversifier command
   * prior to the Get Challenge command. The diversification flag is set to avoid further
   * unnecessary diversification operations.
   *
   * <p>If the key diversification is already done, the Select Diversifier command is omitted.
   *
   * <p>The length of the challenge varies from one card product type to another. This information
   * can be found in the CardResource class field.
   *
   * @return the terminal challenge as an array of bytes
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @throws InconsistentDataException if the APDU SAM exchanges are out of sync.
   * @since 2.0.0
   */
  byte[] getChallenge()
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {

    List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>();

    // diversify only if this has not already been done.
    if (!isDiversificationDone) {
      // build the "Select Diversifier" SAM command to provide the SAM with the card S/N
      // CL-SAM-CSN.1
      samCommands.add(
          new CmdSamSelectDiversifier(samProductType, card.getCalypsoSerialNumberFull()));
      // note that the diversification has been made
      isDiversificationDone = true;
    }

    // build the "Get Challenge" SAM command
    byte challengeLength =
        card.isExtendedModeSupported() ? CHALLENGE_LENGTH_REV32 : CHALLENGE_LENGTH_REV_INF_32;
    CmdSamGetChallenge cmdSamGetChallenge = new CmdSamGetChallenge(samProductType, challengeLength);
    samCommands.add(cmdSamGetChallenge);

    // Transmit the commands to the SAM
    transmitCommands(samCommands);

    // Retrieve the SAM challenge
    byte[] samChallenge = cmdSamGetChallenge.getChallenge();
    if (logger.isDebugEnabled()) {
      logger.debug("identification: TERMINALCHALLENGE={}", HexUtil.toHex(samChallenge));
    }
    return samChallenge;
  }

  /**
   * (package-private)<br>
   * Gets the KVC to use according to the provided write access and the card's KVC.
   *
   * @param writeAccessLevel The write access level.
   * @param kvc The card KVC value.
   * @return Null if the card did not provide a KVC value and if there's no default KVC value.
   * @since 2.0.0
   */
  Byte computeKvc(WriteAccessLevel writeAccessLevel, Byte kvc) {
    if (kvc != null) {
      return kvc;
    }
    return securitySetting.getDefaultKvc(writeAccessLevel);
  }

  /**
   * (package-private)<br>
   * Gets the KIF to use according to the provided write access level and KVC.
   *
   * @param writeAccessLevel The write access level.
   * @param kif The card KIF value.
   * @param kvc The previously computed KVC value.
   * @return Null if the card did not provide a KIF value and if there's no default KIF value.
   * @since 2.0.0
   */
  Byte computeKif(WriteAccessLevel writeAccessLevel, Byte kif, Byte kvc) {
    // CL-KEY-KIF.1
    if ((kif != null && kif != KIF_UNDEFINED) || (kvc == null)) {
      return kif;
    }
    // CL-KEY-KIFUNK.1
    Byte result = securitySetting.getKif(writeAccessLevel, kvc);
    if (result == null) {
      result = securitySetting.getDefaultKif(writeAccessLevel);
    }
    return result;
  }

  /**
   * Initializes the digest computation process
   *
   * <p>Resets the digest data cache, then fills a first packet with the provided data (from open
   * secure session).
   *
   * <p>Keeps the session parameters, sets the KIF if not defined
   *
   * <p>Note: there is no communication with the SAM here.
   *
   * @param isSessionEncrypted true if the session is encrypted.
   * @param isVerificationMode true if the verification mode is active.
   * @param kif the KIF.
   * @param kvc the KVC.
   * @param digestData a first packet of data to digest.
   * @since 2.0.0
   */
  void initializeDigester(
      boolean isSessionEncrypted,
      boolean isVerificationMode,
      byte kif,
      byte kvc,
      byte[] digestData) {

    this.isSessionEncrypted = isSessionEncrypted;
    this.isVerificationMode = isVerificationMode;
    this.kif = kif;
    this.kvc = kvc;

    if (logger.isDebugEnabled()) {
      logger.debug(
          "initialize: CARDREVISION={}, SAMREVISION={}, SESSIONENCRYPTION={}, VERIFICATIONMODE={}",
          card.getProductType(),
          samProductType,
          isSessionEncrypted,
          isVerificationMode);
      logger.debug(
          "initialize: VERIFICATIONMODE={}, REV32MODE={}",
          isVerificationMode,
          card.isExtendedModeSupported());
      logger.debug(
          "initialize: KIF={}, KVC={}, DIGESTDATA={}",
          String.format("%02Xh", kif),
          String.format("%02Xh", kvc),
          HexUtil.toHex(digestData));
    }

    // Clear data cache
    cardDigestDataCache.clear();

    // Build Digest Init command as first ApduRequestAdapter of the digest computation process
    cardDigestDataCache.add(digestData);

    isDigestInitDone = false;
    isDigesterInitialized = true;
  }

  /**
   * Appends a full card exchange (request and response) to the digest data cache.
   *
   * @param request card request.
   * @param response card response.
   * @since 2.0.0
   */
  private void pushCardExchangedData(ApduRequestSpi request, ApduResponseApi response) {

    if (logger.isTraceEnabled()) {
      logger.trace("pushCardExchangedData: {}", request);
    }

    // Add an ApduRequestAdapter to the digest computation: if the request is of case4 type, Le must
    // be excluded from the digest computation. In this cas, we remove here the last byte of the
    // command buffer.
    // CL-C4-MAC.1
    if (ApduUtil.isCase4(request.getApdu())) {
      cardDigestDataCache.add(
          Arrays.copyOfRange(request.getApdu(), 0, request.getApdu().length - 1));
    } else {
      cardDigestDataCache.add(request.getApdu());
    }

    if (logger.isTraceEnabled()) {
      logger.trace("pushCardExchangedData: {}", response);
    }

    // Add an ApduResponseApi to the digest computation
    cardDigestDataCache.add(response.getApdu());
  }

  /**
   * Appends a list full card exchange (request and response) to the digest data cache.<br>
   * The startIndex argument makes it possible not to include the beginning of the list when
   * necessary.
   *
   * @param requests card request list.
   * @param responses card response list.
   * @param startIndex starting point in the list.
   * @since 2.0.0
   */
  void pushCardExchangedData(
      List<ApduRequestSpi> requests, List<ApduResponseApi> responses, int startIndex) {
    for (int i = startIndex; i < requests.size(); i++) {
      // Add requests and responses to the digest processor
      pushCardExchangedData(requests.get(i), responses.get(i));
    }
  }

  /**
   * Gets a single SAM request for all prepared SAM commands.
   *
   * <p>Builds all pending SAM commands related to the digest calculation process of a secure
   * session
   *
   * <ul>
   *   <li>Starts with a Digest Init command if not already done,
   *   <li>Adds as many Digest Update commands as there are packages in the cache,
   *   <li>Appends a Digest Close command if the addDigestClose flag is set to true.
   * </ul>
   *
   * @param addDigestClose indicates whether to add the Digest Close command.
   * @return a list of commands to send to the SAM
   * @since 2.0.0
   */
  private List<AbstractSamCommand> getPendingSamCommands(boolean addDigestClose) {
    // TODO optimization with the use of Digest Update Multiple whenever possible.
    List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>();

    // sanity checks
    if (cardDigestDataCache.isEmpty()) {
      logger.debug("getSamDigestRequest: no data in cache.");
      throw new IllegalStateException("Digest data cache is empty.");
    }

    if (!isDigestInitDone && cardDigestDataCache.size() % 2 == 0) {
      // the number of buffers should be 2*n + 1
      logger.debug(
          "getSamDigestRequest: wrong number of buffer in cache NBR = {}.",
          cardDigestDataCache.size());
      throw new IllegalStateException("Digest data cache is inconsistent.");
    }

    if (!isDigestInitDone) {
      // Build and append Digest Init command as first ApduRequestAdapter of the digest computation
      // process. The Digest Init command comes from the Open Secure Session response from the
      // card. Once added to the ApduRequestAdapter list, the data is remove from the cache to keep
      // only couples of card request/response
      // CL-SAM-DINIT.1
      samCommands.add(
          new CmdSamDigestInit(
              samProductType,
              isVerificationMode,
              card.isExtendedModeSupported(),
              kif,
              kvc,
              cardDigestDataCache.get(0)));
      cardDigestDataCache.remove(0);
      // note that the digest init has been made
      isDigestInitDone = true;
    }

    // Build and append Digest Update commands
    // CL-SAM-DUPDATE.1
    for (byte[] bytes : cardDigestDataCache) {
      samCommands.add(new CmdSamDigestUpdate(samProductType, isSessionEncrypted, bytes));
    }

    // clears cached commands once they have been processed
    cardDigestDataCache.clear();

    if (addDigestClose) {
      // Build and append Digest Close command
      // CL-SAM-DCLOSE.1
      samCommands.add(
          (new CmdSamDigestClose(
              samProductType,
              card.isExtendedModeSupported()
                  ? SIGNATURE_LENGTH_REV32
                  : SIGNATURE_LENGTH_REV_INF_32)));
    }

    return samCommands;
  }

  /**
   * (package-private)<br>
   * Gets the terminal signature's high part from the SAM
   *
   * <p>All remaining data in the digest cache is sent to the SAM and the Digest Close command is
   * executed.
   *
   * @return The terminal signature's high part.
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @throws InconsistentDataException if the APDU SAM exchanges are out of sync.
   * @since 2.0.0
   */
  byte[] getTerminalSignature()
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {

    // All remaining SAM digest operations will now run at once.
    // Get the SAM Digest request including Digest Close from the cache manager
    List<AbstractSamCommand> samCommands = getPendingSamCommands(true);

    // Transmit the commands to the SAM
    transmitCommands(samCommands);

    // Get Terminal Signature from the latest response
    byte[] terminalSignature =
        ((CmdSamDigestClose) samCommands.get(samCommands.size() - 1)).getSignature();

    if (logger.isDebugEnabled()) {
      logger.debug("SIGNATURE={}", HexUtil.toHex(terminalSignature));
    }

    return terminalSignature;
  }

  /**
   * (private)<br>
   * Transmits the provided commands to the SAM, then attach responses and check status words.
   *
   * @param samCommands The SAM commands.
   * @throws ReaderBrokenCommunicationException If the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException If the communication with the SAM has failed.
   * @throws CalypsoSamCommandException If the SAM has responded with an error status.
   * @throws InconsistentDataException If the APDU SAM exchanges are out of sync.
   */
  private void transmitCommands(List<AbstractSamCommand> samCommands)
      throws ReaderBrokenCommunicationException, CardBrokenCommunicationException,
          CalypsoSamCommandException {

    List<ApduRequestSpi> apduRequests = getApduRequests(samCommands);
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, true);
    CardResponseApi cardResponse = null;
    try {
      cardResponse = samReader.transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);
    } catch (ReaderBrokenCommunicationException e) {
      cardResponse = e.getCardResponse();
      throw e;
    } catch (CardBrokenCommunicationException e) {
      cardResponse = e.getCardResponse();
      throw e;
    } catch (UnexpectedStatusWordException e) {
      if (logger.isDebugEnabled()) {
        logger.debug("A SAM card command has failed: {}", e.getMessage());
      }
      cardResponse = e.getCardResponse();
    } finally {
      CardTransactionManagerAdapter.saveTransactionAuditData(
          cardRequest, cardResponse, transactionAuditData);
    }
    List<ApduResponseApi> apduResponses = cardResponse.getApduResponses();

    // If there are more responses than requests, then we are unable to fill the card image. In this
    // case we stop processing immediately because it may be a case of fraud, and we throw a
    // desynchronized exception.
    if (apduResponses.size() > apduRequests.size()) {
      throw new InconsistentDataException(
          "The number of SAM commands/responses does not match: nb commands = "
              + apduRequests.size()
              + ", nb responses = "
              + apduResponses.size());
    }

    // We go through all the responses (and not the requests) because there may be fewer in the case
    // of an error that occurred in strict mode. In this case the last response will raise an
    // exception.
    for (int i = 0; i < apduResponses.size(); i++) {
      samCommands.get(i).setApduResponse(apduResponses.get(i)).checkStatus();
    }

    // Finally, if no error has occurred and there are fewer responses than requests, then we
    // throw a desynchronized exception.
    if (apduResponses.size() < apduRequests.size()) {
      throw new InconsistentDataException(
          "The number of SAM commands/responses does not match: nb commands = "
              + apduRequests.size()
              + ", nb responses = "
              + apduResponses.size());
    }
  }

  /**
   * Authenticates the signature part from the card
   *
   * <p>Executes the Digest Authenticate command with the card part of the signature.
   *
   * @param cardSignatureLo the card part of the signature.
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @throws InconsistentDataException if the APDU SAM exchanges are out of sync.
   * @since 2.0.0
   */
  void authenticateCardSignature(byte[] cardSignatureLo)
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {

    List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>(1);
    samCommands.add(new CmdSamDigestAuthenticate(samProductType, cardSignatureLo));
    transmitCommands(samCommands);
  }

  /**
   * Create an ApduRequestAdapter List from a AbstractSamCommand List.
   *
   * @param samCommands a list of SAM commands.
   * @return the ApduRequestAdapter list
   * @since 2.0.0
   */
  private List<ApduRequestSpi> getApduRequests(List<AbstractSamCommand> samCommands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    if (samCommands != null) {
      for (AbstractSamCommand samCommand : samCommands) {
        apduRequests.add(samCommand.getApduRequest());
      }
    }
    return apduRequests;
  }

  /**
   * (package-private)<br>
   * Compute the encrypted key data for the "Change Key" command.
   *
   * @param cardChallenge The challenge from the card.
   * @param cipheringKif The KIF of the key used for encryption.
   * @param cipheringKvc The KVC of the key used for encryption.
   * @param sourceKif The KIF of the key to encrypt.
   * @param sourceKvc The KVC of the key to encrypt.
   * @return An array of 32 bytes containing the encrypted key.
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @since 2.1.0
   */
  byte[] getEncryptedKey(
      byte[] cardChallenge, byte cipheringKif, byte cipheringKvc, byte sourceKif, byte sourceKvc)
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {

    List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>();

    if (!isDiversificationDone) {
      // Build the SAM Select Diversifier command to provide the SAM with the card S/N
      // CL-SAM-CSN.1
      samCommands.add(
          new CmdSamSelectDiversifier(samProductType, card.getCalypsoSerialNumberFull()));
      isDiversificationDone = true;
    }

    samCommands.add(new CmdSamGiveRandom(samProductType, cardChallenge));

    CmdSamCardGenerateKey cmdSamCardGenerateKey =
        new CmdSamCardGenerateKey(samProductType, cipheringKif, cipheringKvc, sourceKif, sourceKvc);
    samCommands.add(cmdSamCardGenerateKey);

    // Transmit the commands to the SAM
    transmitCommands(samCommands);

    return cmdSamCardGenerateKey.getCipheredData();
  }

  /**
   * (package-private)<br>
   * Compute the PIN ciphered data for the encrypted PIN verification or PIN update commands
   *
   * @param cardChallenge the challenge from the card.
   * @param currentPin the current PIN value.
   * @param newPin the new PIN value (set to null if the operation is a PIN presentation).
   * @return the PIN ciphered data
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @since 2.0.0
   */
  byte[] getCipheredPinData(byte[] cardChallenge, byte[] currentPin, byte[] newPin)
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {

    List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>();
    byte pinCipheringKif;
    byte pinCipheringKvc;

    if (kif != 0) {
      // the current work key has been set (a secure session is open)
      pinCipheringKif = kif;
      pinCipheringKvc = kvc;
    } else {
      // no current work key is available (outside secure session)
      if (newPin == null) {
        // PIN verification
        if (securitySetting.getPinVerificationCipheringKif() == null
            || securitySetting.getPinVerificationCipheringKvc() == null) {
          throw new IllegalStateException(
              "No KIF or KVC defined for the PIN verification ciphering key");
        }
        pinCipheringKif = securitySetting.getPinVerificationCipheringKif();
        pinCipheringKvc = securitySetting.getPinVerificationCipheringKvc();
      } else {
        // PIN modification
        if (securitySetting.getPinModificationCipheringKif() == null
            || securitySetting.getPinModificationCipheringKvc() == null) {
          throw new IllegalStateException(
              "No KIF or KVC defined for the PIN modification ciphering key");
        }
        pinCipheringKif = securitySetting.getPinModificationCipheringKif();
        pinCipheringKvc = securitySetting.getPinModificationCipheringKvc();
      }
    }

    if (!isDiversificationDone) {
      // Build the SAM Select Diversifier command to provide the SAM with the card S/N
      // CL-SAM-CSN.1
      samCommands.add(
          new CmdSamSelectDiversifier(samProductType, card.getCalypsoSerialNumberFull()));
      isDiversificationDone = true;
    }

    if (isDigesterInitialized) {
      /* Get the pending SAM ApduRequestAdapter and add it to the current ApduRequestAdapter list */
      samCommands.addAll(getPendingSamCommands(false));
    }

    samCommands.add(new CmdSamGiveRandom(samProductType, cardChallenge));

    CmdSamCardCipherPin cmdSamCardCipherPin =
        new CmdSamCardCipherPin(
            samProductType, pinCipheringKif, pinCipheringKvc, currentPin, newPin);
    samCommands.add(cmdSamCardCipherPin);

    transmitCommands(samCommands);

    return cmdSamCardCipherPin.getCipheredData();
  }

  /**
   * Generic method to get the complementary data from SvPrepareLoad/Debit/Undebit commands
   *
   * <p>Executes the SV Prepare SAM command to prepare the data needed to complete the card SV
   * command.
   *
   * <p>This data comprises:
   *
   * <ul>
   *   <li>The SAM identifier (4 bytes)
   *   <li>The SAM challenge (3 bytes)
   *   <li>The SAM transaction number (3 bytes)
   *   <li>The SAM part of the SV signature (5 or 10 bytes depending on card mode)
   * </ul>
   *
   * @param cmdSamSvPrepare the prepare command (can be prepareSvReload/Debit/Undebit).
   * @return a byte array containing the complementary data
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @since 2.0.0
   */
  private byte[] getSvComplementaryData(AbstractSamCommand cmdSamSvPrepare)
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {

    List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>();

    if (!isDiversificationDone) {
      /* Build the SAM Select Diversifier command to provide the SAM with the card S/N */
      // CL-SAM-CSN.1
      samCommands.add(
          new CmdSamSelectDiversifier(samProductType, card.getCalypsoSerialNumberFull()));
      isDiversificationDone = true;
    }

    if (isDigesterInitialized) {
      /* Get the pending SAM ApduRequestAdapter and add it to the current ApduRequestAdapter list */
      samCommands.addAll(getPendingSamCommands(false));
    }

    samCommands.add(cmdSamSvPrepare);

    transmitCommands(samCommands);

    byte[] prepareOperationData = cmdSamSvPrepare.getApduResponse().getDataOut();

    byte[] operationComplementaryData =
        new byte[samSerialNumber.length + prepareOperationData.length];

    System.arraycopy(samSerialNumber, 0, operationComplementaryData, 0, samSerialNumber.length);
    System.arraycopy(
        prepareOperationData,
        0,
        operationComplementaryData,
        samSerialNumber.length,
        prepareOperationData.length);

    return operationComplementaryData;
  }

  /**
   * Computes the cryptographic data required for the SvReload command.
   *
   * <p>Use the data from the SvGet command and the partial data from the SvReload command for this
   * purpose.
   *
   * <p>The returned data will be used to finalize the card SvReload command.
   *
   * @param cmdCardSvReload the SvDebit command providing the SvReload partial data.
   * @param svGetHeader the SV Get command header.
   * @param svGetData the SV Get command response data.
   * @return the complementary security data to finalize the SvReload card command (sam ID + SV
   *     prepare load output)
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @since 2.0.0
   */
  byte[] getSvReloadComplementaryData(
      CmdCardSvReload cmdCardSvReload, byte[] svGetHeader, byte[] svGetData)
      throws CalypsoSamCommandException, ReaderBrokenCommunicationException,
          CardBrokenCommunicationException {

    CmdSamSvPrepareLoad cmdSamSvPrepareLoad =
        new CmdSamSvPrepareLoad(
            samProductType, svGetHeader, svGetData, cmdCardSvReload.getSvReloadData());

    return getSvComplementaryData(cmdSamSvPrepareLoad);
  }

  /**
   * (package-private)<br>
   * Computes the cryptographic data required for the SvDebit or SvUndebit command.
   *
   * <p>Use the data from the SvGet command and the partial data from the SvDebit command for this
   * purpose.
   *
   * <p>The returned data will be used to finalize the card SvDebit command.
   *
   * @param isDebitCommand True if the command is a DEBIT, false for UNDEBIT.
   * @param svGetHeader the SV Get command header.
   * @param svGetData the SV Get command response data.
   * @return the complementary security data to finalize the SvDebit/SvUndebit card command (sam ID
   *     + SV prepare debit/debit output)
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @since 2.0.0
   */
  byte[] getSvDebitOrUndebitComplementaryData(
      boolean isDebitCommand,
      CmdCardSvDebitOrUndebit cmdCardSvDebitOrUndebit,
      byte[] svGetHeader,
      byte[] svGetData)
      throws CalypsoSamCommandException, ReaderBrokenCommunicationException,
          CardBrokenCommunicationException {

    CmdSamSvPrepareDebitOrUndebit cmdSamSvPrepareDebitOrUndebit =
        new CmdSamSvPrepareDebitOrUndebit(
            isDebitCommand,
            samProductType,
            svGetHeader,
            svGetData,
            cmdCardSvDebitOrUndebit.getSvDebitOrUndebitData());

    return getSvComplementaryData(cmdSamSvPrepareDebitOrUndebit);
  }

  /**
   * Checks the status of the last SV operation
   *
   * <p>The card signature is compared by the SAM with the one it has computed on its side.
   *
   * @param svOperationResponseData the data of the SV operation performed.
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @since 2.0.0
   */
  void checkSvStatus(byte[] svOperationResponseData)
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {

    List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>();
    samCommands.add(new CmdSamSvCheck(samProductType, svOperationResponseData));
    transmitCommands(samCommands);
  }
}
