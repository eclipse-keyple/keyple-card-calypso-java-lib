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
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.transaction.CardSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.DesynchronizedExchangesException;
import org.calypsonet.terminal.card.*;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
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
 * @since 2.0
 */
class SamCommandProcessor {
  private static final Logger logger = LoggerFactory.getLogger(SamCommandProcessor.class);

  private static final byte KIF_UNDEFINED = (byte) 0xFF;

  private static final byte CHALLENGE_LENGTH_REV_INF_32 = (byte) 0x04;
  private static final byte CHALLENGE_LENGTH_REV32 = (byte) 0x08;
  private static final byte SIGNATURE_LENGTH_REV_INF_32 = (byte) 0x04;
  private static final byte SIGNATURE_LENGTH_REV32 = (byte) 0x08;
  private static final String UNEXPECTED_EXCEPTION = "An unexpected exception was raised.";

  private final ProxyReaderApi samReader;
  private final CardSecuritySetting cardSecuritySettings;
  private static final List<byte[]> cardDigestDataCache = new ArrayList<byte[]>();
  private final CalypsoCardAdapter calypsoCard;
  private final byte[] samSerialNumber;
  private final CalypsoSam.ProductType samProductType;
  private boolean sessionEncryption;
  private boolean verificationMode;
  private byte kif;
  private byte kvc;
  private boolean isDiversificationDone;
  private boolean isDigestInitDone;
  private boolean isDigesterInitialized;

  /**
   * Constructor
   *
   * @param calypsoCard The initial card data provided by the selection process.
   * @param cardSecuritySetting the security settings from the application layer.
   * @since 2.0
   */
  SamCommandProcessor(CalypsoCard calypsoCard, CardSecuritySetting cardSecuritySetting) {

    Assert.getInstance()
        .notNull(cardSecuritySetting.getSamReader(), "samReader")
        .notNull(cardSecuritySetting.getCalypsoSam(), "calypsoSam");

    this.calypsoCard = (CalypsoCardAdapter) calypsoCard;
    this.cardSecuritySettings = cardSecuritySetting;
    CalypsoSam calypsoSam = cardSecuritySettings.getCalypsoSam();
    samProductType = calypsoSam.getProductType();
    samSerialNumber = calypsoSam.getSerialNumber();
    samReader = (ProxyReaderApi) cardSecuritySettings.getSamReader();
  }

  /**
   * Gets the terminal challenge
   *
   * <p>Performs key diversification if necessary by sending the SAM Select Diversifier command
   * prior to the Get Challenge command. The diversification flag is set to avoid further
   * unnecessary diversification operations.
   *
   * <p>If the key diversification is already done, the Select Diversifier command is omitted.
   *
   * <p>The length of the challenge varies from one card revision to another. This information can
   * be found in the CardResource class field.
   *
   * @return the terminal challenge as an array of bytes
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @throws DesynchronizedExchangesException if the APDU SAM exchanges are out of sync
   * @since 2.0
   */
  byte[] getSessionTerminalChallenge()
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();

    // diversify only if this has not already been done.
    if (!isDiversificationDone) {
      // build the SAM Select Diversifier command to provide the SAM with the card S/N
      AbstractApduCommandBuilder selectDiversifier =
          new SamSelectDiversifierBuilder(samProductType, calypsoCard.getCalypsoSerialNumberFull());

      apduRequests.add(selectDiversifier.getApduRequest());

      // note that the diversification has been made
      isDiversificationDone = true;
    }

    // build the SAM Get Challenge command
    byte challengeLength =
        calypsoCard.isExtendedModeSupported()
            ? CHALLENGE_LENGTH_REV32
            : CHALLENGE_LENGTH_REV_INF_32;

    AbstractSamCommandBuilder<? extends AbstractSamResponseParser> samGetChallengeBuilder =
        new SamGetChallengeBuilder(samProductType, challengeLength);

    apduRequests.add(samGetChallengeBuilder.getApduRequest());

    // Transmit the CardRequest to the SAM and get back the CardResponse (list of ApduResponseApi)
    CardResponseApi samCardResponse;
    try {
      samCardResponse =
          samReader.transmitCardRequest(
              new CardRequestAdapter(apduRequests, false), ChannelControl.KEEP_OPEN);
    } catch (UnexpectedStatusWordException e) {
      throw new IllegalStateException(UNEXPECTED_EXCEPTION, e);
    }

    List<ApduResponseApi> samApduResponses = samCardResponse.getApduResponses();
    byte[] sessionTerminalChallenge;

    int numberOfSamCmd = apduRequests.size();
    if (samApduResponses.size() == numberOfSamCmd) {
      SamGetChallengeParser samGetChallengeParser =
          (SamGetChallengeParser)
              samGetChallengeBuilder.createResponseParser(samApduResponses.get(numberOfSamCmd - 1));

      samGetChallengeParser.checkStatus();

      sessionTerminalChallenge = samGetChallengeParser.getChallenge();
      if (logger.isDebugEnabled()) {
        logger.debug(
            "identification: TERMINALCHALLENGE = {}",
            ByteArrayUtil.toHex(sessionTerminalChallenge));
      }
    } else {
      throw new DesynchronizedExchangesException(
          "The number of commands/responses does not match: cmd="
              + numberOfSamCmd
              + ", resp="
              + samApduResponses.size());
    }
    return sessionTerminalChallenge;
  }

  /**
   * (package-private)<br>
   * Gets the KVC to use according to the provided write access and the card's KVC.
   *
   * @param writeAccessLevel The write access level.
   * @param kvc The card KVC value.
   * @return Null if the card did not provided a KVC value and if there's no default KVC value.
   * @since 2.0
   */
  Byte computeKvc(WriteAccessLevel writeAccessLevel, Byte kvc) {
    if (kvc != null) {
      return kvc;
    }
    return ((CardSecuritySettingAdapter) cardSecuritySettings).getDefaultKvc(writeAccessLevel);
  }

  /**
   * (package-private)<br>
   * Gets the KIF to use according to the provided write access level and KVC.
   *
   * @param writeAccessLevel The write access level.
   * @param kif The card KIF value.
   * @param kvc The previously computed KVC value.
   * @return Null if the card did not provided a KIF value and if there's no default KIF value.
   * @since 2.0
   */
  Byte computeKif(WriteAccessLevel writeAccessLevel, Byte kif, Byte kvc) {
    if ((kif != null && kif != KIF_UNDEFINED) || (kvc == null)) {
      return kif;
    }
    Byte result = ((CardSecuritySettingAdapter) cardSecuritySettings).getKif(writeAccessLevel, kvc);
    if (result == null) {
      result = ((CardSecuritySettingAdapter) cardSecuritySettings).getDefaultKif(writeAccessLevel);
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
   * @param sessionEncryption true if the session is encrypted.
   * @param verificationMode true if the verification mode is active.
   * @param kif the KIF.
   * @param kvc the KVC.
   * @param digestData a first packet of data to digest.
   * @since 2.0
   */
  void initializeDigester(
      boolean sessionEncryption, boolean verificationMode, byte kif, byte kvc, byte[] digestData) {

    this.sessionEncryption = sessionEncryption;
    this.verificationMode = verificationMode;
    this.kif = kif;
    this.kvc = kvc;

    if (logger.isDebugEnabled()) {
      logger.debug(
          "initialize: POREVISION = {}, SAMREVISION = {}, SESSIONENCRYPTION = {}, VERIFICATIONMODE = {}",
          calypsoCard.getProductType(),
          samProductType,
          sessionEncryption,
          verificationMode);
      logger.debug(
          "initialize: VERIFICATIONMODE = {}, REV32MODE = {}",
          verificationMode,
          calypsoCard.isExtendedModeSupported());
      logger.debug(
          "initialize: KIF = {}, KVC {}, DIGESTDATA = {}",
          String.format("%02X", kif),
          String.format("%02X", kvc),
          ByteArrayUtil.toHex(digestData));
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
   * @since 2.0
   */
  private void pushCardExchangedData(ApduRequestSpi request, ApduResponseApi response) {

    logger.trace("pushCardExchangedData: REQUEST = {}", request);

    // Add an ApduRequestAdapter to the digest computation: if the request is of case4 type, Le must
    // be
    // excluded from the digest computation. In this cas, we remove here the last byte of the
    // command buffer.
    if (ApduUtil.isCase4(request.getApdu())) {
      cardDigestDataCache.add(
          Arrays.copyOfRange(request.getApdu(), 0, request.getApdu().length - 1));
    } else {
      cardDigestDataCache.add(request.getApdu());
    }

    logger.trace("pushCardExchangedData: RESPONSE = {}", response);

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
   * @since 2.0
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
   * @since 2.0
   */
  private List<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>>
      getPendingSamCommands(boolean addDigestClose) {
    // TODO optimization with the use of Digest Update Multiple whenever possible.
    List<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>> samCommands =
        new ArrayList<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>>();

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
      samCommands.add(
          new SamDigestInitBuilder(
              samProductType,
              verificationMode,
              calypsoCard.isExtendedModeSupported(),
              kif,
              kvc,
              cardDigestDataCache.get(0)));
      cardDigestDataCache.remove(0);
      // note that the digest init has been made
      isDigestInitDone = true;
    }

    // Build and append Digest Update commands
    for (int i = 0; i < cardDigestDataCache.size(); i++) {
      samCommands.add(
          new SamDigestUpdateBuilder(
              samProductType, sessionEncryption, cardDigestDataCache.get(i)));
    }

    // clears cached commands once they have been processed
    cardDigestDataCache.clear();

    if (addDigestClose) {
      // Build and append Digest Close command
      samCommands.add(
          (new SamDigestCloseBuilder(
              samProductType,
              calypsoCard.isExtendedModeSupported()
                  ? SIGNATURE_LENGTH_REV32
                  : SIGNATURE_LENGTH_REV_INF_32)));
    }

    return samCommands;
  }

  /**
   * Gets the terminal signature from the SAM
   *
   * <p>All remaining data in the digest cache is sent to the SAM and the Digest Close command is
   * executed.
   *
   * @return the terminal signature
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @throws DesynchronizedExchangesException if the APDU SAM exchanges are out of sync
   * @since 2.0
   */
  byte[] getTerminalSignature()
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {

    // All remaining SAM digest operations will now run at once.
    // Get the SAM Digest request including Digest Close from the cache manager
    List<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>> samCommands =
        getPendingSamCommands(true);

    CardRequestSpi samCardRequest = new CardRequestAdapter(getApduRequests(samCommands), false);

    // Transmit CardRequest and get CardResponse
    CardResponseApi samCardResponse;

    try {
      samCardResponse = samReader.transmitCardRequest(samCardRequest, ChannelControl.KEEP_OPEN);
    } catch (UnexpectedStatusWordException e) {
      throw new IllegalStateException(UNEXPECTED_EXCEPTION, e);
    }

    List<ApduResponseApi> samApduResponses = samCardResponse.getApduResponses();

    if (samApduResponses.size() != samCommands.size()) {
      throw new DesynchronizedExchangesException(
          "The number of commands/responses does not match: cmd="
              + samCommands.size()
              + ", resp="
              + samApduResponses.size());
    }

    // check all responses status
    for (int i = 0; i < samApduResponses.size(); i++) {
      samCommands.get(i).createResponseParser(samApduResponses.get(i)).checkStatus();
    }

    // Get Terminal Signature from the latest response
    SamDigestCloseParser samDigestCloseParser =
        (SamDigestCloseParser)
            samCommands
                .get(samCommands.size() - 1)
                .createResponseParser(samApduResponses.get(samCommands.size() - 1));

    byte[] sessionTerminalSignature = samDigestCloseParser.getSignature();

    if (logger.isDebugEnabled()) {
      logger.debug("SIGNATURE = {}", ByteArrayUtil.toHex(sessionTerminalSignature));
    }

    return sessionTerminalSignature;
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
   * @throws DesynchronizedExchangesException if the APDU SAM exchanges are out of sync
   * @since 2.0
   */
  void authenticateCardSignature(byte[] cardSignatureLo)
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {
    // Check the card signature part with the SAM
    // Build and send SAM Digest Authenticate command
    SamDigestAuthenticateBuilder samDigestAuthenticateBuilder =
        new SamDigestAuthenticateBuilder(samProductType, cardSignatureLo);

    List<ApduRequestSpi> samApduRequests = new ArrayList<ApduRequestSpi>();
    samApduRequests.add(samDigestAuthenticateBuilder.getApduRequest());

    CardRequestSpi samCardRequest = new CardRequestAdapter(samApduRequests, false);

    CardResponseApi samCardResponse;
    try {
      samCardResponse = samReader.transmitCardRequest(samCardRequest, ChannelControl.KEEP_OPEN);
    } catch (UnexpectedStatusWordException e) {
      throw new IllegalStateException(UNEXPECTED_EXCEPTION, e);
    }

    // Get transaction result parsing the response
    List<ApduResponseApi> samApduResponses = samCardResponse.getApduResponses();

    if (samApduResponses == null || samApduResponses.isEmpty()) {
      throw new DesynchronizedExchangesException("No response to Digest Authenticate command.");
    }

    SamDigestAuthenticateParser digestAuthenticateRespPars =
        samDigestAuthenticateBuilder.createResponseParser(samApduResponses.get(0));

    digestAuthenticateRespPars.checkStatus();
  }

  /**
   * Create an ApduRequestAdapter List from a AbstractSamCommandBuilder List.
   *
   * @param samCommands a list of SAM commands.
   * @return the ApduRequestAdapter list
   * @since 2.0
   */
  private List<ApduRequestSpi> getApduRequests(
      List<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>> samCommands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    if (samCommands != null) {
      for (AbstractSamCommandBuilder<? extends AbstractSamResponseParser> commandBuilder :
          samCommands) {
        apduRequests.add(commandBuilder.getApduRequest());
      }
    }
    return apduRequests;
  }

  /**
   * Compute the PIN ciphered data for the encrypted PIN verification or PIN update commands
   *
   * @param poChallenge the challenge from the card.
   * @param currentPin the current PIN value.
   * @param newPin the new PIN value (set to null if the operation is a PIN presentation).
   * @return the PIN ciphered data
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @since 2.0
   */
  byte[] getCipheredPinData(byte[] poChallenge, byte[] currentPin, byte[] newPin)
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {
    List<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>> samCommands =
        new ArrayList<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>>();
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
        pinCipheringKif =
            ((CardSecuritySettingAdapter) cardSecuritySettings).getPinVerificationCipheringKif();
        pinCipheringKvc =
            ((CardSecuritySettingAdapter) cardSecuritySettings).getPinVerificationCipheringKvc();
      } else {
        // PIN modification
        pinCipheringKif =
            ((CardSecuritySettingAdapter) cardSecuritySettings).getPinModificationCipheringKif();
        pinCipheringKvc =
            ((CardSecuritySettingAdapter) cardSecuritySettings).getPinModificationCipheringKvc();
      }
    }

    if (!isDiversificationDone) {
      /* Build the SAM Select Diversifier command to provide the SAM with the card S/N */
      samCommands.add(
          new SamSelectDiversifierBuilder(
              samProductType, calypsoCard.getCalypsoSerialNumberFull()));
      isDiversificationDone = true;
    }

    if (isDigesterInitialized) {
      /* Get the pending SAM ApduRequestAdapter and add it to the current ApduRequestAdapter list */
      samCommands.addAll(getPendingSamCommands(false));
    }

    samCommands.add(new SamGiveRandomBuilder(samProductType, poChallenge));

    int cardCipherPinCmdIndex = samCommands.size();

    SamCardCipherPinBuilder samCardCipherPinBuilder =
        new SamCardCipherPinBuilder(
            samProductType, pinCipheringKif, pinCipheringKvc, currentPin, newPin);

    samCommands.add(samCardCipherPinBuilder);

    // build a SAM CardRequest
    CardRequestSpi samCardRequest = new CardRequestAdapter(getApduRequests(samCommands), false);

    // execute the command
    CardResponseApi samCardResponse;
    try {
      samCardResponse = samReader.transmitCardRequest(samCardRequest, ChannelControl.KEEP_OPEN);
    } catch (UnexpectedStatusWordException e) {
      throw new IllegalStateException(UNEXPECTED_EXCEPTION, e);
    }

    ApduResponseApi cardCipherPinResponse =
        samCardResponse.getApduResponses().get(cardCipherPinCmdIndex);

    // create a parser
    SamCardCipherPinParser samCardCipherPinParser =
        samCardCipherPinBuilder.createResponseParser(cardCipherPinResponse);

    samCardCipherPinParser.checkStatus();

    return samCardCipherPinParser.getCipheredData();
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
   * @param samSvPrepareBuilder the prepare command builder (can be prepareSvReload/Debit/Undebit).
   * @return a byte array containing the complementary data
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @since 2.0
   */
  private byte[] getSvComplementaryData(
      AbstractSamCommandBuilder<? extends AbstractSamResponseParser> samSvPrepareBuilder)
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {
    List<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>> samCommands =
        new ArrayList<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>>();

    if (!isDiversificationDone) {
      /* Build the SAM Select Diversifier command to provide the SAM with the card S/N */
      samCommands.add(
          new SamSelectDiversifierBuilder(
              samProductType, calypsoCard.getCalypsoSerialNumberFull()));
      isDiversificationDone = true;
    }

    if (isDigesterInitialized) {
      /* Get the pending SAM ApduRequestAdapter and add it to the current ApduRequestAdapter list */
      samCommands.addAll(getPendingSamCommands(false));
    }

    int svPrepareOperationCmdIndex = samCommands.size();

    samCommands.add(samSvPrepareBuilder);

    // build a SAM CardRequest
    CardRequestSpi samCardRequest = new CardRequestAdapter(getApduRequests(samCommands), false);

    // execute the command
    CardResponseApi samCardResponse;
    try {
      samCardResponse = samReader.transmitCardRequest(samCardRequest, ChannelControl.KEEP_OPEN);
    } catch (UnexpectedStatusWordException e) {
      throw new IllegalStateException(UNEXPECTED_EXCEPTION, e);
    }

    ApduResponseApi svPrepareResponse =
        samCardResponse.getApduResponses().get(svPrepareOperationCmdIndex);

    // create a parser
    SamSvPrepareOperationParser svPrepareOperationRespPars =
        (SamSvPrepareOperationParser) samSvPrepareBuilder.createResponseParser(svPrepareResponse);

    svPrepareOperationRespPars.checkStatus();

    byte[] prepareOperationData = svPrepareOperationRespPars.getApduResponse().getDataOut();

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
   * @param cardSvReloadBuilder the SvDebit builder providing the SvReload partial data.
   * @param svGetHeader the SV Get command header.
   * @param svGetData the SV Get command response data.
   * @return the complementary security data to finalize the SvReload card command (sam ID + SV
   *     prepare load output)
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @since 2.0
   */
  byte[] getSvReloadComplementaryData(
      CardSvReloadBuilder cardSvReloadBuilder, byte[] svGetHeader, byte[] svGetData)
      throws CalypsoSamCommandException, ReaderBrokenCommunicationException,
          CardBrokenCommunicationException {
    // get the complementary data from the SAM
    SamSvPrepareLoadBuilder samSvPrepareLoadBuilder =
        new SamSvPrepareLoadBuilder(
            samProductType, svGetHeader, svGetData, cardSvReloadBuilder.getSvReloadData());

    return getSvComplementaryData(samSvPrepareLoadBuilder);
  }

  /**
   * Computes the cryptographic data required for the SvDebit command.
   *
   * <p>Use the data from the SvGet command and the partial data from the SvDebit command for this
   * purpose.
   *
   * <p>The returned data will be used to finalize the card SvDebit command.
   *
   * @param svGetHeader the SV Get command header.
   * @param svGetData the SV Get command response data.
   * @return the complementary security data to finalize the SvDebit card command (sam ID + SV
   *     prepare load output)
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @since 2.0
   */
  byte[] getSvDebitComplementaryData(
      CardSvDebitBuilder cardSvDebitBuilder, byte[] svGetHeader, byte[] svGetData)
      throws CalypsoSamCommandException, ReaderBrokenCommunicationException,
          CardBrokenCommunicationException {
    // get the complementary data from the SAM
    SamSvPrepareDebitBuilder samSvPrepareDebitBuilder =
        new SamSvPrepareDebitBuilder(
            samProductType, svGetHeader, svGetData, cardSvDebitBuilder.getSvDebitData());

    return getSvComplementaryData(samSvPrepareDebitBuilder);
  }

  /**
   * Computes the cryptographic data required for the SvUndebit command.
   *
   * <p>Use the data from the SvGet command and the partial data from the SvUndebit command for this
   * purpose.
   *
   * <p>The returned data will be used to finalize the card SvUndebit command.
   *
   * @param svGetHeader the SV Get command header.
   * @param svGetData the SV Get command response data.
   * @return the complementary security data to finalize the SvUndebit card command (sam ID + SV
   *     prepare load output)
   * @throws CalypsoSamCommandException if the SAM has responded with an error status
   * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
   * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
   * @since 2.0
   */
  public byte[] getSvUndebitComplementaryData(
      CardSvUndebitBuilder cardSvUndebitBuilder, byte[] svGetHeader, byte[] svGetData)
      throws CalypsoSamCommandException, ReaderBrokenCommunicationException,
          CardBrokenCommunicationException {
    // get the complementary data from the SAM
    SamSvPrepareUndebitBuilder samSvPrepareUndebitBuilder =
        new SamSvPrepareUndebitBuilder(
            samProductType, svGetHeader, svGetData, cardSvUndebitBuilder.getSvUndebitData());

    return getSvComplementaryData(samSvPrepareUndebitBuilder);
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
   * @since 2.0
   */
  void checkSvStatus(byte[] svOperationResponseData)
      throws CalypsoSamCommandException, CardBrokenCommunicationException,
          ReaderBrokenCommunicationException {
    List<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>> samCommands =
        new ArrayList<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>>();

    SamSvCheckBuilder samSvCheckBuilder =
        new SamSvCheckBuilder(samProductType, svOperationResponseData);
    samCommands.add(samSvCheckBuilder);

    // build a SAM CardRequest
    CardRequestSpi samCardRequest = new CardRequestAdapter(getApduRequests(samCommands), false);

    // execute the command
    CardResponseApi samCardResponse;
    try {
      samCardResponse = samReader.transmitCardRequest(samCardRequest, ChannelControl.KEEP_OPEN);
    } catch (UnexpectedStatusWordException e) {
      throw new IllegalStateException(UNEXPECTED_EXCEPTION, e);
    }

    ApduResponseApi svCheckResponse = samCardResponse.getApduResponses().get(0);

    // create a parser
    SamSvCheckParser samSvCheckParser = samSvCheckBuilder.createResponseParser(svCheckResponse);

    samSvCheckParser.checkStatus();
  }
}
