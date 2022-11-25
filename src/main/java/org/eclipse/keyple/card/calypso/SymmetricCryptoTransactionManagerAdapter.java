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
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.InconsistentDataException;
import org.calypsonet.terminal.calypso.transaction.InvalidSignatureException;
import org.calypsonet.terminal.calypso.transaction.ReaderIOException;
import org.calypsonet.terminal.calypso.transaction.SamIOException;
import org.calypsonet.terminal.calypso.transaction.SamRevokedException;
import org.calypsonet.terminal.calypso.transaction.UnexpectedCommandStatusException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardBrokenCommunicationException;
import org.calypsonet.terminal.card.CardResponseApi;
import org.calypsonet.terminal.card.ChannelControl;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.calypsonet.terminal.card.ReaderBrokenCommunicationException;
import org.calypsonet.terminal.card.UnexpectedStatusWordException;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class SymmetricCryptoTransactionManagerAdapter implements SymmetricCryptoTransactionManagerSpi {

  private static final Logger logger =
      LoggerFactory.getLogger(SymmetricCryptoTransactionManagerAdapter.class);

  /* Prefix/suffix used to compose exception messages */
  private static final String MSG_SAM_READER_COMMUNICATION_ERROR =
      "A communication error with the SAM reader occurred ";
  private static final String MSG_SAM_COMMUNICATION_ERROR =
      "A communication error with the SAM occurred ";
  private static final String MSG_SAM_COMMAND_ERROR = "A SAM command error occurred ";
  private static final String MSG_SAM_INCONSISTENT_DATA =
      "The number of SAM commands/responses does not match: nb commands = ";
  private static final String MSG_SAM_NB_RESPONSES = ", nb responses = ";
  private static final String MSG_WHILE_TRANSMITTING_COMMANDS = "while transmitting commands.";
  private static final String MSG_INPUT_OUTPUT_DATA = "input/output data";
  private static final String MSG_SIGNATURE_SIZE = "signature size";
  private static final String MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8 =
      "key diversifier size is in range [1..8]";

  /* Final fields */
  private final ProxyReaderApi samReader;
  private final CalypsoSamAdapter sam;
  private final byte[] cardKeyDiversifier;
  private final boolean isExtendedModeRequired;
  private final List<byte[]> transactionAuditData;
  private final List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>();

  // Temporary field for manage PSO signature
  private final CardSecuritySettingAdapter tmpCardSecuritySetting;

  /* Dynamic fields */
  private byte[] currentKeyDiversifier;
  private DigestManager digestManager;

  SymmetricCryptoTransactionManagerAdapter(
      ProxyReaderApi samReader,
      CalypsoSamAdapter sam,
      byte[] cardKeyDiversifier,
      boolean useExtendedMode,
      List<byte[]> transactionAuditData,
      CardSecuritySettingAdapter tmpCardSecuritySetting) {
    this.samReader = samReader;
    this.sam = sam;
    this.cardKeyDiversifier = cardKeyDiversifier;
    this.isExtendedModeRequired = useExtendedMode;
    this.transactionAuditData = transactionAuditData;
    this.tmpCardSecuritySetting = tmpCardSecuritySetting;
  }

  @Override
  public byte[] initTerminalSecureSessionContext()
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    prepareSelectDiversifierIfNeeded();
    CmdSamGetChallenge cmd = new CmdSamGetChallenge(sam, isExtendedModeRequired ? 8 : 4);
    samCommands.add(cmd);
    processCommands();
    return cmd.getChallenge();
  }

  @Override
  public void initTerminalSessionMac(byte[] openSecureSessionDataOut, byte kif, byte kvc) {
    digestManager = new DigestManager(openSecureSessionDataOut, kif, kvc);
  }

  @Override
  public byte[] updateTerminalSessionMac(byte[] cardApdu) {
    digestManager.updateSession(cardApdu);
    return cardApdu;
  }

  @Override
  public byte[] finalizeTerminalSessionMac()
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    digestManager.prepareCommands();
    digestManager = null;
    CmdSamDigestClose cmdSamDigestClose =
        (CmdSamDigestClose) samCommands.get(samCommands.size() - 1);
    processCommands();
    return cmdSamDigestClose.getSignature();
  }

  @Override
  public byte[] generateTerminalSessionMac() {
    return new byte[0]; // TODO
  }

  @Override
  public void activateEncryption() {
    // TODO
  }

  @Override
  public void deactivateEncryption() {
    // TODO
  }

  @Override
  public boolean verifyCardSessionMac(byte[] cardSessionMac)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    samCommands.add(new CmdSamDigestAuthenticate(sam, cardSessionMac));
    try {
      processCommands();
      return true;
    } catch (InvalidCardMacException e) {
      return false;
    }
  }

  @Override
  public void computeSvCommandSecurityData(SvCommandSecurityDataApi svCommandSecurityData)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    SvCommandSecurityDataApiAdapter data = (SvCommandSecurityDataApiAdapter) svCommandSecurityData;
    prepareSelectDiversifierIfNeeded();
    if (data.getSvCommandPartialRequest()[0] == (byte) 0xB8) {
      samCommands.add(new CmdSamSvPrepareLoad(sam, data));
    } else {
      samCommands.add(new CmdSamSvPrepareDebitOrUndebit(sam, data));
    }
    processCommands();
  }

  @Override
  public boolean verifyCardSvMac(byte[] cardSvMac)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    samCommands.add(new CmdSamSvCheck(sam, cardSvMac));
    try {
      processCommands();
      return true;
    } catch (InvalidCardMacException e) {
      return false;
    }
  }

  /** Prepares a "Give Random" SAM command. */
  private void prepareGiveRandom(byte[] cardChallenge) {
    prepareSelectDiversifierIfNeeded();
    samCommands.add(new CmdSamGiveRandom(sam, cardChallenge));
  }

  @Override
  public byte[] cipherPinForPresentation(byte[] cardChallenge, byte[] pin, Byte kif, Byte kvc)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    return cipherPin(cardChallenge, pin, null, kif, kvc);
  }

  @Override
  public byte[] cipherPinForModification(
      byte[] cardChallenge, byte[] currentPin, byte[] newPin, Byte kif, Byte kvc)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    return cipherPin(cardChallenge, currentPin, newPin, kif, kvc);
  }

  private byte[] cipherPin(
      byte[] cardChallenge, byte[] currentPin, byte[] newPin, Byte kif, Byte kvc)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    byte pinCipheringKif;
    byte pinCipheringKvc;
    if (digestManager != null && digestManager.sessionKif != 0) {
      // the current work key has been set (a secure session is open)
      pinCipheringKif = digestManager.sessionKif;
      pinCipheringKvc = digestManager.sessionKvc;
    } else {
      // no current work key is available (outside secure session)
      if (kif == null || kvc == null) {
        String msg = newPin == null ? "verification" : "modification";
        throw new IllegalStateException(
            String.format("No KIF or KVC defined for the PIN %s ciphering key", msg));
      }
      pinCipheringKif = kif;
      pinCipheringKvc = kvc;
    }
    prepareGiveRandom(cardChallenge);
    CmdSamCardCipherPin cmd =
        new CmdSamCardCipherPin(sam, pinCipheringKif, pinCipheringKvc, currentPin, newPin);
    samCommands.add(cmd);
    processCommands();
    return cmd.getCipheredData();
  }

  @Override
  public byte[] generateCipheredCardKey(
      byte[] cardChallenge,
      byte issuerKeyKif,
      byte issuerKeyKvc,
      byte targetKeyKif,
      byte targetKeyKvc)
      throws SymmetricCryptoIOException, SymmetricCryptoException {
    prepareGiveRandom(cardChallenge);
    CmdSamCardGenerateKey cmd =
        new CmdSamCardGenerateKey(sam, issuerKeyKif, issuerKeyKvc, targetKeyKif, targetKeyKvc);
    samCommands.add(cmd);
    processCommands();
    return cmd.getCipheredData();
  }

  void processCommands() throws SymmetricCryptoException, SymmetricCryptoIOException {
    // If there are pending SAM commands and the secure session is open and the "Digest Init"
    // command is not already executed, then we need to flush the session pending commands by
    // executing the pending "digest" commands "BEFORE" the other SAM commands to make sure that
    // between the session "Get Challenge" and the "Digest Init", there is no other command
    // inserted.
    if (!samCommands.isEmpty() && digestManager != null && !digestManager.isDigestInitDone) {
      digestManager.prepareDigestInit();
    }
    if (samCommands.isEmpty()) {
      return;
    }
    try {
      // Get the list of C-APDU to transmit
      List<ApduRequestSpi> apduRequests = getApduRequests(samCommands);

      // Wrap the list of C-APDUs into a card request
      CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, true);

      // Transmit the commands to the SAM
      CardResponseApi cardResponse = transmitCardRequest(cardRequest);

      // Retrieve the list of R-APDUs
      List<ApduResponseApi> apduResponses = cardResponse.getApduResponses();

      // If there are more responses than requests, then we are unable to fill the card image. In
      // this case we stop processing immediately because it may be a case of fraud, and we throw an
      // exception.
      if (apduResponses.size() > apduRequests.size()) {
        throw new SymmetricCryptoException(
            MSG_SAM_INCONSISTENT_DATA
                + apduRequests.size()
                + MSG_SAM_NB_RESPONSES
                + apduResponses.size(),
            new InconsistentDataException(
                MSG_SAM_INCONSISTENT_DATA
                    + apduRequests.size()
                    + MSG_SAM_NB_RESPONSES
                    + apduResponses.size()
                    + getTransactionAuditDataAsString()));
      }

      // We go through all the responses (and not the requests) because there may be fewer in the
      // case of an error that occurred in strict mode. In this case the last response will raise an
      // exception.
      for (int i = 0; i < apduResponses.size(); i++) {
        try {
          samCommands.get(i).parseApduResponse(apduResponses.get(i));
        } catch (CalypsoSamCommandException e) {
          CalypsoSamCommand commandRef = samCommands.get(i).getCommandRef();
          if (commandRef == CalypsoSamCommand.DIGEST_AUTHENTICATE
              && e instanceof CalypsoSamSecurityDataException) {
            throw new InvalidCardMacException("Invalid card signature.");
          } else if ((commandRef == CalypsoSamCommand.PSO_VERIFY_SIGNATURE
                  || commandRef == CalypsoSamCommand.DATA_CIPHER)
              && e instanceof CalypsoSamSecurityDataException) {
            throw new InvalidSignatureException("Invalid signature.", e);
          } else if (commandRef == CalypsoSamCommand.SV_CHECK
              && e instanceof CalypsoSamSecurityDataException) {
            throw new InvalidCardMacException("Invalid SV card signature.");
          }
          String sw = e.getStatusWord() != null ? HexUtil.toHex(e.getStatusWord()) : "null";
          throw new SymmetricCryptoException(
              MSG_SAM_COMMAND_ERROR
                  + "while processing responses to SAM commands: "
                  + e.getCommand()
                  + " ["
                  + sw
                  + "]",
              new UnexpectedCommandStatusException(
                  MSG_SAM_COMMAND_ERROR
                      + "while processing responses to SAM commands: "
                      + e.getCommand()
                      + " ["
                      + sw
                      + "]"
                      + getTransactionAuditDataAsString(),
                  e));
        }
      }

      // Finally, if no error has occurred and there are fewer responses than requests, then we
      // throw an exception.
      if (apduResponses.size() < apduRequests.size()) {
        throw new SymmetricCryptoException(
            MSG_SAM_INCONSISTENT_DATA
                + apduRequests.size()
                + MSG_SAM_NB_RESPONSES
                + apduResponses.size(),
            new InconsistentDataException(
                MSG_SAM_INCONSISTENT_DATA
                    + apduRequests.size()
                    + MSG_SAM_NB_RESPONSES
                    + apduResponses.size()
                    + getTransactionAuditDataAsString()));
      }
    } finally {
      // Reset the list of commands.
      samCommands.clear();
    }
  }

  /**
   * (private)<br>
   * Creates a list of {@link ApduRequestSpi} from a list of {@link AbstractSamCommand}.
   *
   * @param commands The list of commands.
   * @return An empty list if there is no command.
   * @since 2.2.0
   */
  private List<ApduRequestSpi> getApduRequests(List<AbstractSamCommand> commands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<ApduRequestSpi>();
    if (commands != null) {
      for (AbstractSamCommand command : commands) {
        apduRequests.add(command.getApduRequest());
      }
    }
    return apduRequests;
  }

  /**
   * (private)<br>
   * Transmits a card request, processes and converts any exceptions.
   *
   * @param cardRequest The card request to transmit.
   * @return The card response.
   */
  private CardResponseApi transmitCardRequest(CardRequestSpi cardRequest)
      throws SymmetricCryptoIOException {
    CardResponseApi cardResponse;
    try {
      cardResponse = samReader.transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);
    } catch (ReaderBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse());
      throw new SymmetricCryptoIOException(
          MSG_SAM_READER_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS,
          new ReaderIOException(
              MSG_SAM_READER_COMMUNICATION_ERROR
                  + MSG_WHILE_TRANSMITTING_COMMANDS
                  + getTransactionAuditDataAsString(),
              e));
    } catch (CardBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse());
      throw new SymmetricCryptoIOException(
          MSG_SAM_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS,
          new SamIOException(
              MSG_SAM_COMMUNICATION_ERROR
                  + MSG_WHILE_TRANSMITTING_COMMANDS
                  + getTransactionAuditDataAsString(),
              e));
    } catch (UnexpectedStatusWordException e) {
      if (logger.isDebugEnabled()) {
        logger.debug("A SAM command has failed: {}", e.getMessage());
      }
      cardResponse = e.getCardResponse();
    }
    saveTransactionAuditData(cardRequest, cardResponse);
    return cardResponse;
  }

  /**
   * (package-private)<br>
   * Saves the provided exchanged APDU commands in the list of transaction audit data.
   *
   * @param cardRequest The card request.
   * @param cardResponse The associated card response.
   * @since 2.1.1
   */
  private void saveTransactionAuditData(CardRequestSpi cardRequest, CardResponseApi cardResponse) {
    if (cardResponse != null) {
      List<ApduRequestSpi> requests = cardRequest.getApduRequests();
      List<ApduResponseApi> responses = cardResponse.getApduResponses();
      for (int i = 0; i < responses.size(); i++) {
        transactionAuditData.add(requests.get(i).getApdu());
        transactionAuditData.add(responses.get(i).getApdu());
      }
    }
  }

  /**
   * (package-private)<br>
   * Returns a string representation of the transaction audit data.
   *
   * @return A not empty string.
   */
  private String getTransactionAuditDataAsString() {
    return "\nTransaction audit JSON data: {"
        + "\"sam\":"
        + sam
        + ",\"apdus\":"
        + JsonUtil.toJson(transactionAuditData)
        + "}";
  }

  /**
   * (private)<br>
   * Prepares a "SelectDiversifier" command using the current key diversifier.
   *
   * @return The current instance.
   */
  private void prepareSelectDiversifier() {
    samCommands.add(new CmdSamSelectDiversifier(sam, currentKeyDiversifier));
  }

  /**
   * (package-private)<br>
   * Prepares a "SelectDiversifier" command using a specific or the default key diversifier if it is
   * not already selected.
   *
   * @param specificKeyDiversifier The specific key diversifier (optional).
   * @since 2.2.0
   */
  private void prepareSelectDiversifierIfNeeded(byte[] specificKeyDiversifier) {
    if (specificKeyDiversifier != null) {
      if (!Arrays.equals(specificKeyDiversifier, currentKeyDiversifier)) {
        currentKeyDiversifier = specificKeyDiversifier;
        prepareSelectDiversifier();
      }
    } else {
      prepareSelectDiversifierIfNeeded();
    }
  }

  /**
   * (package-private)<br>
   * Prepares a "SelectDiversifier" command using the default key diversifier if it is not already
   * selected.
   *
   * @since 2.2.0
   */
  private void prepareSelectDiversifierIfNeeded() {
    if (!Arrays.equals(currentKeyDiversifier, cardKeyDiversifier)) {
      currentKeyDiversifier = cardKeyDiversifier;
      prepareSelectDiversifier();
    }
  }

  void prepareComputeSignature(CommonSignatureComputationData data) {

    if (data instanceof BasicSignatureComputationDataAdapter) {
      // Basic signature
      BasicSignatureComputationDataAdapter dataAdapter =
          (BasicSignatureComputationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "data to sign")
          .isInRange(dataAdapter.getData().length, 1, 208, "length of data to sign")
          .isTrue(
              dataAdapter.getData().length % 8 == 0, "length of data to sign is a multiple of 8")
          .isInRange(dataAdapter.getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      samCommands.add(new CmdSamDataCipher(sam, dataAdapter, null));

    } else if (data instanceof TraceableSignatureComputationDataAdapter) {
      // Traceable signature
      TraceableSignatureComputationDataAdapter dataAdapter =
          (TraceableSignatureComputationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "data to sign")
          .isInRange(
              dataAdapter.getData().length,
              1,
              dataAdapter.isSamTraceabilityMode() ? 206 : 208,
              "length of data to sign")
          .isInRange(dataAdapter.getSignatureSize(), 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              !dataAdapter.isSamTraceabilityMode()
                  || (dataAdapter.getTraceabilityOffset() >= 0
                      && dataAdapter.getTraceabilityOffset()
                          <= ((dataAdapter.getData().length * 8)
                              - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))
                  + "]")
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      samCommands.add(new CmdSamPsoComputeSignature(sam, dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'BasicSignatureComputationDataAdapter' or 'TraceableSignatureComputationDataAdapter'");
    }
  }

  void prepareVerifySignature(CommonSignatureVerificationData data) {
    if (data instanceof BasicSignatureVerificationDataAdapter) {
      // Basic signature
      BasicSignatureVerificationDataAdapter dataAdapter =
          (BasicSignatureVerificationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "signed data to verify")
          .isInRange(dataAdapter.getData().length, 1, 208, "length of signed data to verify")
          .isTrue(
              dataAdapter.getData().length % 8 == 0, "length of data to verify is a multiple of 8")
          .notNull(dataAdapter.getSignature(), "signature")
          .isInRange(dataAdapter.getSignature().length, 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      samCommands.add(new CmdSamDataCipher(sam, null, dataAdapter));

    } else if (data instanceof TraceableSignatureVerificationDataAdapter) {
      // Traceable signature
      TraceableSignatureVerificationDataAdapter dataAdapter =
          (TraceableSignatureVerificationDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
          .notNull(dataAdapter.getData(), "signed data to verify")
          .isInRange(
              dataAdapter.getData().length,
              1,
              dataAdapter.isSamTraceabilityMode() ? 206 : 208,
              "length of signed data to verify")
          .notNull(dataAdapter.getSignature(), "signature")
          .isInRange(dataAdapter.getSignature().length, 1, 8, MSG_SIGNATURE_SIZE)
          .isTrue(
              !dataAdapter.isSamTraceabilityMode()
                  || (dataAdapter.getTraceabilityOffset() >= 0
                      && dataAdapter.getTraceabilityOffset()
                          <= ((dataAdapter.getData().length * 8)
                              - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))),
              "traceability offset is in range [0.."
                  + ((dataAdapter.getData().length * 8)
                      - (dataAdapter.isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))
                  + "]")
          .isTrue(
              dataAdapter.getKeyDiversifier() == null
                  || (dataAdapter.getKeyDiversifier().length >= 1
                      && dataAdapter.getKeyDiversifier().length <= 8),
              MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

      // Check SAM revocation status if requested.
      if (dataAdapter.isSamRevocationStatusVerificationRequested()) {
        Assert.getInstance()
            // .notNull(securitySetting, "security settings")
            .notNull(tmpCardSecuritySetting.getSamRevocationServiceSpi(), "SAM revocation service");

        // Extract the SAM serial number and the counter value from the data.
        byte[] samSerialNumber =
            ByteArrayUtil.extractBytes(
                dataAdapter.getData(),
                dataAdapter.getTraceabilityOffset(),
                dataAdapter.isPartialSamSerialNumber() ? 3 : 4);

        int samCounterValue =
            ByteArrayUtil.extractInt(
                ByteArrayUtil.extractBytes(
                    dataAdapter.getData(),
                    dataAdapter.getTraceabilityOffset()
                        + (dataAdapter.isPartialSamSerialNumber() ? 3 * 8 : 4 * 8),
                    3),
                0,
                3,
                false);

        // Is SAM revoked ?
        if (tmpCardSecuritySetting
            .getSamRevocationServiceSpi()
            .isSamRevoked(samSerialNumber, samCounterValue)) {
          throw new SamRevokedException(
              String.format(
                  "SAM with serial number '%s' and counter value '%d' is revoked.",
                  HexUtil.toHex(samSerialNumber), samCounterValue));
        }
      }

      prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
      samCommands.add(new CmdSamPsoVerifySignature(sam, dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'CommonSignatureVerificationDataAdapter'");
    }
  }

  /**
   * (private)<br>
   * The manager of the digest session.
   */
  private class DigestManager {

    private final byte[] openSecureSessionDataOut;
    private final byte sessionKif;
    private final byte sessionKvc;
    private final List<byte[]> cardApdus = new ArrayList<byte[]>();
    private boolean isDigestInitDone;
    boolean isRequest = true;

    /**
     * (private)<br>
     * Creates a new digest manager.
     *
     * @param openSecureSessionDataOut The data out of the "Open Secure Session" card command.
     * @param kif The KIF to use.
     * @param kvc The KVC to use.
     */
    private DigestManager(byte[] openSecureSessionDataOut, byte kif, byte kvc) {
      this.openSecureSessionDataOut = openSecureSessionDataOut;
      this.sessionKif = kif;
      this.sessionKvc = kvc;
    }

    /**
     * (private)<br>
     * Add one or more exchanged card APDUs to the buffer.
     *
     * @param cardApdu The APDU.
     */
    private void updateSession(byte[] cardApdu) {
      // If the request is of case4 type, LE must be excluded from the digest computation. In this
      // case, we remove here the last byte of the command buffer.
      // CL-C4-MAC.1
      if (isRequest) {
        cardApdus.add(
            ApduUtil.isCase4(cardApdu)
                ? Arrays.copyOfRange(cardApdu, 0, cardApdu.length - 1)
                : cardApdu);
      } else {
        cardApdus.add(cardApdu);
      }
      isRequest = !isRequest;
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
      samCommands.add(
          0,
          new CmdSamDigestInit(
              sam,
              false,
              isExtendedModeRequired,
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
      if (sam.getProductType() == CalypsoSam.ProductType.SAM_C1) {
        // Digest Update Multiple
        // Construct list of DataIn
        List<byte[]> digestDataList = new ArrayList<byte[]>(1);
        byte[] buffer = new byte[255];
        int i = 0;
        for (byte[] cardApdu : cardApdus) {
          /*
           * The maximum buffer length of the "Digest Update Multiple" SAM command is set to 230
           * bytes instead of the 254 theoretically allowed by the SAM in order to be compatible
           * with certain unpredictable applications (e.g. 237 for the Hoplink application).
           */
          if (i + cardApdu.length > 230) {
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
          samCommands.add(new CmdSamDigestUpdateMultiple(sam, dataIn));
        }
      } else {
        // Digest Update (simple)
        for (byte[] cardApdu : cardApdus) {
          samCommands.add(new CmdSamDigestUpdate(sam, false, cardApdu));
        }
      }
    }

    /**
     * (private)<br>
     * Prepares the "Digest Close" SAM command.
     */
    private void prepareDigestClose() {
      // CL-SAM-DCLOSE.1
      samCommands.add(new CmdSamDigestClose(sam, isExtendedModeRequired ? 8 : 4));
    }
  }

  private static class InvalidCardMacException extends RuntimeException {
    private InvalidCardMacException(String message) {
      super(message);
    }
  }
}
