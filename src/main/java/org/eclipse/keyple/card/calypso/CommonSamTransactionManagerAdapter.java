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
import org.calypsonet.terminal.calypso.transaction.InconsistentDataException;
import org.calypsonet.terminal.calypso.transaction.InvalidSignatureException;
import org.calypsonet.terminal.calypso.transaction.ReaderIOException;
import org.calypsonet.terminal.calypso.transaction.SamIOException;
import org.calypsonet.terminal.calypso.transaction.SamRevokedException;
import org.calypsonet.terminal.calypso.transaction.SamSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.SamTransactionManager;
import org.calypsonet.terminal.calypso.transaction.SignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.SignatureVerificationData;
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
import org.calypsonet.terminal.reader.CardReader;
import org.calypsonet.terminal.reader.selection.spi.SmartCard;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Abstract class for all {@link SamTransactionManager} classes.
 *
 * @since 2.2.0
 */
abstract class CommonSamTransactionManagerAdapter
    extends CommonTransactionManagerAdapter<SamTransactionManager, SamSecuritySetting>
    implements SamTransactionManager {

  private static final Logger logger =
      LoggerFactory.getLogger(CommonSamTransactionManagerAdapter.class);

  /* Final fields */
  private final ProxyReaderApi samReader;
  private final CalypsoSamAdapter sam;
  private final CommonSecuritySettingAdapter<?> securitySetting;
  private final List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>();
  private final byte[] defaultKeyDiversifier;

  /* Dynamic fields */
  private byte[] currentKeyDiversifier;

  /**
   * (package-private)<br>
   * Creates a new instance (to be used for instantiation of {@link SamTransactionManagerAdapter}
   * only).
   *
   * @param samReader The reader through which the SAM communicates.
   * @param sam The initial SAM data provided by the selection process.
   * @param securitySetting The SAM security settings (optional).
   * @since 2.2.0
   */
  CommonSamTransactionManagerAdapter(
      ProxyReaderApi samReader, CalypsoSamAdapter sam, SamSecuritySettingAdapter securitySetting) {
    super(sam, securitySetting, null);
    this.samReader = samReader;
    this.sam = sam;
    this.securitySetting = securitySetting;
    this.defaultKeyDiversifier = sam.getSerialNumber();
  }

  /**
   * (package-private)<br>
   * Creates a new instance (to be used for instantiation of {@link
   * ControlSamTransactionManagerAdapter} only).
   *
   * @param targetSmartCard The target smartcard provided by the selection process.
   * @param securitySetting The card or SAM security settings.
   * @param defaultKeyDiversifier The full serial number of the target card or SAM to be used by
   *     default when diversifying keys.
   * @param transactionAuditData The original transaction data to fill.
   * @since 2.2.0
   */
  CommonSamTransactionManagerAdapter(
      SmartCard targetSmartCard,
      CommonSecuritySettingAdapter<?> securitySetting,
      byte[] defaultKeyDiversifier,
      List<byte[]> transactionAuditData) {
    super(targetSmartCard, securitySetting, transactionAuditData);
    this.samReader = securitySetting.getControlSamReader();
    this.sam = securitySetting.getControlSam();
    this.securitySetting = securitySetting;
    this.defaultKeyDiversifier = defaultKeyDiversifier;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final CardReader getSamReader() {
    return (CardReader) samReader;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final CalypsoSam getCalypsoSam() {
    return sam;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final SamTransactionManager prepareComputeSignature(SignatureComputationData data) {

    if (!(data instanceof SignatureComputationDataAdapter)) {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'SignatureComputationDataAdapter'");
    }

    SignatureComputationDataAdapter dataAdapter = (SignatureComputationDataAdapter) data;

    Assert.getInstance()
        .notNull(dataAdapter, "input/output data")
        .notNull(dataAdapter.getData(), "data to sign")
        .isInRange(
            dataAdapter.getData().length,
            1,
            dataAdapter.isSamTraceabilityMode() ? 206 : 208,
            "length of data to sign")
        .isInRange(dataAdapter.getSignatureSize(), 1, 8, "signature size")
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
            "key diversifier size is in range [1..8]");

    prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
    samCommands.add(new CmdSamPsoComputeSignature(sam.getProductType(), dataAdapter));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final SamTransactionManager prepareVerifySignature(SignatureVerificationData data) {

    if (!(data instanceof SignatureVerificationDataAdapter)) {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'SignatureVerificationDataAdapter'");
    }

    SignatureVerificationDataAdapter dataAdapter = (SignatureVerificationDataAdapter) data;

    Assert.getInstance()
        .notNull(dataAdapter, "input/output data")
        .notNull(dataAdapter.getData(), "signed data to verify")
        .isInRange(
            dataAdapter.getData().length,
            1,
            dataAdapter.isSamTraceabilityMode() ? 206 : 208,
            "length of signed data to verify")
        .notNull(dataAdapter.getSignature(), "signature")
        .isInRange(dataAdapter.getSignature().length, 1, 8, "signature size")
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
            "key diversifier size is in range [1..8]");

    // Check SAM revocation status if requested.
    if (dataAdapter.isSamRevocationStatusVerificationRequested()) {
      Assert.getInstance()
          .notNull(securitySetting, "security settings")
          .notNull(securitySetting.getSamRevocationServiceSpi(), "SAM revocation service");

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
      if (securitySetting
          .getSamRevocationServiceSpi()
          .isSamRevoked(samSerialNumber, samCounterValue)) {
        throw new SamRevokedException(
            String.format(
                "SAM with serial number '%s' and counter value '%d' is revoked.",
                HexUtil.toHex(samSerialNumber), samCounterValue));
      }
    }

    prepareSelectDiversifierIfNeeded(dataAdapter.getKeyDiversifier());
    samCommands.add(new CmdSamPsoVerifySignature(sam.getProductType(), dataAdapter));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final SamTransactionManager processCommands() {
    if (samCommands.isEmpty()) {
      return this;
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
        throw new InconsistentDataException(
            "The number of SAM commands/responses does not match: nb commands = "
                + apduRequests.size()
                + ", nb responses = "
                + apduResponses.size());
      }

      // We go through all the responses (and not the requests) because there may be fewer in the
      // case of an error that occurred in strict mode. In this case the last response will raise an
      // exception.
      for (int i = 0; i < apduResponses.size(); i++) {
        try {
          samCommands.get(i).setApduResponse(apduResponses.get(i)).checkStatus();
        } catch (CalypsoSamCommandException e) {
          if (samCommands.get(i).getCommandRef() == CalypsoSamCommand.PSO_VERIFY_SIGNATURE
              && e instanceof CalypsoSamSecurityDataException) {
            throw new InvalidSignatureException("Invalid signature.", e);
          }
          throw new UnexpectedCommandStatusException(
              MSG_SAM_COMMAND_ERROR
                  + "while processing responses to SAM commands: "
                  + e.getCommand()
                  + getTransactionAuditDataAsString(),
              e);
        }
      }

      // Finally, if no error has occurred and there are fewer responses than requests, then we
      // throw an exception.
      if (apduResponses.size() < apduRequests.size()) {
        throw new InconsistentDataException(
            "The number of SAM commands/responses does not match: nb commands = "
                + apduRequests.size()
                + ", nb responses = "
                + apduResponses.size());
      }
    } finally {
      // Reset the list of commands.
      samCommands.clear();
    }
    return this;
  }

  /**
   * (private)<br>
   * Transmits a card request, processes and converts any exceptions.
   *
   * @param cardRequest The card request to transmit.
   * @return The card response.
   */
  private CardResponseApi transmitCardRequest(CardRequestSpi cardRequest) {
    CardResponseApi cardResponse;
    try {
      cardResponse = samReader.transmitCardRequest(cardRequest, ChannelControl.KEEP_OPEN);
    } catch (ReaderBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse());
      throw new ReaderIOException(
          MSG_SAM_READER_COMMUNICATION_ERROR
              + MSG_WHILE_TRANSMITTING_COMMANDS
              + getTransactionAuditDataAsString(),
          e);
    } catch (CardBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse());
      throw new SamIOException(
          MSG_SAM_COMMUNICATION_ERROR
              + MSG_WHILE_TRANSMITTING_COMMANDS
              + getTransactionAuditDataAsString(),
          e);
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
   * Prepares a "SelectDiversifier" command using a specific or the default key diversifier if it is
   * not already selected.
   *
   * @param specificKeyDiversifier The specific key diversifier (optional).
   * @since 2.2.0
   */
  final void prepareSelectDiversifierIfNeeded(byte[] specificKeyDiversifier) {
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
  final void prepareSelectDiversifierIfNeeded() {
    if (!Arrays.equals(currentKeyDiversifier, defaultKeyDiversifier)) {
      currentKeyDiversifier = defaultKeyDiversifier;
      prepareSelectDiversifier();
    }
  }

  /**
   * (private)<br>
   * Prepares a "SelectDiversifier" command using the current key diversifier.
   *
   * @return The current instance.
   */
  private void prepareSelectDiversifier() {
    samCommands.add(new CmdSamSelectDiversifier(sam.getProductType(), currentKeyDiversifier));
  }
}
