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
import org.calypsonet.terminal.calypso.transaction.CommonSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.InconsistentDataException;
import org.calypsonet.terminal.calypso.transaction.InvalidCardSignatureException;
import org.calypsonet.terminal.calypso.transaction.InvalidSignatureException;
import org.calypsonet.terminal.calypso.transaction.ReaderIOException;
import org.calypsonet.terminal.calypso.transaction.SamIOException;
import org.calypsonet.terminal.calypso.transaction.SamRevokedException;
import org.calypsonet.terminal.calypso.transaction.SamSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.SamTransactionManager;
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
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Implementation of {@link SamTransactionManager}.
 *
 * @since 2.2.0
 */
final class SamTransactionManagerAdapter
    extends CommonTransactionManagerAdapter<SamTransactionManager, SamSecuritySetting>
    implements SamTransactionManager {

  private static final Logger logger = LoggerFactory.getLogger(SamTransactionManagerAdapter.class);

  private static final String MSG_INPUT_OUTPUT_DATA = "input/output data";
  private static final String MSG_SIGNATURE_SIZE = "signature size";
  private static final String MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8 =
      "key diversifier size is in range [1..8]";

  /* Final fields */
  private final ProxyReaderApi samReader;
  private final CalypsoSamAdapter sam;
  private final SamSecuritySettingAdapter securitySetting;
  private final List<AbstractSamCommand> samCommands = new ArrayList<AbstractSamCommand>();
  private final byte[] defaultKeyDiversifier;

  /* Dynamic fields */
  private byte[] currentKeyDiversifier;

  /**
   * (package-private)<br>
   * Creates a new instance.
   *
   * @param samReader The reader through which the SAM communicates.
   * @param sam The initial SAM data provided by the selection process.
   * @param securitySetting The security settings (optional).
   * @since 2.2.0
   */
  SamTransactionManagerAdapter(
      ProxyReaderApi samReader, CalypsoSamAdapter sam, SamSecuritySettingAdapter securitySetting) {
    super(sam, securitySetting, null);
    this.samReader = samReader;
    this.sam = sam;
    this.securitySetting = securitySetting;
    this.defaultKeyDiversifier = sam.getSerialNumber();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SamSecuritySetting getSecuritySetting() {
    return securitySetting;
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
  public final CalypsoSamAdapter getCalypsoSam() {
    return sam;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final SamTransactionManager prepareComputeSignature(CommonSignatureComputationData data) {

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
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final SamTransactionManager prepareVerifySignature(CommonSignatureVerificationData data) {

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
      samCommands.add(new CmdSamPsoVerifySignature(sam, dataAdapter));

    } else {
      throw new IllegalArgumentException(
          "The provided data must be an instance of 'CommonSignatureVerificationDataAdapter'");
    }
    return this;
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
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SamTransactionManager processCommands() {
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
                + apduResponses.size()
                + getTransactionAuditDataAsString());
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
            throw new InvalidCardSignatureException("Invalid card signature.", e);
          } else if ((commandRef == CalypsoSamCommand.PSO_VERIFY_SIGNATURE
                  || commandRef == CalypsoSamCommand.DATA_CIPHER)
              && e instanceof CalypsoSamSecurityDataException) {
            throw new InvalidSignatureException("Invalid signature.", e);
          } else if (commandRef == CalypsoSamCommand.SV_CHECK
              && e instanceof CalypsoSamSecurityDataException) {
            throw new InvalidCardSignatureException("Invalid SV card signature.", e);
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
                + apduResponses.size()
                + getTransactionAuditDataAsString());
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
   * Prepares a "SelectDiversifier" command using a specific or the default key diversifier if it is
   * not already selected.
   *
   * @param specificKeyDiversifier The specific key diversifier (optional).
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
   * Prepares a "SelectDiversifier" command using the default key diversifier if it is not already
   * selected.
   */
  private void prepareSelectDiversifierIfNeeded() {
    if (!Arrays.equals(currentKeyDiversifier, defaultKeyDiversifier)) {
      currentKeyDiversifier = defaultKeyDiversifier;
      prepareSelectDiversifier();
    }
  }

  /**
   * Prepares a "SelectDiversifier" command using the current key diversifier.
   *
   * @return The current instance.
   */
  private void prepareSelectDiversifier() {
    samCommands.add(new CmdSamSelectDiversifier(sam, currentKeyDiversifier));
  }

  /* Constants */
  //  private static final int MIN_EVENT_COUNTER_NUMBER = 0;
  //  private static final int MAX_EVENT_COUNTER_NUMBER = 26;
  //  private static final int MIN_EVENT_CEILING_NUMBER = 0;
  //  private static final int MAX_EVENT_CEILING_NUMBER = 26;
  //  private static final int FIRST_COUNTER_REC1 = 0;
  //  private static final int LAST_COUNTER_REC1 = 8;
  //  private static final int FIRST_COUNTER_REC2 = 9;
  //  private static final int LAST_COUNTER_REC2 = 17;
  //  private static final int FIRST_COUNTER_REC3 = 18;
  //  private static final int LAST_COUNTER_REC3 = 26;
  //
  //  /**
  //   * (private)<br>
  //   * Overlapping interval test
  //   *
  //   * @param startA beginning of the A interval.
  //   * @param endA end of the A interval.
  //   * @param startB beginning of the B interval.
  //   * @param endB end of the B interval.
  //   * @return true if the intervals A and B overlap.
  //   */
  //  private boolean areIntervalsOverlapping(int startA, int endA, int startB, int endB) {
  //    return startA <= endB && endA >= startB;
  //  }
  //
  //  /**
  //   * {@inheritDoc}
  //   *
  //   * @since 2.2.3
  //   */
  //  @Override
  //  public SamTransactionManager prepareReadEventCounter(int eventCounterNumber) {
  //
  //    Assert.getInstance()
  //        .isInRange(
  //            eventCounterNumber,
  //            MIN_EVENT_COUNTER_NUMBER,
  //            MAX_EVENT_COUNTER_NUMBER,
  //            "eventCounterNumber");
  //
  //    getSamCommands()
  //        .add(
  //            new CmdSamReadEventCounter(
  //                getCalypsoSam(),
  //                CmdSamReadEventCounter.CounterOperationType.READ_SINGLE_COUNTER,
  //                eventCounterNumber));
  //    return this;
  //  }
  //
  //  /**
  //   * {@inheritDoc}
  //   *
  //   * @since 2.2.3
  //   */
  //  @Override
  //  public SamTransactionManager prepareReadEventCounters(
  //      int fromEventCounterNumber, int toEventCounterNumber) {
  //
  //    Assert.getInstance()
  //        .isInRange(
  //            fromEventCounterNumber,
  //            MIN_EVENT_COUNTER_NUMBER,
  //            MAX_EVENT_COUNTER_NUMBER,
  //            "fromEventCounterNumber")
  //        .isInRange(
  //            toEventCounterNumber,
  //            MIN_EVENT_COUNTER_NUMBER,
  //            MAX_EVENT_COUNTER_NUMBER,
  //            "toEventCounterNumber")
  //        .greaterOrEqual(
  //            toEventCounterNumber,
  //            fromEventCounterNumber,
  //            "fromEventCounterNumber/toEventCounterNumber");
  //
  //    if (areIntervalsOverlapping(
  //        FIRST_COUNTER_REC1, LAST_COUNTER_REC1, fromEventCounterNumber, toEventCounterNumber)) {
  //      getSamCommands()
  //          .add(
  //              new CmdSamReadEventCounter(
  //                  getCalypsoSam(),
  //                  CmdSamReadEventCounter.CounterOperationType.READ_COUNTER_RECORD,
  //                  1));
  //    }
  //    if (areIntervalsOverlapping(
  //        FIRST_COUNTER_REC2, LAST_COUNTER_REC2, fromEventCounterNumber, toEventCounterNumber)) {
  //      getSamCommands()
  //          .add(
  //              new CmdSamReadEventCounter(
  //                  getCalypsoSam(),
  //                  CmdSamReadEventCounter.CounterOperationType.READ_COUNTER_RECORD,
  //                  2));
  //    }
  //    if (areIntervalsOverlapping(
  //        FIRST_COUNTER_REC3, LAST_COUNTER_REC3, fromEventCounterNumber, toEventCounterNumber)) {
  //      getSamCommands()
  //          .add(
  //              new CmdSamReadEventCounter(
  //                  getCalypsoSam(),
  //                  CmdSamReadEventCounter.CounterOperationType.READ_COUNTER_RECORD,
  //                  3));
  //    }
  //    return this;
  //  }
  //
  //  /**
  //   * {@inheritDoc}
  //   *
  //   * @since 2.2.3
  //   */
  //  @Override
  //  public SamTransactionManager prepareReadEventCeiling(int eventCeilingNumber) {
  //
  //    Assert.getInstance()
  //        .isInRange(
  //            eventCeilingNumber,
  //            MIN_EVENT_CEILING_NUMBER,
  //            MAX_EVENT_CEILING_NUMBER,
  //            "eventCeilingNumber");
  //
  //    getSamCommands()
  //        .add(
  //            new CmdSamReadCeilings(
  //                getCalypsoSam(),
  //                CmdSamReadCeilings.CeilingsOperationType.READ_SINGLE_CEILING,
  //                eventCeilingNumber));
  //    return this;
  //  }
  //
  //  /**
  //   * {@inheritDoc}
  //   *
  //   * @since 2.2.3
  //   */
  //  @Override
  //  public SamTransactionManager prepareReadEventCeilings(
  //      int fromEventCeilingNumber, int toEventCeilingNumber) {
  //
  //    Assert.getInstance()
  //        .isInRange(
  //            fromEventCeilingNumber,
  //            MIN_EVENT_CEILING_NUMBER,
  //            MAX_EVENT_CEILING_NUMBER,
  //            "fromEventCeilingNumber")
  //        .isInRange(
  //            toEventCeilingNumber,
  //            MIN_EVENT_CEILING_NUMBER,
  //            MAX_EVENT_CEILING_NUMBER,
  //            "toEventCeilingNumber")
  //        .greaterOrEqual(
  //            toEventCeilingNumber,
  //            fromEventCeilingNumber,
  //            "fromEventCeilingNumber/toEventCeilingNumber");
  //
  //    if (areIntervalsOverlapping(
  //        FIRST_COUNTER_REC1, LAST_COUNTER_REC1, fromEventCeilingNumber, toEventCeilingNumber)) {
  //      getSamCommands()
  //          .add(
  //              new CmdSamReadCeilings(
  //                  getCalypsoSam(),
  //                  CmdSamReadCeilings.CeilingsOperationType.READ_CEILING_RECORD,
  //                  1));
  //    }
  //    if (areIntervalsOverlapping(
  //        FIRST_COUNTER_REC2, LAST_COUNTER_REC2, fromEventCeilingNumber, toEventCeilingNumber)) {
  //      getSamCommands()
  //          .add(
  //              new CmdSamReadCeilings(
  //                  getCalypsoSam(),
  //                  CmdSamReadCeilings.CeilingsOperationType.READ_CEILING_RECORD,
  //                  2));
  //    }
  //    if (areIntervalsOverlapping(
  //        FIRST_COUNTER_REC3, LAST_COUNTER_REC3, fromEventCeilingNumber, toEventCeilingNumber)) {
  //      getSamCommands()
  //          .add(
  //              new CmdSamReadCeilings(
  //                  getCalypsoSam(),
  //                  CmdSamReadCeilings.CeilingsOperationType.READ_CEILING_RECORD,
  //                  3));
  //    }
  //    return this;
  //  }
  //
  //  /**
  //   * {@inheritDoc}
  //   *
  //   * @since 2.2.3
  //   */
  //  @Override
  //  public SamTransactionManager prepareWriteEventCeiling(int eventCeilingNumber, int newValue) {
  //    return null;
  //  }
  //
  //  /**
  //   * {@inheritDoc}
  //   *
  //   * @since 2.2.3
  //   */
  //  @Override
  //  public SamTransactionManager prepareWriteEventCeilings(
  //      int fromEventCeilingNumber, List<Integer> newValues) {
  //    return null;
  //  }
}
