/* **************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/
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

import java.util.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.card.GetDataTag;
import org.eclipse.keypop.calypso.card.PutDataTag;
import org.eclipse.keypop.calypso.card.SelectFileControl;
import org.eclipse.keypop.calypso.card.card.CalypsoCard;
import org.eclipse.keypop.calypso.card.card.ElementaryFile;
import org.eclipse.keypop.calypso.card.transaction.*;
import org.eclipse.keypop.card.*;
import org.eclipse.keypop.card.spi.ApduRequestSpi;
import org.eclipse.keypop.card.spi.CardRequestSpi;
import org.eclipse.keypop.reader.CardCommunicationException;
import org.eclipse.keypop.reader.InvalidCardResponseException;
import org.eclipse.keypop.reader.ReaderCommunicationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link TransactionManager}.
 *
 * <ul>
 *   <li>CL-APP-ISOL.1
 *   <li>CL-CMD-SEND.1
 *   <li>CL-CMD-RECV.1
 *   <li>CL-CMD-CASE.1
 *   <li>CL-CMD-LCLE.1
 *   <li>CL-CMD-DATAIN.1
 *   <li>CL-C1-5BYTE.1
 *   <li>CL-C1-MAC.1
 *   <li>CL-C4-LE.1
 *   <li>CL-CLA-CMD.1
 *   <li>CL-RFU-FIELDCMD.1
 *   <li>CL-RFU-VALUECMD.1
 *   <li>CL-RFU-FIELDRSP.1
 *   <li>CL-SW-ANALYSIS.1
 *   <li>CL-SW-SUCCESS.1
 *   <li>CL-SF-SFI.1
 *   <li>CL-PERF-HFLOW.1
 *   <li>CL-CSS-INFOEND.1
 *   <li>CL-SW-CHECK.1
 *   <li>CL-CSS-SMEXCEED.1
 *   <li>CL-CSS-6D006E00.1
 *   <li>CL-CSS-UNEXPERR.1
 *   <li>CL-CSS-INFOCSS.1
 *   <li>CL-CSS-OSSMODE.1
 *   <li>CL-SV-CMDMODE.1
 * </ul>
 *
 * @param <T> The type of the lowest level child object.
 * @since 3.0.0
 */
abstract class TransactionManagerAdapter<T extends TransactionManager<T>>
    implements TransactionManager<T> {

  private static final Logger logger = LoggerFactory.getLogger(TransactionManagerAdapter.class);

  /* Prefix/suffix used to compose exception messages */
  private static final String MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_NB_COMMANDS =
      "The number of commands/responses does not match: nb commands = ";
  private static final String MSG_NB_RESPONSES = ", nb responses = ";
  private static final String MSG_CARD_READER_COMMUNICATION_ERROR =
      "A communication error with the card reader occurred ";
  private static final String MSG_CARD_COMMUNICATION_ERROR =
      "A communication error with the card occurred ";
  private static final String MSG_CARD_COMMAND_ERROR = "A card command error occurred ";
  private static final String MSG_WHILE_TRANSMITTING_COMMANDS = "while transmitting commands";
  private static final String MSG_PIN_NOT_AVAILABLE = "PIN is not available for this card";
  private static final String MSG_RECORD_NUMBER = "record number";
  private static final String MSG_OFFSET = "offset";
  private static final String MSG_RECORD_DATA = "record data";
  private static final String MSG_RECORD_DATA_LENGTH = "record data length";
  private static final String MSG_SECURE_SESSION_OPEN = "Secure session open";
  private static final String MSG_PKI_MODE_IS_NOT_AVAILABLE_FOR_THIS_CARD =
      "PKI mode not available for this card";
  private static final String MSG_DATA_LENGTH = "data length";

  /* Final fields */
  T currentInstance = (T) this;
  final ProxyReaderApi cardReader;
  final CalypsoCardAdapter card;
  private final List<byte[]> transactionAuditData = new ArrayList<>();

  /* Dynamic fields */
  final List<Command> commands = new ArrayList<>();

  /**
   * Builds a new instance.
   *
   * @param cardReader The card reader to be used.
   * @param card The selected card on which to operate the transaction.
   * @since 3.0.0
   */
  TransactionManagerAdapter(ProxyReaderApi cardReader, CalypsoCardAdapter card) {
    this.cardReader = cardReader;
    this.card = card;
  }

  /**
   * Returns the transaction context.
   *
   * @return A non-null reference.
   * @since 3.0.0
   */
  abstract TransactionContextDto getTransactionContext();

  /**
   * @return The current command context as a new DTO instance containing a reference to the global
   *     transaction context.
   * @since 3.0.0
   */
  abstract CommandContextDto getCommandContext();

  /**
   * Returns the payload capacity.
   *
   * @return A positive value.
   * @since 3.0.0
   */
  abstract int getPayloadCapacity();

  /**
   * Resets the transaction fields and try to cancel silently the current secure session if opened,
   * without raising any exception.
   *
   * @since 3.0.0
   */
  abstract void resetTransaction();

  /**
   * Closes and opens a new secure session if the three following conditions are satisfied:
   *
   * <ul>
   *   <li>a secure session is open
   *   <li>the command will overflow the modifications buffer size
   *   <li>the multiple session mode is allowed
   * </ul>
   *
   * @param command The command.
   * @throws SessionBufferOverflowException If the command will overflow the modifications buffer
   *     size and the multiple session is not allowed.
   * @since 3.0.0
   */
  abstract void prepareNewSecureSessionIfNeeded(Command command);

  /**
   * @return True if it is possible to configure the auto read record into the open secure session
   *     command.
   * @since 3.0.0
   */
  abstract boolean canConfigureReadOnOpenSecureSession();

  /**
   * Executes the provided commands.
   *
   * @param commands The commands.
   * @param channelControl The channel control directive.
   * @since 3.0.0
   */
  final void executeCardCommands(
      List<Command> commands, org.eclipse.keypop.reader.ChannelControl channelControl) {

    // Retrieve the list of C-APDUs
    List<ApduRequestSpi> apduRequests = getApduRequests(commands);

    // Wrap the list of C-APDUs into a card request
    CardRequestSpi cardRequest = new CardRequestAdapter(apduRequests, true);

    // Transmit the commands to the card
    CardResponseApi cardResponse = transmitCardRequest(cardRequest, channelControl);

    // Retrieve the list of R-APDUs
    List<ApduResponseApi> apduResponses = cardResponse.getApduResponses(); // NOSONAR

    // If there are more responses than requests, then we are unable to fill the card image. In this
    // case we stop processing immediately because it may be a case of fraud, and we throw a
    // desynchronized exception.
    if (apduResponses.size() > commands.size()) {
      throw new InconsistentDataException(
          MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_NB_COMMANDS
              + commands.size()
              + MSG_NB_RESPONSES
              + apduResponses.size()
              + getTransactionAuditDataAsString());
    }

    // We go through all the responses (and not the requests) because there may be fewer in the
    // case of an error that occurred in strict mode. In this case the last response will raise an
    // exception.
    for (int i = 0; i < apduResponses.size(); i++) {
      Command command = commands.get(i);
      try {
        parseCommandResponse(command, apduResponses.get(i));
      } catch (CardCommandException e) {
        throw new InvalidCardResponseException(
            MSG_CARD_COMMAND_ERROR
                + "while processing responses to card commands: "
                + command.getCommandRef()
                + getTransactionAuditDataAsString(),
            e);
      }
    }

    // Finally, if no error has occurred and there are fewer responses than requests, then we
    // throw a desynchronized exception.
    if (apduResponses.size() < commands.size()) {
      throw new InconsistentDataException(
          MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_NB_COMMANDS
              + commands.size()
              + MSG_NB_RESPONSES
              + apduResponses.size()
              + getTransactionAuditDataAsString());
    }
  }

  /**
   * Parses the command's response.
   *
   * @param command The command.
   * @param apduResponse The response from the card.
   * @throws CardCommandException If there is an error in the card command.
   * @since 3.1.0
   */
  void parseCommandResponse(Command command, ApduResponseApi apduResponse)
      throws CardCommandException {
    command.parseResponse(apduResponse);
  }

  /**
   * Creates a list of {@link ApduRequestSpi} from a list of {@link Command}.
   *
   * @param commands The list of commands.
   * @return An empty list if there is no command.
   * @since 2.2.0
   */
  private static List<ApduRequestSpi> getApduRequests(List<Command> commands) {
    List<ApduRequestSpi> apduRequests = new ArrayList<>();
    if (commands != null) {
      for (Command command : commands) {
        apduRequests.add(command.getApduRequest());
      }
    }
    return apduRequests;
  }

  /**
   * Transmits a card request, processes and converts any exceptions.
   *
   * @param cardRequest The card request to transmit.
   * @param channelControl The channel control.
   * @return The card response.
   */
  private CardResponseApi transmitCardRequest(
      CardRequestSpi cardRequest, org.eclipse.keypop.reader.ChannelControl channelControl) {
    CardResponseApi cardResponse;
    try {
      cardResponse =
          cardReader.transmitCardRequest(cardRequest, mapToInternalChannelControl(channelControl));
    } catch (ReaderBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse());
      throw new ReaderCommunicationException(
          MSG_CARD_READER_COMMUNICATION_ERROR
              + MSG_WHILE_TRANSMITTING_COMMANDS
              + getTransactionAuditDataAsString(),
          e);
    } catch (CardBrokenCommunicationException e) {
      saveTransactionAuditData(cardRequest, e.getCardResponse());
      throw new CardCommunicationException(
          MSG_CARD_COMMUNICATION_ERROR
              + MSG_WHILE_TRANSMITTING_COMMANDS
              + getTransactionAuditDataAsString(),
          e);
    } catch (UnexpectedStatusWordException e) {
      cardResponse = e.getCardResponse();
    }
    saveTransactionAuditData(cardRequest, cardResponse);
    return cardResponse;
  }

  /**
   * Maps a ChannelControl provided by the Calypso layer to a ChannelControl provided by the Card
   * layer.
   *
   * @param channelControl The ChannelControl provided by the Calypso layer.
   * @return The corresponding ChannelControl provided by the Card layer.
   */
  private org.eclipse.keypop.card.ChannelControl mapToInternalChannelControl(
      org.eclipse.keypop.reader.ChannelControl channelControl) {
    return org.eclipse.keypop.card.ChannelControl.valueOf(channelControl.name());
  }

  /**
   * Saves the provided exchanged APDU commands in the list of transaction audit data.
   *
   * @param cardRequest The card request.
   * @param cardResponse The associated card response.
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
   * Returns a string representation of the transaction audit data.
   *
   * @return A non-empty string.
   * @since 3.0.0
   */
  final String getTransactionAuditDataAsString() {
    return "\nTransaction audit JSON data: {"
        + "\"targetSmartCard\":"
        + card.toString()
        + ","
        + "\"apdus\":"
        + JsonUtil.toJson(transactionAuditData)
        + "}";
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final T prepareSelectFile(short lid) {
    try {
      commands.add(new CommandSelectFile(getTransactionContext(), getCommandContext(), lid));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final T prepareSelectFile(SelectFileControl selectFileControl) {
    try {
      Assert.getInstance().notNull(selectFileControl, "selectFileControl");
      commands.add(
          new CommandSelectFile(getTransactionContext(), getCommandContext(), selectFileControl));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public T prepareGetData(GetDataTag tag) {
    try {
      if (getCommandContext().isSecureSessionOpen()) {
        throw new IllegalStateException(MSG_SECURE_SESSION_OPEN);
      }
      Assert.getInstance().notNull(tag, "tag");
      switch (tag) {
        case FCI_FOR_CURRENT_DF:
          commands.add(new CommandGetDataFci(getTransactionContext(), getCommandContext()));
          break;
        case FCP_FOR_CURRENT_FILE:
          commands.add(new CommandGetDataFcp(getTransactionContext(), getCommandContext()));
          break;
        case EF_LIST:
          commands.add(new CommandGetDataEfList(getTransactionContext(), getCommandContext()));
          break;
        case TRACEABILITY_INFORMATION:
          commands.add(
              new CommandGetDataTraceabilityInformation(
                  getTransactionContext(), getCommandContext()));
          break;
        case CARD_PUBLIC_KEY:
          commands.add(
              new CommandGetDataCardPublicKey(getTransactionContext(), getCommandContext()));
          break;
        case CARD_CERTIFICATE:
          commands.add(
              new CommandGetDataCertificate(
                  getTransactionContext(), getCommandContext(), true, true));
          commands.add(
              new CommandGetDataCertificate(
                  getTransactionContext(), getCommandContext(), true, false));
          break;
        case CA_CERTIFICATE:
          commands.add(
              new CommandGetDataCertificate(
                  getTransactionContext(), getCommandContext(), false, true));
          commands.add(
              new CommandGetDataCertificate(
                  getTransactionContext(), getCommandContext(), false, false));
          break;
        default:
          throw new UnsupportedOperationException("Unsupported Get Data tag: " + tag.name());
      }
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public T preparePutData(PutDataTag putDataTag, byte[] data) {
    if (getCommandContext().isSecureSessionOpen()) {
      throw new IllegalStateException(MSG_SECURE_SESSION_OPEN);
    }
    Assert.getInstance().notNull(putDataTag, "putDataTag").notNull(data, "data");
    switch (putDataTag) {
      case CARD_KEY_PAIR:
        preparePutDataCardKeyPair(putDataTag, data);
        break;
      case CARD_CERTIFICATE:
        preparePutDataCertificate(putDataTag, data, CalypsoCardConstant.CARD_CERTIFICATE_SIZE);
        break;
      case CA_CERTIFICATE:
        preparePutDataCertificate(putDataTag, data, CalypsoCardConstant.CA_CERTIFICATE_SIZE);
        break;
      default:
        throw new UnsupportedOperationException("Unsupported tag: " + putDataTag);
    }
    return currentInstance;
  }

  private void preparePutDataCardKeyPair(PutDataTag putDataTag, byte[] data) {

    if (!card.isPkiModeSupported()) {
      throw new UnsupportedOperationException(MSG_PKI_MODE_IS_NOT_AVAILABLE_FOR_THIS_CARD);
    }

    Assert.getInstance()
        .isEqual(data.length, CalypsoCardConstant.CARD_KEY_PAIR_SIZE, MSG_DATA_LENGTH);

    commands.add(
        new CommandPutData(getTransactionContext(), getCommandContext(), putDataTag, true, data));
  }

  private void preparePutDataCertificate(PutDataTag putDataTag, byte[] data, int certificateSize) {

    TransactionContextDto transactionContext = getTransactionContext();
    CommandContextDto commandContext = getCommandContext();
    int payloadCapacity = getTransactionContext().getCard().getPayloadCapacity();

    if (!card.isPkiModeSupported()) {
      throw new UnsupportedOperationException(MSG_PKI_MODE_IS_NOT_AVAILABLE_FOR_THIS_CARD);
    }

    Assert.getInstance().isEqual(data.length, certificateSize, MSG_DATA_LENGTH);

    commands.add(
        new CommandPutData(
            transactionContext,
            commandContext,
            putDataTag,
            true,
            Arrays.copyOf(
                data, payloadCapacity - CalypsoCardConstant.TAG_CERTIFICATE_HEADER_SIZE)));
    commands.add(
        new CommandPutData(
            transactionContext,
            commandContext,
            putDataTag,
            false,
            Arrays.copyOfRange(
                data,
                payloadCapacity - CalypsoCardConstant.TAG_CERTIFICATE_HEADER_SIZE,
                data.length)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final T prepareReadRecord(byte sfi, int recordNumber) {
    try {
      if (getCommandContext().isSecureSessionOpen()) {
        throw new IllegalStateException(MSG_SECURE_SESSION_OPEN);
      }

      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              recordNumber,
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              MSG_RECORD_NUMBER);

      // A null record size indicates that the card determines the output length.
      // However, "legacy case 1" cards require a non-zero value.
      Integer recordSize = card.isLegacyCase1() ? CalypsoCardConstant.LEGACY_REC_LENGTH : null;

      commands.add(
          new CommandReadRecords(
              getTransactionContext(),
              getCommandContext(),
              sfi,
              recordNumber,
              CommandReadRecords.ReadMode.ONE_RECORD,
              recordSize,
              recordSize != null ? recordSize : 0));

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final T prepareReadRecords(
      byte sfi, int fromRecordNumber, int toRecordNumber, int recordSize) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              fromRecordNumber,
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              "fromRecordNumber")
          .isInRange(
              toRecordNumber, fromRecordNumber, CalypsoCardConstant.NB_REC_MAX, "toRecordNumber")
          .isInRange(recordSize, 0, getPayloadCapacity(), "recordSize");

      if (toRecordNumber == fromRecordNumber
          || (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3
              && card.getProductType() != CalypsoCard.ProductType.LIGHT)) {
        // Creates N unitary "Read Records" commands.
        // Try to group the first read record command with the open secure session command.
        if (canConfigureReadOnOpenSecureSession()) {
          ((CommandOpenSecureSession) commands.get(commands.size() - 1))
              .configureReadMode(sfi, fromRecordNumber, recordSize);
          fromRecordNumber++;
        }
        for (int i = fromRecordNumber; i <= toRecordNumber; i++) {
          commands.add(
              new CommandReadRecords(
                  getTransactionContext(),
                  getCommandContext(),
                  sfi,
                  i,
                  CommandReadRecords.ReadMode.ONE_RECORD,
                  recordSize,
                  recordSize));
        }
      } else {
        // Manages the reading of multiple records taking into account the transmission capacity
        // of the card and the response format (2 extra bytes).
        // Multiple APDUs can be generated depending on record size and transmission capacity.
        int nbBytesPerRecord = recordSize + 2;
        int nbRecordsPerApdu = getPayloadCapacity() / nbBytesPerRecord;
        int dataSizeMaxPerApdu = nbRecordsPerApdu * nbBytesPerRecord;

        int currentRecordNumber = fromRecordNumber;
        int nbRecordsRemainingToRead = toRecordNumber - fromRecordNumber + 1;
        int currentLength;

        while (currentRecordNumber < toRecordNumber) {
          currentLength =
              nbRecordsRemainingToRead <= nbRecordsPerApdu
                  ? nbRecordsRemainingToRead * nbBytesPerRecord
                  : dataSizeMaxPerApdu;

          commands.add(
              new CommandReadRecords(
                  getTransactionContext(),
                  getCommandContext(),
                  sfi,
                  currentRecordNumber,
                  CommandReadRecords.ReadMode.MULTIPLE_RECORD,
                  currentLength,
                  recordSize));

          currentRecordNumber += (currentLength / nbBytesPerRecord);
          nbRecordsRemainingToRead -= (currentLength / nbBytesPerRecord);
        }

        // Optimization: prepare a read "one record" if possible for last iteration.
        if (currentRecordNumber == toRecordNumber) {
          commands.add(
              new CommandReadRecords(
                  getTransactionContext(),
                  getCommandContext(),
                  sfi,
                  currentRecordNumber,
                  CommandReadRecords.ReadMode.ONE_RECORD,
                  recordSize,
                  recordSize));
        }
      }

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final T prepareReadRecordsPartially(
      byte sfi, int fromRecordNumber, int toRecordNumber, int offset, int nbBytesToRead) {
    try {
      if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3
          && card.getProductType() != CalypsoCard.ProductType.LIGHT) {
        throw new UnsupportedOperationException(
            "'Read Record Multiple' command not available for this card");
      }
      if (getCommandContext().isSecureSessionOpen()) {
        throw new IllegalStateException(MSG_SECURE_SESSION_OPEN);
      }

      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              fromRecordNumber,
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              "fromRecordNumber")
          .isInRange(
              toRecordNumber, fromRecordNumber, CalypsoCardConstant.NB_REC_MAX, "toRecordNumber")
          .isInRange(
              offset, CalypsoCardConstant.OFFSET_MIN, CalypsoCardConstant.OFFSET_MAX, MSG_OFFSET)
          .isInRange(
              nbBytesToRead,
              CalypsoCardConstant.DATA_LENGTH_MIN,
              getPayloadCapacity(),
              "nbBytesToRead");

      int nbRecordsPerApdu = getPayloadCapacity() / nbBytesToRead;

      int currentRecordNumber = fromRecordNumber;

      while (currentRecordNumber <= toRecordNumber) {
        commands.add(
            new CommandReadRecordMultiple(
                getTransactionContext(),
                getCommandContext(),
                sfi,
                (byte) currentRecordNumber,
                (byte) offset,
                (byte) nbBytesToRead));
        currentRecordNumber += nbRecordsPerApdu;
      }

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final T prepareReadBinary(byte sfi, int offset, int nbBytesToRead) {
    try {
      if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3) {
        if (card.getProductType() == CalypsoCard.ProductType.PRIME_REVISION_2) {
          logger.warn("Command may not be supported for PRIME_REVISION_2 card: Read Binary");
        } else {
          throw new UnsupportedOperationException(
              "'Read Binary' command not available for this card");
        }
      }

      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              offset,
              CalypsoCardConstant.OFFSET_MIN,
              CalypsoCardConstant.OFFSET_BINARY_MAX,
              MSG_OFFSET)
          .greaterOrEqual(nbBytesToRead, 1, "nbBytesToRead");

      if (sfi > 0 && offset > 255) { // FFh
        // Tips to select the file: add a "Read Binary" command (read one byte at offset 0).
        commands.add(
            new CommandReadBinary(getTransactionContext(), getCommandContext(), sfi, 0, 1));
      }

      int currentLength;
      int currentOffset = offset;
      int nbBytesRemainingToRead = nbBytesToRead;
      do {
        currentLength = Math.min(nbBytesRemainingToRead, getPayloadCapacity());

        commands.add(
            new CommandReadBinary(
                getTransactionContext(), getCommandContext(), sfi, currentOffset, currentLength));

        currentOffset += currentLength;
        nbBytesRemainingToRead -= currentLength;
      } while (nbBytesRemainingToRead > 0);

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final T prepareReadCounter(byte sfi, int nbCountersToRead) {
    return prepareReadRecords(sfi, 1, 1, nbCountersToRead * 3);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final T prepareSearchRecords(SearchCommandData data) {
    try {
      if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3) {
        throw new UnsupportedOperationException(
            "'Search Record Multiple' command not available for this card");
      }
      if (!(data instanceof SearchCommandDataAdapter)) {
        throw new IllegalArgumentException(
            "The provided data must be an instance of 'SearchCommandDataAdapter'");
      }
      if (getCommandContext().isSecureSessionOpen()) {
        throw new IllegalStateException(MSG_SECURE_SESSION_OPEN);
      }

      SearchCommandDataAdapter dataAdapter = (SearchCommandDataAdapter) data;

      Assert.getInstance()
          .notNull(dataAdapter, "data")
          .isInRange(
              (int) dataAdapter.getSfi(),
              CalypsoCardConstant.SFI_MIN,
              CalypsoCardConstant.SFI_MAX,
              "sfi")
          .isInRange(
              dataAdapter.getRecordNumber(),
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              "startAtRecord")
          .isInRange(
              dataAdapter.getOffset(),
              CalypsoCardConstant.OFFSET_MIN,
              CalypsoCardConstant.OFFSET_MAX,
              MSG_OFFSET)
          .notNull(dataAdapter.getSearchData(), "searchData")
          .isInRange(
              dataAdapter.getSearchData().length,
              CalypsoCardConstant.DATA_LENGTH_MIN,
              getPayloadCapacity(),
              "searchData");
      if (dataAdapter.getMask() != null) {
        Assert.getInstance()
            .isInRange(
                dataAdapter.getMask().length,
                CalypsoCardConstant.DATA_LENGTH_MIN,
                dataAdapter.getSearchData().length,
                "mask");
      }

      commands.add(
          new CommandSearchRecordMultiple(
              getTransactionContext(), getCommandContext(), dataAdapter));

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final T prepareCheckPinStatus() {
    try {
      if (!card.isPinFeatureAvailable()) {
        throw new UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
      }
      commands.add(new CommandVerifyPin(getTransactionContext(), getCommandContext()));
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final T prepareAppendRecord(byte sfi, byte[] recordData) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .notNull(recordData, MSG_RECORD_DATA)
          .isInRange(recordData.length, 0, getPayloadCapacity(), MSG_RECORD_DATA_LENGTH);
      CommandAppendRecord command =
          new CommandAppendRecord(getTransactionContext(), getCommandContext(), sfi, recordData);
      prepareNewSecureSessionIfNeeded(command);
      commands.add(command);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final T prepareUpdateRecord(byte sfi, int recordNumber, byte[] recordData) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              recordNumber,
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              MSG_RECORD_NUMBER)
          .notNull(recordData, MSG_RECORD_DATA)
          .isInRange(recordData.length, 0, getPayloadCapacity(), MSG_RECORD_DATA_LENGTH);
      CommandUpdateRecord command =
          new CommandUpdateRecord(
              getTransactionContext(), getCommandContext(), sfi, recordNumber, recordData);
      prepareNewSecureSessionIfNeeded(command);
      commands.add(command);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final T prepareWriteRecord(byte sfi, int recordNumber, byte[] recordData) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              recordNumber,
              CalypsoCardConstant.NB_REC_MIN,
              CalypsoCardConstant.NB_REC_MAX,
              MSG_RECORD_NUMBER)
          .notNull(recordData, MSG_RECORD_DATA)
          .isInRange(recordData.length, 0, getPayloadCapacity(), MSG_RECORD_DATA_LENGTH);
      CommandWriteRecord command =
          new CommandWriteRecord(
              getTransactionContext(), getCommandContext(), sfi, recordNumber, recordData);
      prepareNewSecureSessionIfNeeded(command);
      commands.add(command);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final T prepareUpdateBinary(byte sfi, int offset, byte[] data) {
    return prepareUpdateOrWriteBinary(true, sfi, offset, data);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final T prepareWriteBinary(byte sfi, int offset, byte[] data) {
    return prepareUpdateOrWriteBinary(false, sfi, offset, data);
  }

  /**
   * Prepare an "Update/Write Binary" command.
   *
   * @param isUpdateCommand True if it is an "Update Binary" command, false if it is a "Write
   *     Binary" command.
   * @param sfi The SFI.
   * @param offset The offset.
   * @param data The data to update/write.
   * @return The current instance.
   */
  private T prepareUpdateOrWriteBinary(boolean isUpdateCommand, byte sfi, int offset, byte[] data) {
    try {
      if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3) {
        if (card.getProductType() == CalypsoCard.ProductType.PRIME_REVISION_2) {
          logger.warn(
              "Command may not be supported for PRIME_REVISION_2 card: Update/Write Binary");
        } else {
          throw new UnsupportedOperationException(
              "'Update/Write Binary' command not available for this card");
        }
      }

      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              offset,
              CalypsoCardConstant.OFFSET_MIN,
              CalypsoCardConstant.OFFSET_BINARY_MAX,
              MSG_OFFSET)
          .notEmpty(data, "data");

      if (sfi > 0 && offset > 255) { // FFh
        // Tips to select the file: add a "Read Binary" command (read one byte at offset 0).
        commands.add(
            new CommandReadBinary(getTransactionContext(), getCommandContext(), sfi, 0, 1));
      }

      int dataLength = data.length;

      int currentLength;
      int currentOffset = offset;
      int currentIndex = 0;
      do {
        currentLength = Math.min(dataLength - currentIndex, getPayloadCapacity());

        CommandUpdateOrWriteBinary command =
            new CommandUpdateOrWriteBinary(
                isUpdateCommand,
                getTransactionContext(),
                getCommandContext(),
                sfi,
                currentOffset,
                Arrays.copyOfRange(data, currentIndex, currentIndex + currentLength));
        prepareNewSecureSessionIfNeeded(command);
        commands.add(command);

        currentOffset += currentLength;
        currentIndex += currentLength;
      } while (currentIndex < dataLength);

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final T prepareIncreaseCounter(byte sfi, int counterNumber, int incValue) {
    return prepareIncreaseOrDecreaseCounter(false, sfi, counterNumber, incValue);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final T prepareIncreaseCounters(
      byte sfi, Map<Integer, Integer> counterNumberToIncValueMap) {
    return prepareIncreaseOrDecreaseCounters(false, sfi, counterNumberToIncValueMap);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final T prepareDecreaseCounter(byte sfi, int counterNumber, int decValue) {
    return prepareIncreaseOrDecreaseCounter(true, sfi, counterNumber, decValue);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public final T prepareDecreaseCounters(
      byte sfi, Map<Integer, Integer> counterNumberToDecValueMap) {
    return prepareIncreaseOrDecreaseCounters(true, sfi, counterNumberToDecValueMap);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final T prepareSetCounter(byte sfi, int counterNumber, int newValue) {
    try {
      Integer oldValue = null;
      ElementaryFile ef = card.getFileBySfi(sfi);
      if (ef != null) {
        oldValue = ef.getData().getContentAsCounterValue(counterNumber != 0 ? counterNumber : 1);
      }
      if (oldValue == null) {
        throw new IllegalStateException(
            "The value for counter " + counterNumber + " in file " + sfi + " is not available");
      }
      int delta = newValue - oldValue;
      if (delta > 0) {
        if (logger.isTraceEnabled()) {
          logger.trace(
              "Increment counter #{} (file {}h) from {} to {}",
              counterNumber,
              HexUtil.toHex(sfi),
              newValue - delta,
              newValue);
        }
        prepareIncreaseCounter(sfi, counterNumber, delta);
      } else if (delta < 0) {
        if (logger.isTraceEnabled()) {
          logger.trace(
              "Decrement counter #{} (file {}h) from {} to {}",
              counterNumber,
              HexUtil.toHex(sfi),
              newValue - delta,
              newValue);
        }
        prepareDecreaseCounter(sfi, counterNumber, -delta);
      } else {
        if (logger.isDebugEnabled()) {
          logger.debug(
              "Counter #{} (sfi {}h) already set to the desired value {}",
              counterNumber,
              HexUtil.toHex(sfi),
              newValue);
        }
      }

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * Factorisation of prepareDecreaseCounter and prepareIncreaseCounter.
   *
   * @param isDecreaseCommand True if is a decrease command, False if is an increase command.
   * @param sfi SFI of the EF to select.
   * @param counterNumber The number of the counter (must be zero in case of a simulated counter).
   * @param incDecValue Value to increment/decrement to the counter (defined as a positive int <=
   *     16777215 [FFFFFFh])
   * @return The current instance.
   * @since 3.0.0
   */
  T prepareIncreaseOrDecreaseCounter(
      boolean isDecreaseCommand, byte sfi, int counterNumber, int incDecValue) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              counterNumber,
              0, // Allows simulated counters
              getPayloadCapacity() / 3,
              "counterNumber")
          .isInRange(
              incDecValue,
              CalypsoCardConstant.CNT_VALUE_MIN,
              CalypsoCardConstant.CNT_VALUE_MAX,
              "incDecValue");
      CommandIncreaseOrDecrease command =
          new CommandIncreaseOrDecrease(
              isDecreaseCommand,
              getTransactionContext(),
              getCommandContext(),
              sfi,
              counterNumber,
              incDecValue);
      prepareNewSecureSessionIfNeeded(command);
      commands.add(command);
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * Factorisation of prepareDecreaseMultipleCounters and prepareIncreaseMultipleCounters.
   *
   * @param isDecreaseCommand True if is a decrease command, False if is an increase command.
   * @param sfi SFI of the EF to select.
   * @param counterNumberToIncDecValueMap The map containing the counter numbers to be
   *     incremented/decremented and their associated increment/decrement values.
   * @return The current instance.
   */
  private T prepareIncreaseOrDecreaseCounters(
      boolean isDecreaseCommand, byte sfi, Map<Integer, Integer> counterNumberToIncDecValueMap) {
    try {
      Assert.getInstance()
          .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
          .isInRange(
              counterNumberToIncDecValueMap.size(),
              1,
              getPayloadCapacity() / 3,
              "counterNumberToIncDecValueMap");
      for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
        Assert.getInstance()
            .isInRange(
                entry.getKey(),
                CalypsoCardConstant.NUM_CNT_MIN,
                getPayloadCapacity() / 3,
                "counterNumberToIncDecValueMapKey")
            .isInRange(
                entry.getValue(),
                CalypsoCardConstant.CNT_VALUE_MIN,
                CalypsoCardConstant.CNT_VALUE_MAX,
                "counterNumberToIncDecValueMapValue");
      }
      if (card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_3
          && card.getProductType() != CalypsoCard.ProductType.PRIME_REVISION_2) {
        for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
          if (isDecreaseCommand) {
            prepareDecreaseCounter(sfi, entry.getKey(), entry.getValue());
          } else {
            prepareIncreaseCounter(sfi, entry.getKey(), entry.getValue());
          }
        }
      } else {
        int nbCountersPerApdu = getPayloadCapacity() / 4;
        if (counterNumberToIncDecValueMap.size() <= nbCountersPerApdu) {
          CommandIncreaseOrDecreaseMultiple command =
              new CommandIncreaseOrDecreaseMultiple(
                  isDecreaseCommand,
                  getTransactionContext(),
                  getCommandContext(),
                  sfi,
                  new TreeMap<>(counterNumberToIncDecValueMap));
          prepareNewSecureSessionIfNeeded(command);
          commands.add(command);
        } else {
          // the number of counters exceeds the payload capacity, let's split into several apdu
          // commands
          int i = 0;
          TreeMap<Integer, Integer> map = new TreeMap<>();
          for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
            i++;
            map.put(entry.getKey(), entry.getValue());
            if (i == nbCountersPerApdu) {
              CommandIncreaseOrDecreaseMultiple command =
                  new CommandIncreaseOrDecreaseMultiple(
                      isDecreaseCommand,
                      getTransactionContext(),
                      getCommandContext(),
                      sfi,
                      new TreeMap<>(map));
              prepareNewSecureSessionIfNeeded(command);
              commands.add(command);
              i = 0;
              map.clear();
            }
          }
          if (!map.isEmpty()) {
            CommandIncreaseOrDecreaseMultiple command =
                new CommandIncreaseOrDecreaseMultiple(
                    isDecreaseCommand, getTransactionContext(), getCommandContext(), sfi, map);
            prepareNewSecureSessionIfNeeded(command);
            commands.add(command);
          }
        }
      }
    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final T prepareSvReadAllLogs() {
    try {
      if (!card.isSvFeatureAvailable()) {
        throw new UnsupportedOperationException("Stored Value not available for this card");
      }
      if (card.getApplicationSubtype() != CalypsoCardConstant.STORED_VALUE_FILE_STRUCTURE_ID) {
        throw new UnsupportedOperationException(
            "The currently selected application is not an SV application");
      }
      // reset SV data in CalypsoCard if any
      card.setSvData((byte) 0, null, null, 0, 0);
      prepareReadRecords(
          CalypsoCardConstant.SV_RELOAD_LOG_FILE_SFI,
          1,
          CalypsoCardConstant.SV_RELOAD_LOG_FILE_NB_REC,
          CalypsoCardConstant.SV_LOG_FILE_REC_LENGTH);
      prepareReadRecords(
          CalypsoCardConstant.SV_DEBIT_LOG_FILE_SFI,
          1,
          CalypsoCardConstant.SV_DEBIT_LOG_FILE_NB_REC,
          CalypsoCardConstant.SV_LOG_FILE_REC_LENGTH);

    } catch (RuntimeException e) {
      resetTransaction();
      throw e;
    }
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 3.1.0
   */
  @Override
  public T prepareGenerateAsymmetricKeyPair() {
    if (!card.isPkiModeSupported()) {
      throw new UnsupportedOperationException(MSG_PKI_MODE_IS_NOT_AVAILABLE_FOR_THIS_CARD);
    }
    if (getTransactionContext().isSecureSessionOpen()) {
      throw new IllegalStateException(MSG_SECURE_SESSION_OPEN);
    }
    commands.add(
        new CommandGenerateAsymmetricKeyPair(getTransactionContext(), getCommandContext()));
    return currentInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final List<byte[]> getTransactionAuditData() {
    // CL-CSS-INFODATA.1
    return transactionAuditData;
  }
}
