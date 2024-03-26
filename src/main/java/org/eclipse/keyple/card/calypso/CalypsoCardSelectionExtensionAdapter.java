/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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
import java.util.Collections;
import java.util.List;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.card.GetDataTag;
import org.eclipse.keypop.calypso.card.SelectFileControl;
import org.eclipse.keypop.calypso.card.WriteAccessLevel;
import org.eclipse.keypop.calypso.card.card.CalypsoCard;
import org.eclipse.keypop.calypso.card.card.CalypsoCardSelectionExtension;
import org.eclipse.keypop.calypso.card.transaction.InconsistentDataException;
import org.eclipse.keypop.calypso.card.transaction.SelectFileException;
import org.eclipse.keypop.calypso.card.transaction.UnexpectedCommandStatusException;
import org.eclipse.keypop.card.ApduResponseApi;
import org.eclipse.keypop.card.CardResponseApi;
import org.eclipse.keypop.card.CardSelectionResponseApi;
import org.eclipse.keypop.card.ParseException;
import org.eclipse.keypop.card.spi.*;

/**
 * Implementation of {@link CalypsoCardSelectionExtension}.
 *
 * @since 2.0.0
 */
final class CalypsoCardSelectionExtensionAdapter
    implements CalypsoCardSelectionExtension, CardSelectionExtensionSpi {

  private static final int SW_CARD_INVALIDATED = 0x6283;
  private static final String MSG_CARD_COMMAND_ERROR = "A card command error occurred ";

  private final List<Command> commands;
  private final TransactionContextDto transactionContext;
  private final CommandContextDto commandContext;
  private boolean isPreOpenPrepared;
  private boolean isInvalidatedCardAccepted;

  /**
   * Creates an instance of {@link CalypsoCardSelectionExtension}.
   *
   * @since 2.0.0
   * @throws IllegalArgumentException If cardSelector is null.
   */
  CalypsoCardSelectionExtensionAdapter() {
    commands = new ArrayList<Command>();
    transactionContext = new TransactionContextDto();
    commandContext = new CommandContextDto(false, false);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelectionExtension acceptInvalidatedCard() {
    isInvalidatedCardAccepted = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CalypsoCardSelectionExtension prepareReadRecord(byte sfi, int recordNumber) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            recordNumber,
            CalypsoCardConstant.NB_REC_MIN,
            CalypsoCardConstant.NB_REC_MAX,
            "recordNumber");
    commands.add(
        new CommandReadRecords(
            transactionContext,
            commandContext,
            sfi,
            recordNumber,
            CommandReadRecords.ReadMode.ONE_RECORD,
            0,
            0));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.3
   */
  @Override
  public CalypsoCardSelectionExtension prepareReadBinary(byte sfi, int offset, int nbBytesToRead) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            offset, CalypsoCardConstant.OFFSET_MIN, CalypsoCardConstant.OFFSET_BINARY_MAX, "offset")
        .greaterOrEqual(nbBytesToRead, 1, "nbBytesToRead");
    if (sfi > 0 && offset > 255) { // FFh
      // Tips to select the file: add a "Read Binary" command (read one byte at offset 0).
      commands.add(new CommandReadBinary(transactionContext, commandContext, sfi, 0, 1));
    }
    int currentLength;
    int currentOffset = offset;
    int nbBytesRemainingToRead = nbBytesToRead;
    do {
      currentLength =
          Math.min(nbBytesRemainingToRead, CalypsoCardConstant.DEFAULT_PAYLOAD_CAPACITY);
      commands.add(
          new CommandReadBinary(
              transactionContext, commandContext, sfi, currentOffset, currentLength));
      currentOffset += currentLength;
      nbBytesRemainingToRead -= currentLength;
    } while (nbBytesRemainingToRead > 0);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.3
   */
  @Override
  public CalypsoCardSelectionExtension prepareReadCounter(byte sfi, int nbCountersToRead) {
    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            nbCountersToRead,
            0,
            CalypsoCardConstant.DEFAULT_PAYLOAD_CAPACITY / 3,
            "nbCountersToRead");
    commands.add(
        new CommandReadRecords(
            transactionContext,
            commandContext,
            sfi,
            1,
            CommandReadRecords.ReadMode.ONE_RECORD,
            nbCountersToRead * 3,
            0));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.3
   */
  @Override
  public CalypsoCardSelectionExtension preparePreOpenSecureSession(
      WriteAccessLevel writeAccessLevel) {
    if (isPreOpenPrepared) {
      throw new IllegalStateException("'Pre-Open Secure Session' command already prepared");
    }
    Assert.getInstance().notNull(writeAccessLevel, "writeAccessLevel");
    commands.add(
        new CommandOpenSecureSession(transactionContext, commandContext, writeAccessLevel));
    isPreOpenPrepared = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelectionExtension prepareGetData(GetDataTag tag) {
    Assert.getInstance().notNull(tag, "tag");
    switch (tag) {
      case FCI_FOR_CURRENT_DF:
        commands.add(new CommandGetDataFci(transactionContext, commandContext));
        break;
      case FCP_FOR_CURRENT_FILE:
        commands.add(new CommandGetDataFcp(transactionContext, commandContext));
        break;
      case EF_LIST:
        commands.add(new CommandGetDataEfList(transactionContext, commandContext));
        break;
      case TRACEABILITY_INFORMATION:
        commands.add(new CommandGetDataTraceabilityInformation(transactionContext, commandContext));
        break;
      default:
        throw new UnsupportedOperationException("Unsupported Get Data tag: " + tag.name());
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelectionExtension prepareSelectFile(short lid) {
    commands.add(new CommandSelectFile(transactionContext, commandContext, lid));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelectionExtension prepareSelectFile(SelectFileControl selectControl) {
    Assert.getInstance().notNull(selectControl, "selectControl");
    commands.add(new CommandSelectFile(transactionContext, commandContext, selectControl));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CardSelectionRequestSpi getCardSelectionRequest() {
    List<ApduRequestSpi> cardSelectionApduRequests = new ArrayList<ApduRequestSpi>();
    CardSelectionRequestAdapter cardSelectionRequest;
    if (commands.isEmpty()) {
      cardSelectionRequest = new CardSelectionRequestAdapter(null);
    } else {
      for (Command command : commands) {
        cardSelectionApduRequests.add(command.getApduRequest());
      }
      cardSelectionRequest =
          new CardSelectionRequestAdapter(new CardRequestAdapter(cardSelectionApduRequests, false));
    }
    if (isInvalidatedCardAccepted) {
      cardSelectionRequest.addSuccessfulSelectionStatusWord(SW_CARD_INVALIDATED);
    }
    return cardSelectionRequest;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public SmartCardSpi parse(CardSelectionResponseApi cardSelectionResponse) throws ParseException {
    CardResponseApi cardResponse = cardSelectionResponse.getCardResponse();
    List<ApduResponseApi> apduResponses =
        cardResponse != null
            ? cardResponse.getApduResponses()
            : Collections.<ApduResponseApi>emptyList();
    if (commands.size() != apduResponses.size()) {
      throw new ParseException("Mismatch in the number of requests/responses.");
    }
    CalypsoCardAdapter calypsoCard;
    try {
      calypsoCard = new CalypsoCardAdapter(cardSelectionResponse);
      if (!commands.isEmpty()) {
        parseApduResponses(calypsoCard, commands, apduResponses);
      }
    } catch (Exception e) {
      throw new ParseException("Invalid card response: " + e.getMessage(), e);
    }
    if (calypsoCard.getProductType() == CalypsoCard.ProductType.UNKNOWN
        && cardSelectionResponse.getSelectApplicationResponse() == null
        && cardSelectionResponse.getPowerOnData() == null) {
      throw new ParseException(
          "Unable to create a CalypsoCard: no power-on data and no FCI provided.");
    }
    return calypsoCard;
  }

  /**
   * Parses the APDU responses and updates the Calypso card image.
   *
   * @param calypsoCard The Calypso card.
   * @param commands The list of commands that get the responses.
   * @param apduResponses The APDU responses returned by the card to all commands.
   */
  private static void parseApduResponses(
      CalypsoCardAdapter calypsoCard,
      List<? extends Command> commands,
      List<? extends ApduResponseApi> apduResponses) {
    // If there are more responses than requests, then we are unable to fill the card image. In this
    // case we stop processing immediately because it may be a case of fraud, and we throw a
    // desynchronized exception.
    if (apduResponses.size() > commands.size()) {
      throw new InconsistentDataException(
          "The number of commands/responses does not match: nb commands = "
              + commands.size()
              + ", nb responses = "
              + apduResponses.size());
    }
    // We go through all the responses (and not the requests) because there may be fewer in the
    // case of an error that occurred in strict mode. In this case the last response will raise an
    // exception.
    for (int i = 0; i < apduResponses.size(); i++) {
      try {
        commands.get(i).parseResponseForSelection(apduResponses.get(i), calypsoCard);
      } catch (CardCommandException e) {
        CardCommandRef commandRef = commands.get(i).getCommandRef();
        if (commandRef == CardCommandRef.READ_RECORDS
            || commandRef == CardCommandRef.READ_BINARY
            || commandRef == CardCommandRef.OPEN_SECURE_SESSION) {
          continue;
        }
        if (e instanceof CardDataAccessException && commandRef == CardCommandRef.SELECT_FILE) {
          throw new SelectFileException("File not found", e);
        } else {
          throw new UnexpectedCommandStatusException(
              MSG_CARD_COMMAND_ERROR + "while processing responses to card commands: " + commandRef,
              e);
        }
      }
    }
    // Finally, if no error has occurred and there are fewer responses than requests, then we
    // throw a desynchronized exception.
    if (apduResponses.size() < commands.size()) {
      throw new InconsistentDataException(
          "The number of commands/responses does not match: nb commands = "
              + commands.size()
              + ", nb responses = "
              + apduResponses.size());
    }
  }
}
