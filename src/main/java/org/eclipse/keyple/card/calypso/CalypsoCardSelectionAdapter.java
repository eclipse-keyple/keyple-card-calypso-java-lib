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
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.calypsonet.terminal.calypso.GetDataTag;
import org.calypsonet.terminal.calypso.SelectFileControl;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.calypso.card.CalypsoCardSelection;
import org.calypsonet.terminal.calypso.transaction.InconsistentDataException;
import org.calypsonet.terminal.calypso.transaction.SelectFileException;
import org.calypsonet.terminal.calypso.transaction.UnexpectedCommandStatusException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardResponseApi;
import org.calypsonet.terminal.card.CardSelectionResponseApi;
import org.calypsonet.terminal.card.spi.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;

/**
 * Implementation of {@link CalypsoCardSelection}.
 *
 * @since 2.0.0
 */
final class CalypsoCardSelectionAdapter implements CalypsoCardSelection, CardSelectionSpi {

  private static final int AID_MIN_LENGTH = 5;
  private static final int AID_MAX_LENGTH = 16;
  private static final int SW_CARD_INVALIDATED = 0x6283;
  private static final String MSG_CARD_COMMAND_ERROR = "A card command error occurred ";

  private final List<CardCommand> commands;
  private final CardSelectorAdapter cardSelector;

  /**
   * Creates an instance of {@link CalypsoCardSelection}.
   *
   * @since 2.0.0
   * @throws IllegalArgumentException If cardSelector is null.
   */
  CalypsoCardSelectionAdapter() {

    cardSelector = new CardSelectorAdapter();

    this.commands = new ArrayList<CardCommand>();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelection filterByCardProtocol(String cardProtocol) {

    Assert.getInstance().notEmpty(cardProtocol, "cardProtocol");

    cardSelector.filterByCardProtocol(cardProtocol);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelection filterByPowerOnData(String powerOnDataRegex) {

    Assert.getInstance().notEmpty(powerOnDataRegex, "powerOnDataRegex");

    try {
      Pattern.compile(powerOnDataRegex);
    } catch (PatternSyntaxException exception) {
      throw new IllegalArgumentException(
          String.format("Invalid regular expression: '%s'.", powerOnDataRegex));
    }

    cardSelector.filterByPowerOnData(powerOnDataRegex);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelection filterByDfName(byte[] aid) {

    Assert.getInstance()
        .notNull(aid, "aid")
        .isInRange(aid.length, AID_MIN_LENGTH, AID_MAX_LENGTH, "aid");

    cardSelector.filterByDfName(aid);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelection filterByDfName(String aid) {
    Assert.getInstance().isHexString(aid, "aid format");
    this.filterByDfName(HexUtil.toByteArray(aid));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelection setFileOccurrence(FileOccurrence fileOccurrence) {

    Assert.getInstance().notNull(fileOccurrence, "fileOccurrence");

    switch (fileOccurrence) {
      case FIRST:
        cardSelector.setFileOccurrence(CardSelectorSpi.FileOccurrence.FIRST);
        break;
      case LAST:
        cardSelector.setFileOccurrence(CardSelectorSpi.FileOccurrence.LAST);
        break;
      case NEXT:
        cardSelector.setFileOccurrence(CardSelectorSpi.FileOccurrence.NEXT);
        break;
      case PREVIOUS:
        cardSelector.setFileOccurrence(CardSelectorSpi.FileOccurrence.PREVIOUS);
        break;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelection setFileControlInformation(
      FileControlInformation fileControlInformation) {

    Assert.getInstance().notNull(fileControlInformation, "fileControlInformation");

    if (fileControlInformation == FileControlInformation.FCI) {
      cardSelector.setFileControlInformation(CardSelectorSpi.FileControlInformation.FCI);
    } else if (fileControlInformation == FileControlInformation.NO_RESPONSE) {
      cardSelector.setFileControlInformation(CardSelectorSpi.FileControlInformation.NO_RESPONSE);
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Override
  @Deprecated
  public CalypsoCardSelection addSuccessfulStatusWord(int statusWord) {

    Assert.getInstance().isInRange(statusWord, 0, 0xFFFF, "statusWord");

    cardSelector.addSuccessfulStatusWord(statusWord);
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelection acceptInvalidatedCard() {
    cardSelector.addSuccessfulStatusWord(SW_CARD_INVALIDATED);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   * @deprecated
   */
  @Override
  @Deprecated
  public CalypsoCardSelection prepareReadRecordFile(byte sfi, int recordNumber) {
    return prepareReadRecord(sfi, recordNumber);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public CalypsoCardSelection prepareReadRecord(byte sfi, int recordNumber) {

    Assert.getInstance()
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            recordNumber,
            CalypsoCardConstant.NB_REC_MIN,
            CalypsoCardConstant.NB_REC_MAX,
            "recordNumber");

    commands.add(
        new CmdCardReadRecords(
            CalypsoCardClass.ISO, sfi, recordNumber, CmdCardReadRecords.ReadMode.ONE_RECORD, 0));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public CalypsoCardSelection prepareSingleStepSecureSession(
      WriteAccessLevel writeAccessLevel, boolean useExtendedMode) {
    Assert.getInstance().notNull(writeAccessLevel, "writeAccessLevel");
    commands.add(new CmdCardOpenSession(writeAccessLevel, 0, 0, useExtendedMode));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.2
   */
  @Override
  public CalypsoCardSelection prepareSingleStepSecureSession(
      WriteAccessLevel writeAccessLevel, boolean useExtendedMode, byte sfi, int recordNumber) {
    Assert.getInstance()
        .notNull(writeAccessLevel, "writeAccessLevel")
        .isInRange((int) sfi, CalypsoCardConstant.SFI_MIN, CalypsoCardConstant.SFI_MAX, "sfi")
        .isInRange(
            recordNumber,
            CalypsoCardConstant.NB_REC_MIN,
            CalypsoCardConstant.NB_REC_MAX,
            "recordNumber");
    commands.add(new CmdCardOpenSession(writeAccessLevel, sfi, recordNumber, useExtendedMode));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelection prepareGetData(GetDataTag tag) {
    Assert.getInstance().notNull(tag, "tag");

    // create the command and add it to the list of commands
    switch (tag) {
      case FCI_FOR_CURRENT_DF:
        commands.add(new CmdCardGetDataFci(CalypsoCardClass.ISO));
        break;
      case FCP_FOR_CURRENT_FILE:
        commands.add(new CmdCardGetDataFcp(CalypsoCardClass.ISO));
        break;
      case EF_LIST:
        commands.add(new CmdCardGetDataEfList(CalypsoCardClass.ISO));
        break;
      case TRACEABILITY_INFORMATION:
        commands.add(new CmdCardGetDataTraceabilityInformation(CalypsoCardClass.ISO));
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
   * @deprecated
   */
  @Override
  @Deprecated
  public CalypsoCardSelection prepareSelectFile(byte[] lid) {
    Assert.getInstance().notNull(lid, "lid").isEqual(lid.length, 2, "lid length");
    return prepareSelectFile((short) ByteArrayUtil.extractInt(lid, 0, 2, false));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelection prepareSelectFile(short lid) {
    commands.add(
        new CmdCardSelectFile(CalypsoCardClass.ISO, CalypsoCard.ProductType.PRIME_REVISION_3, lid));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public CalypsoCardSelection prepareSelectFile(SelectFileControl selectControl) {
    Assert.getInstance().notNull(selectControl, "selectControl");
    commands.add(new CmdCardSelectFile(CalypsoCardClass.ISO, selectControl));
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
    if (!commands.isEmpty()) {
      for (CardCommand command : commands) {
        cardSelectionApduRequests.add(command.getApduRequest());
      }
      return new CardSelectionRequestAdapter(
          cardSelector, new CardRequestAdapter(cardSelectionApduRequests, false));
    } else {
      return new CardSelectionRequestAdapter(cardSelector, null);
    }
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
   * @throws CardCommandException If a response from the card was unexpected.
   * @throws InconsistentDataException If the number of commands/responses does not match.
   */
  private void parseApduResponses(
      CalypsoCardAdapter calypsoCard,
      List<CardCommand> commands,
      List<ApduResponseApi> apduResponses)
      throws CardCommandException {

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
        commands.get(i).parseApduResponse(apduResponses.get(i), calypsoCard);
      } catch (CardCommandException e) {
        CardCommandRef commandRef = commands.get(i).getCommandRef();
        if (commandRef == CardCommandRef.READ_RECORDS
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
