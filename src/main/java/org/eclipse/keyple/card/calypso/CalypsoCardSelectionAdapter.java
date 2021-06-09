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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.calypsonet.terminal.calypso.SelectFileControl;
import org.calypsonet.terminal.calypso.card.CalypsoCardSelection;
import org.calypsonet.terminal.calypso.transaction.CardAnomalyException;
import org.calypsonet.terminal.calypso.transaction.DesynchronizedExchangesException;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardResponseApi;
import org.calypsonet.terminal.card.CardSelectionResponseApi;
import org.calypsonet.terminal.card.spi.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Implementation of {@link CalypsoCardSelection}.
 *
 * @since 2.0
 */
final class CalypsoCardSelectionAdapter implements CalypsoCardSelection, CardSelectionSpi {

  private static final int AID_MIN_LENGTH = 5;
  private static final int AID_MAX_LENGTH = 16;
  private static final int SW_CARD_INVALIDATED = 0x6283;

  private final List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>>
      commandBuilders;
  private final CardSelectorAdapter cardSelector;
  private final CalypsoCardClass calypsoCardClass;

  /**
   * (package-private)<br>
   * Creates an instance of {@link CalypsoCardSelection}.
   *
   * @since 2.0
   * @throws IllegalArgumentException If cardSelector is null.
   */
  CalypsoCardSelectionAdapter() {

    cardSelector = new CardSelectorAdapter();

    this.commandBuilders =
        new ArrayList<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>>();
    // deduces the class of the card according to the type of selection
    if (cardSelector.getAid() == null) {
      calypsoCardClass = CalypsoCardClass.LEGACY;
    } else {
      calypsoCardClass = CalypsoCardClass.ISO;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
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
   * @since 2.0
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
   * @since 2.0
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
   * @since 2.0
   */
  @Override
  public CalypsoCardSelection filterByDfName(String aid) {
    this.filterByDfName(ByteArrayUtil.fromHex(aid));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
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
   * @since 2.0
   */
  @Override
  public CalypsoCardSelection setFileControlInformation(
      FileControlInformation fileControlInformation) {

    Assert.getInstance().notNull(fileControlInformation, "fileControlInformation");

    switch (fileControlInformation) {
      case FCI:
        cardSelector.setFileControlInformation(CardSelectorSpi.FileControlInformation.FCI);
        break;
      case NO_RESPONSE:
        cardSelector.setFileControlInformation(CardSelectorSpi.FileControlInformation.NO_RESPONSE);
        break;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoCardSelection addSuccessfulStatusWord(int statusWord) {
    cardSelector.addSuccessfulStatusWord(statusWord);
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoCardSelection acceptInvalidatedCard() {
    cardSelector.addSuccessfulStatusWord(SW_CARD_INVALIDATED);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoCardSelection prepareReadRecordFile(byte sfi, int recordNumber) {
    commandBuilders.add(
        CalypsoCardUtils.prepareReadRecordFile(calypsoCardClass, sfi, recordNumber));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoCardSelection prepareSelectFile(byte[] lid) {
    Assert.getInstance().notNull(lid, "lid").isEqual(lid.length, 2, "lid length");
    commandBuilders.add(CalypsoCardUtils.prepareSelectFile(calypsoCardClass, lid));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoCardSelection prepareSelectFile(short lid) {
    byte[] bLid =
        new byte[] {
          (byte) ((lid >> 8) & 0xff), (byte) (lid & 0xff),
        };
    prepareSelectFile(bLid);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoCardSelection prepareSelectFile(SelectFileControl selectControl) {
    commandBuilders.add(CalypsoCardUtils.prepareSelectFile(calypsoCardClass, selectControl));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSelectionRequestSpi getCardSelectionRequest() {
    List<ApduRequestSpi> cardSelectionApduRequests = new ArrayList<ApduRequestSpi>();
    if (!commandBuilders.isEmpty()) {
      for (AbstractCardCommandBuilder<? extends AbstractCardResponseParser> commandBuilder :
          commandBuilders) {
        cardSelectionApduRequests.add(commandBuilder.getApduRequest());
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
   * @since 2.0
   */
  @Override
  // TODO check how to handle exceptions in this method
  public SmartCardSpi parse(CardSelectionResponseApi cardSelectionResponse) {
    CardResponseApi cardResponse = cardSelectionResponse.getCardResponse();

    List<ApduResponseApi> apduResponses;

    if (cardResponse != null) {
      apduResponses = cardResponse.getApduResponses();
    } else {
      apduResponses = Collections.emptyList();
    }

    if (commandBuilders.size() != apduResponses.size()) {
      throw new DesynchronizedExchangesException("Mismatch in the number of requests/responses");
    }

    CalypsoCardAdapter calypsoCard = new CalypsoCardAdapter(cardSelectionResponse);

    if (!commandBuilders.isEmpty()) {
      try {
        CalypsoCardUtils.updateCalypsoCard(calypsoCard, commandBuilders, apduResponses);
      } catch (CardCommandException e) {
        throw new CardAnomalyException(
            "An error occurred while parsing the card selection request responses", e);
      }
    }

    return calypsoCard;
  }
}
