/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://www.calypsonet-asso.org/
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
import org.eclipse.keyple.card.calypso.card.CalypsoCardSelection;
import org.eclipse.keyple.card.calypso.card.SelectFileControl;
import org.eclipse.keyple.card.calypso.transaction.CalypsoCardAnomalyException;
import org.eclipse.keyple.card.calypso.transaction.CalypsoDesynchronizedExchangesException;
import org.eclipse.keyple.core.card.*;
import org.eclipse.keyple.core.card.spi.CardSelectionSpi;
import org.eclipse.keyple.core.card.spi.SmartCardSpi;
import org.eclipse.keyple.core.service.selection.CardSelector;
import org.eclipse.keyple.core.util.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Implementation of {@link CalypsoCardSelection}.
 *
 * @since 2.0
 */
final class CalypsoCardSelectionAdapter implements CalypsoCardSelection, CardSelectionSpi {

  private static final Logger logger = LoggerFactory.getLogger(CalypsoCardSelectionAdapter.class);

  private static final int SW_CARD_INVALIDATED = 0x6283;

  private final List<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>>
      commandBuilders;
  private final CardSelector cardSelector;
  private final CalypsoCardClass calypsoCardClass;

  /**
   * (package-private)<br>
   * Creates an instance of {@link CalypsoCardSelection}.
   *
   * @param cardSelector A card selector.
   * @since 2.0
   * @throws IllegalArgumentException If cardSelector is null.
   */
  CalypsoCardSelectionAdapter(CardSelector cardSelector, boolean acceptInvalidatedCard) {

    Assert.getInstance().notNull(cardSelector, "cardSelector");

    this.cardSelector = cardSelector;

    if (acceptInvalidatedCard) {
      this.cardSelector.addSuccessfulStatusCode(SW_CARD_INVALIDATED);
    }

    this.commandBuilders =
        new ArrayList<AbstractCardCommandBuilder<? extends AbstractCardResponseParser>>();
    // deduces the class of the card according to the type of selection
    if (cardSelector.getAid() == null) {
      calypsoCardClass = CalypsoCardClass.LEGACY;
    } else {
      calypsoCardClass = CalypsoCardClass.ISO;
    }

    if (logger.isTraceEnabled()) {
      logger.trace("Calypso {} selector", calypsoCardClass);
    }
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
  public CardSelectionRequest getCardSelectionRequest() {
    List<ApduRequest> cardSelectionApduRequests = new ArrayList<ApduRequest>();
    if (!commandBuilders.isEmpty()) {
      for (AbstractCardCommandBuilder<? extends AbstractCardResponseParser> commandBuilder :
          commandBuilders) {
        cardSelectionApduRequests.add(commandBuilder.getApduRequest());
      }
      return new CardSelectionRequest(
          cardSelector, new CardRequest(cardSelectionApduRequests, false));
    } else {
      return new CardSelectionRequest(cardSelector, null);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  // TODO check how to handle exceptions in this method
  public SmartCardSpi parse(CardSelectionResponse cardSelectionResponse) {
    CardResponse cardResponse = cardSelectionResponse.getCardResponse();

    List<ApduResponse> apduResponses;

    if (cardResponse != null) {
      apduResponses = cardResponse.getApduResponses();
    } else {
      apduResponses = Collections.emptyList();
    }

    if (commandBuilders.size() != apduResponses.size()) {
      throw new CalypsoDesynchronizedExchangesException(
          "Mismatch in the number of requests/responses");
    }

    CalypsoCardAdapter calypsoCard = new CalypsoCardAdapter(cardSelectionResponse);

    if (!commandBuilders.isEmpty()) {
      try {
        CalypsoCardUtils.updateCalypsoCard(calypsoCard, commandBuilders, apduResponses);
      } catch (CalypsoCardCommandException e) {
        throw new CalypsoCardAnomalyException(
            "An error occurred while parsing the card selection request responses", e);
      }
    }

    return calypsoCard;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSelector getCardSelector() {
    return cardSelector;
  }
}
