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
import org.eclipse.keyple.card.calypso.po.PoCardSelection;
import org.eclipse.keyple.card.calypso.po.SelectFileControl;
import org.eclipse.keyple.card.calypso.transaction.CalypsoDesynchronizedExchangesException;
import org.eclipse.keyple.card.calypso.transaction.CalypsoPoAnomalyException;
import org.eclipse.keyple.core.card.*;
import org.eclipse.keyple.core.card.spi.CardSelectionSpi;
import org.eclipse.keyple.core.card.spi.SmartCardSpi;
import org.eclipse.keyple.core.service.selection.CardSelector;
import org.eclipse.keyple.core.util.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Implementation of {@link PoCardSelection}.
 *
 * @since 2.0
 */
final class PoCardSelectionAdapter implements PoCardSelection, CardSelectionSpi {

  private static final Logger logger = LoggerFactory.getLogger(PoCardSelectionAdapter.class);

  private static final int SW_PO_INVALIDATED = 0x6283;

  private final List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> commandBuilders;
  private final CardSelector poCardSelector;
  private final PoClass poClass;

  /**
   * (package-private)<br>
   * Creates an instance of {@link PoCardSelection}.
   *
   * @param poCardSelector A card selector.
   * @since 2.0
   * @throws IllegalArgumentException If poCardSelector is null.
   */
  PoCardSelectionAdapter(CardSelector poCardSelector, boolean acceptInvalidatedPo) {

    Assert.getInstance().notNull(poCardSelector, "poCardSelector");

    this.poCardSelector = poCardSelector;

    if (acceptInvalidatedPo) {
      this.poCardSelector.addSuccessfulStatusCode(SW_PO_INVALIDATED);
    }

    this.commandBuilders =
        new ArrayList<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>>();
    // deduces the class of the PO according to the type of selection
    if (poCardSelector.getAid() == null) {
      poClass = PoClass.LEGACY;
    } else {
      poClass = PoClass.ISO;
    }

    if (logger.isTraceEnabled()) {
      logger.trace("Calypso {} selector", poClass);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoCardSelection prepareReadRecordFile(byte sfi, int recordNumber) {
    commandBuilders.add(CalypsoPoUtils.prepareReadRecordFile(poClass, sfi, recordNumber));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoCardSelection prepareSelectFile(byte[] lid) {
    commandBuilders.add(CalypsoPoUtils.prepareSelectFile(poClass, lid));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoCardSelection prepareSelectFile(short lid) {
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
  public PoCardSelection prepareSelectFile(SelectFileControl selectControl) {
    commandBuilders.add(CalypsoPoUtils.prepareSelectFile(poClass, selectControl));
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
      for (AbstractPoCommandBuilder<? extends AbstractPoResponseParser> commandBuilder :
          commandBuilders) {
        cardSelectionApduRequests.add(commandBuilder.getApduRequest());
      }
      return new CardSelectionRequest(
          poCardSelector, new CardRequest(cardSelectionApduRequests, false));
    } else {
      return new CardSelectionRequest(poCardSelector, null);
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

    PoSmartCardAdapter calypsoPoSmartCard = new PoSmartCardAdapter(cardSelectionResponse);

    if (!commandBuilders.isEmpty()) {
      try {
        CalypsoPoUtils.updateCalypsoPo(calypsoPoSmartCard, commandBuilders, apduResponses);
      } catch (CalypsoPoCommandException e) {
        throw new CalypsoPoAnomalyException(
            "An error occurred while parsing the card selection request responses", e);
      }
    }

    return calypsoPoSmartCard;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSelector getCardSelector() {
    return poCardSelector;
  }
}
