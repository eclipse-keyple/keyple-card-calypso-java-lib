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
import java.util.List;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardSelectionResponseApi;
import org.calypsonet.terminal.card.spi.*;
import org.calypsonet.terminal.reader.selection.spi.CardSelector;
import org.eclipse.keyple.card.calypso.sam.SamRevision;
import org.eclipse.keyple.card.calypso.transaction.CalypsoDesynchronizedExchangesException;
import org.eclipse.keyple.core.util.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Implementation of {@link SamCardSelection}.
 *
 * @since 2.0
 */
class SamCardSelectionAdapter implements SamCardSelection, CardSelectionSpi {
  private static final Logger logger = LoggerFactory.getLogger(SamCardSelectionAdapter.class);
  private final CardSelector samCardSelector;
  private final ArrayList<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>>
      commandBuilders;

  /**
   * (package-private)<br>
   * Creates a {@link SamCardSelection}.
   *
   * @param samCardSelector The SAM selector.
   * @since 2.0
   */
  SamCardSelectionAdapter(CardSelector samCardSelector) {

    Assert.getInstance().notNull(samCardSelector, "samCardSelector");

    this.samCardSelector = samCardSelector;
    this.commandBuilders =
        new ArrayList<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>>();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSelectionRequestSpi getCardSelectionRequest() {
    List<ApduRequestSpi> cardSelectionApduRequests = new ArrayList<ApduRequestSpi>();
    for (AbstractSamCommandBuilder<? extends AbstractSamResponseParser> commandBuilder :
        commandBuilders) {
      cardSelectionApduRequests.add(commandBuilder.getApduRequest());
    }
    if (!cardSelectionApduRequests.isEmpty()) {
      return new CardSelectionRequestAdapter(
          (CardSelectorSpi) samCardSelector,
          new CardRequestAdapter(cardSelectionApduRequests, false));
    } else {
      return new CardSelectionRequestAdapter((CardSelectorSpi) samCardSelector, null);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SmartCardSpi parse(CardSelectionResponseApi cardSelectionResponse) {

    if (commandBuilders.size() == 1) {
      // an unlock command has been requested
      List<ApduResponseApi> apduResponses =
          cardSelectionResponse.getCardResponse().getApduResponses();
      if (apduResponses == null) {
        throw new CalypsoDesynchronizedExchangesException(
            "Mismatch in the number of requests/responses");
      }
      // check the SAM response to the unlock command
      try {
        commandBuilders.get(0).createResponseParser(apduResponses.get(0)).checkStatus();
      } catch (CalypsoSamCommandException e) {
        // TODO check what to do here!
        logger.error("An exception occurred while parse the SAM responses: {}", e.getMessage());
      }
    }

    return new CalypsoSamAdapter(cardSelectionResponse);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSelector getCardSelector() {
    return samCardSelector;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public void prepareUnlock(SamRevision samRevision, byte[] unlockData) {

    Assert.getInstance()
        .notNull(samRevision, "samRevision")
        .notNull(unlockData, "unlockData")
        .isTrue(unlockData.length == 8 || unlockData.length == 16, "length");

    commandBuilders.add(new SamUnlockBuilder(samRevision, unlockData));
  }
}
