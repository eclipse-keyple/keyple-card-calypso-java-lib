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
package org.eclipse.keyple.calypso;

import java.util.ArrayList;
import java.util.List;
import org.eclipse.keyple.calypso.sam.CalypsoSamCardSelection;
import org.eclipse.keyple.calypso.sam.CalypsoSamCardSelector;
import org.eclipse.keyple.calypso.transaction.CalypsoDesynchronizedExchangesException;
import org.eclipse.keyple.core.card.*;
import org.eclipse.keyple.core.card.spi.CardSelectionSpi;
import org.eclipse.keyple.core.card.spi.SmartCardSpi;
import org.eclipse.keyple.core.service.selection.spi.CardSelector;
import org.eclipse.keyple.core.util.Assert;

/**
 * (package-private)<br>
 * Implementation of {@link CalypsoSamCardSelection}.
 *
 * @since 2.0
 */
class CalypsoSamCardSelectionAdapter implements CalypsoSamCardSelection, CardSelectionSpi {

  private final CalypsoSamCardSelector calypsoSamCardSelector;
  private final ArrayList<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>>
      commandBuilders;

  /**
   * (package-private)<br>
   * Creates a {@link CalypsoSamCardSelection}.<br>
   * Prepares the unlock command if unlock data are defined in the provided {@link
   * CalypsoSamCardSelector}.
   *
   * @param calypsoSamCardSelector The SAM selector.
   * @since 2.0
   */
  CalypsoSamCardSelectionAdapter(CalypsoSamCardSelector calypsoSamCardSelector) {

    Assert.getInstance().notNull(calypsoSamCardSelector, "calypsoPoCardSelector");

    this.calypsoSamCardSelector = calypsoSamCardSelector;
    this.commandBuilders =
        new ArrayList<AbstractSamCommandBuilder<? extends AbstractSamResponseParser>>();

    // TODO check if it is the right place to do this
    byte[] unlockData = calypsoSamCardSelector.getUnlockData();
    if (unlockData != null) {
      // a unlock data value has been set, let's add the unlock command to be executed
      // following the selection
      commandBuilders.add(
          new SamUnlockBuilder(
              calypsoSamCardSelector.getTargetSamRevision(),
              calypsoSamCardSelector.getUnlockData()));
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSelectionRequest getCardSelectionRequest() {
    List<ApduRequest> cardSelectionApduRequests = new ArrayList<ApduRequest>();
    for (AbstractSamCommandBuilder<? extends AbstractSamResponseParser> commandBuilder :
        commandBuilders) {
      cardSelectionApduRequests.add(commandBuilder.getApduRequest());
    }
    // TODO check the boolean use in every creation of CardRequest
    return new CardSelectionRequest(
        calypsoSamCardSelector, new CardRequest(cardSelectionApduRequests, false));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SmartCardSpi parse(CardSelectionResponse cardSelectionResponse) {

    if (commandBuilders.size() == 1) {
      // an unlock command has been requested
      List<ApduResponse> apduResponses = cardSelectionResponse.getCardResponse().getApduResponses();
      if (apduResponses == null) {
        throw new CalypsoDesynchronizedExchangesException(
            "Mismatch in the number of requests/responses");
      }
      // check the SAM response to the unlock command
      try {
        commandBuilders.get(0).createResponseParser(apduResponses.get(0)).checkStatus();
      } catch (CalypsoSamCommandException e) {
        // TODO check what to do here!
        e.printStackTrace();
      }
    }

    return new CalypsoSamSmartCardAdapter(cardSelectionResponse);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSelector getCardSelector() {
    return calypsoSamCardSelector;
  }
}
