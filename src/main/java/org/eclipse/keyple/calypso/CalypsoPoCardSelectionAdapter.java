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
import org.eclipse.keyple.calypso.po.CalypsoPoCardSelection;
import org.eclipse.keyple.calypso.po.CalypsoPoCardSelector;
import org.eclipse.keyple.calypso.po.SelectFileControl;
import org.eclipse.keyple.calypso.transaction.CalypsoDesynchronizedExchangesException;
import org.eclipse.keyple.calypso.transaction.CalypsoPoAnomalyException;
import org.eclipse.keyple.core.card.*;
import org.eclipse.keyple.core.card.spi.CardSelectionSpi;
import org.eclipse.keyple.core.card.spi.SmartCardSpi;
import org.eclipse.keyple.core.service.selection.spi.CardSelector;
import org.eclipse.keyple.core.util.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class CalypsoPoCardSelectionAdapter
    implements CalypsoPoCardSelection, CardSelectionSpi, CalypsoPoCardSelectionInterface {

  private static final Logger logger = LoggerFactory.getLogger(CalypsoPoCardSelectionAdapter.class);

  private final List<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>> commandBuilders;
  private final CalypsoPoCardSelector cardSelector;
  private final PoClass poClass;

  CalypsoPoCardSelectionAdapter(CalypsoPoCardSelector cardSelector) {

    Assert.getInstance().notNull(cardSelector, "cardSelector");

    this.cardSelector = cardSelector;
    this.commandBuilders =
        new ArrayList<AbstractPoCommandBuilder<? extends AbstractPoResponseParser>>();
    // deduces the class of the PO according to the type of selection
    if (cardSelector.getAidSelector() == null) {
      poClass = PoClass.LEGACY;
    } else {
      poClass = PoClass.ISO;
    }

    if (logger.isTraceEnabled()) {
      logger.trace("Calypso {} selector", poClass);
    }
  }

  /**
   * Adds a command APDU to read a single record from the indicated EF.
   *
   * @param sfi the SFI of the EF to read
   * @param recordNumber the record number to read
   * @throws IllegalArgumentException if one of the provided argument is out of range
   * @since 2.0
   */
  public final void prepareReadRecordFile(byte sfi, int recordNumber) {
    commandBuilders.add(CalypsoPoUtils.prepareReadRecordFile(poClass, sfi, recordNumber));
  }

  /**
   * Adds a command APDU to select file with an LID provided as a 2-byte byte array.
   *
   * @param lid LID of the EF to select as a byte array
   * @throws IllegalArgumentException if the argument is not an array of 2 bytes
   * @since 2.0
   */
  public void prepareSelectFile(byte[] lid) {
    commandBuilders.add(CalypsoPoUtils.prepareSelectFile(poClass, lid));
  }

  /**
   * Adds a command APDU to select file with an LID provided as a short.
   *
   * @param lid A short
   * @since 2.0
   */
  public void prepareSelectFile(short lid) {
    byte[] bLid =
        new byte[] {
          (byte) ((lid >> 8) & 0xff), (byte) (lid & 0xff),
        };
    prepareSelectFile(bLid);
  }

  /**
   * Adds a command APDU to select file according to the provided {@link SelectFileControl} enum
   * entry indicating the navigation case: FIRST, NEXT or CURRENT.
   *
   * @param selectControl A {@link SelectFileControl} enum entry
   * @since 2.0
   */
  public void prepareSelectFile(SelectFileControl selectControl) {
    commandBuilders.add(CalypsoPoUtils.prepareSelectFile(poClass, selectControl));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSelectionRequest getCardSelectionRequest() {
    List<ApduRequest> cardSelectionApduRequests = new ArrayList<ApduRequest>();
    for (AbstractPoCommandBuilder<? extends AbstractPoResponseParser> commandBuilder :
        commandBuilders) {
      cardSelectionApduRequests.add(commandBuilder.getApduRequest());
    }
    // TODO check the boolean use in every creation of CardRequest
    return new CardSelectionRequest(
        cardSelector, new CardRequest(cardSelectionApduRequests, false));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  // TODO check how to handle exceptions in this method
  public SmartCardSpi parse(CardSelectionResponse cardSelectionResponse) {
    List<ApduResponse> apduResponses = cardSelectionResponse.getCardResponse().getApduResponses();

    if (commandBuilders.size() != apduResponses.size()) {
      throw new CalypsoDesynchronizedExchangesException(
          "Mismatch in the number of requests/responses");
    }

    CalypsoPoSmartCardAdapter calypsoPoSmartCard =
        new CalypsoPoSmartCardAdapter(cardSelectionResponse);

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
    return cardSelector;
  }
}
