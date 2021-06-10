/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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

import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.calypsonet.terminal.card.spi.CardSelectionRequestSpi;
import org.calypsonet.terminal.card.spi.CardSelectorSpi;
import org.eclipse.keyple.core.util.json.JsonUtil;

/**
 * (package-private)<br>
 * This POJO contains the data used to define a selection case.
 *
 * <p>A selection case is defined by a {@link CardSelectorSpi} that target a particular smart card
 * and an optional {@link CardRequestSpi} containing additional APDU commands to be sent to the card
 * when the selection is successful.
 *
 * <p>One of the uses of this class is to open a logical communication channel with a card in order
 * to continue with other exchanges and carry out a complete transaction.
 *
 * @since 2.0
 */
final class CardSelectionRequestAdapter implements CardSelectionRequestSpi {

  private final CardSelectorSpi cardSelector;
  private final CardRequestSpi cardRequest;

  /**
   * Builds a card selection request to open a logical channel without sending additional APDUs.
   *
   * <p>The cardRequest field is set to null.
   *
   * @param cardSelector The card selector.
   * @since 2.0
   */
  public CardSelectionRequestAdapter(CardSelectorSpi cardSelector) {
    this(cardSelector, null);
  }

  /**
   * Builds a card selection request to open a logical channel with additional APDUs to be sent
   * after the selection step.
   *
   * @param cardSelector The card selector.
   * @param cardRequest The card request.
   * @since 2.0
   */
  public CardSelectionRequestAdapter(CardSelectorSpi cardSelector, CardRequestSpi cardRequest) {
    this.cardSelector = cardSelector;
    this.cardRequest = cardRequest;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSelectorSpi getCardSelector() {
    return cardSelector;
  }

  /**
   * Gets the card request.
   *
   * @return a {@link CardRequestSpi} or null if it has not been defined
   * @since 2.0
   */
  @Override
  public CardRequestSpi getCardRequest() {
    return cardRequest;
  }

  /**
   * Converts the card selection request into a string where the data is encoded in a json format.
   *
   * @return A not empty String
   * @since 2.0
   */
  @Override
  public String toString() {
    return "CARD_SELECTION_REQUEST = " + JsonUtil.toJson(this);
  }
}
