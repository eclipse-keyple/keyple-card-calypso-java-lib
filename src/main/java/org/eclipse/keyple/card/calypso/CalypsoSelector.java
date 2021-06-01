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

import org.calypsonet.terminal.reader.selection.spi.CardSelector;

/**
 * Contains information needed to select a particular card.
 *
 * <p>Provides a builder to define 3 filtering levels based:
 *
 * <ul>
 *   <li>The card protocol.
 *   <li>A regular expression to be applied to the power-on data.
 *   <li>An Application Identifier (AID) used to create a standard SELECT APPLICATION Apdu with
 *       various options.
 * </ul>
 *
 * <p>All three filter levels are optional.
 *
 * <p>Also provides a method to check the match between the power-on data of a card and the defined
 * filter.
 *
 * @since 2.0
 */
public interface CalypsoSelector extends CardSelector {
  /**
   * Requests an protocol-based filtering by defining an expected card.
   *
   * <p>If the card protocol is set, only cards using that protocol will match the card selector.
   *
   * @param cardProtocol A not empty String.
   * @return The object instance.
   * @throws IllegalArgumentException If the argument is null or empty.
   * @throws IllegalStateException If this parameter has already been set.
   * @since 2.0
   */
  CalypsoSelector filterByCardProtocol(String cardProtocol);

  /**
   * Requests an power-on data-based filtering by defining a regular expression that will be applied
   * to the card's power-on data.
   *
   * <p>If it is set, only the cards whose power-on data is recognized by the provided regular
   * expression will match the card selector.
   *
   * @param powerOnDataRegex A valid regular expression
   * @return The object instance.
   * @throws IllegalArgumentException If the provided regular expression is null, empty or invalid.
   * @throws IllegalStateException If this parameter has already been set.
   * @since 2.0
   */
  CalypsoSelector filterByPowerOnData(String powerOnDataRegex);

  /**
   * Requests a DF Name-based filtering by defining in a byte array the AID that will be included in
   * the standard SELECT APPLICATION command sent to the card during the selection process.
   *
   * <p>The provided AID can be a right truncated image of the target DF Name (see ISO 7816-4 4.2).
   *
   * @param aid A byte array containing 5 to 16 bytes.
   * @return The object instance.
   * @throws IllegalArgumentException If the provided array is null or out of range.
   * @throws IllegalStateException If this parameter has already been set.
   * @since 2.0
   */
  CalypsoSelector filterByDfName(byte[] aid);

  /**
   * Requests a DF Name-based filtering by defining in a hexadecimal string the AID that will be
   * included in the standard SELECT APPLICATION command sent to the card during the selection
   * process.
   *
   * <p>The provided AID can be a right truncated image of the target DF Name (see ISO 7816-4 4.2).
   *
   * @param aid A hexadecimal string representation of 5 to 16 bytes.
   * @return The object instance.
   * @throws IllegalArgumentException If the provided AID is null, invalid or out of range.
   * @throws IllegalStateException If this parameter has already been set.
   * @since 2.0
   */
  CalypsoSelector filterByDfName(String aid);

  /**
   * Sets the file occurrence mode (see ISO7816-4).
   *
   * <p>The default value is {@link CardSelector.FileOccurrence#FIRST}.
   *
   * @param fileOccurrence The {@link CardSelector.FileOccurrence}.
   * @return The object instance.
   * @throws IllegalArgumentException If fileOccurrence is null.
   * @throws IllegalStateException If this parameter has already been set.
   * @since 2.0
   */
  CalypsoSelector setFileOccurrence(CardSelector.FileOccurrence fileOccurrence);

  /**
   * Sets the file control mode (see ISO7816-4).
   *
   * <p>The default value is {@link CardSelector.FileControlInformation#FCI}.
   *
   * @param fileControlInformation The {@link CardSelector.FileControlInformation}.
   * @return The object instance.
   * @throws IllegalArgumentException If fileControlInformation is null.
   * @throws IllegalStateException If this parameter has already been set.
   * @since 2.0
   */
  CalypsoSelector setFileControlInformation(
      CardSelector.FileControlInformation fileControlInformation);

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  CalypsoSelector addSuccessfulStatusWord(int statusWord);
}
