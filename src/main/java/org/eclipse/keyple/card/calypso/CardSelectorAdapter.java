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

import java.util.LinkedHashSet;
import java.util.Set;
import org.calypsonet.terminal.card.spi.CardSelectorSpi;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Implementation of {@link CardSelectorSpi}.
 *
 * @since 2.0.0
 */
final class CardSelectorAdapter implements CardSelectorSpi {

  private static final int DEFAULT_SUCCESSFUL_CODE = 0x9000;

  private String cardProtocol;
  private String powerOnDataRegex;
  private byte[] aid;
  private FileOccurrence fileOccurrence;
  private FileControlInformation fileControlInformation;
  private final Set<Integer> successfulSelectionStatusWords;

  /**
   * (package-private)<br>
   * Created an instance of {@link CardSelectorAdapter}.
   *
   * <p>Initialize default values.
   *
   * @since 2.0.0
   */
  CardSelectorAdapter() {
    fileOccurrence = FileOccurrence.FIRST;
    fileControlInformation = FileControlInformation.FCI;
    successfulSelectionStatusWords = new LinkedHashSet<Integer>();
    successfulSelectionStatusWords.add(DEFAULT_SUCCESSFUL_CODE);
  }

  /**
   * Sets a protocol-based filtering by defining an expected card.
   *
   * <p>If the card protocol is set, only cards using that protocol will match the card selector.
   *
   * @param cardProtocol A not empty String.
   * @return The object instance.
   * @since 2.0.0
   */
  public CardSelectorSpi filterByCardProtocol(String cardProtocol) {
    this.cardProtocol = cardProtocol;
    return this;
  }

  /**
   * Sets a power-on data-based filtering by defining a regular expression that will be applied to
   * the card's power-on data.
   *
   * <p>If it is set, only the cards whose power-on data is recognized by the provided regular
   * expression will match the card selector.
   *
   * @param powerOnDataRegex A valid regular expression
   * @return The object instance.
   * @since 2.0.0
   */
  public CardSelectorSpi filterByPowerOnData(String powerOnDataRegex) {
    this.powerOnDataRegex = powerOnDataRegex;
    return this;
  }

  /**
   * Sets a DF Name-based filtering by defining in a byte array the AID that will be included in the
   * standard SELECT APPLICATION command sent to the card during the selection process.
   *
   * <p>The provided AID can be a right truncated image of the target DF Name (see ISO 7816-4 4.2).
   *
   * @param aid A byte array containing 5 to 16 bytes.
   * @return The object instance.
   * @since 2.0.0
   */
  public CardSelectorSpi filterByDfName(byte[] aid) {
    this.aid = aid;
    return this;
  }

  /**
   * Sets a DF Name-based filtering by defining in a hexadecimal string the AID that will be
   * included in the standard SELECT APPLICATION command sent to the card during the selection
   * process.
   *
   * <p>The provided AID can be a right truncated image of the target DF Name (see ISO 7816-4 4.2).
   *
   * @param aid A hexadecimal string representation of 5 to 16 bytes.
   * @return The object instance.
   * @since 2.0.0
   */
  public CardSelectorSpi filterByDfName(String aid) {
    return filterByDfName(ByteArrayUtil.fromHex(aid));
  }

  /**
   * Sets the file occurrence mode (see ISO7816-4).
   *
   * <p>The default value is {@link FileOccurrence#FIRST}.
   *
   * @param fileOccurrence The {@link FileOccurrence}.
   * @return The object instance.
   * @since 2.0.0
   */
  public CardSelectorSpi setFileOccurrence(FileOccurrence fileOccurrence) {
    this.fileOccurrence = fileOccurrence;
    return this;
  }

  /**
   * Sets the file control mode (see ISO7816-4).
   *
   * <p>The default value is {@link FileControlInformation#FCI}.
   *
   * @param fileControlInformation The {@link FileControlInformation}.
   * @return The object instance.
   * @since 2.0.0
   */
  public CardSelectorSpi setFileControlInformation(FileControlInformation fileControlInformation) {
    this.fileControlInformation = fileControlInformation;
    return this;
  }

  /**
   * Adds a status word to the list of those that should be considered successful for the Select
   * Application APDU.
   *
   * <p>Note: initially, the list contains the standard successful status word {@code 9000h}.
   *
   * @param statusWord A positive int &le; {@code FFFFh}.
   * @return The object instance.
   * @since 2.0.0
   */
  public CardSelectorSpi addSuccessfulStatusWord(int statusWord) {
    this.successfulSelectionStatusWords.add(statusWord);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public final String getCardProtocol() {
    return cardProtocol;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getPowerOnDataRegex() {
    return powerOnDataRegex;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] getAid() {
    return aid;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public FileOccurrence getFileOccurrence() {
    return fileOccurrence;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public FileControlInformation getFileControlInformation() {
    return fileControlInformation;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public Set<Integer> getSuccessfulSelectionStatusWords() {
    return successfulSelectionStatusWords;
  }
}
