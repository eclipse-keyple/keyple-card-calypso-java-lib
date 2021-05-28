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

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.calypsonet.terminal.card.spi.CardSelectorSpi;
import org.calypsonet.terminal.reader.selection.spi.CardSelector;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;

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
public final class CalypsoCardSelectorAdapter implements CardSelectorSpi, CardSelector {

  private final String cardProtocol;
  private final String powerOnDataRegex;
  private final byte[] aid;
  private final FileOccurrence fileOccurrence;
  private final FileControlInformation fileControlInformation;
  private final LinkedHashSet<Integer> successfulSelectionStatusWords;

  /**
   * Builder of {@link CalypsoCardSelectorAdapter}.
   *
   * @since 2.0
   */
  public static final class Builder {
    private static final int AID_MIN_LENGTH = 5;
    private static final int AID_MAX_LENGTH = 16;
    private static final int DEFAULT_SUCCESSFUL_CODE = 0x9000;

    private String cardProtocol;
    private String powerOnDataRegex;
    private byte[] aid;
    private FileOccurrence fileOccurrence;
    private FileControlInformation fileControlInformation;
    private final LinkedHashSet<Integer> successfulSelectionStatusWords;

    /** (private) */
    private Builder() {
      this.successfulSelectionStatusWords = new LinkedHashSet<Integer>();
      this.successfulSelectionStatusWords.add(DEFAULT_SUCCESSFUL_CODE);
    }

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
    public Builder filterByCardProtocol(String cardProtocol) {

      Assert.getInstance().notEmpty(cardProtocol, "cardProtocol");

      if (this.cardProtocol != null) {
        throw new IllegalStateException(
            String.format("cardProtocol has already been set to '%s'", this.cardProtocol));
      }

      this.cardProtocol = cardProtocol;
      return this;
    }

    /**
     * Requests an power-on data-based filtering by defining a regular expression that will be
     * applied to the card's power-on data.
     *
     * <p>If it is set, only the cards whose power-on data is recognized by the provided regular
     * expression will match the card selector.
     *
     * @param powerOnDataRegex A valid regular expression
     * @return The object instance.
     * @throws IllegalArgumentException If the provided regular expression is null, empty or
     *     invalid.
     * @throws IllegalStateException If this parameter has already been set.
     * @since 2.0
     */
    public Builder filterByPowerOnData(String powerOnDataRegex) {

      Assert.getInstance().notEmpty(powerOnDataRegex, "powerOnDataRegex");

      if (this.powerOnDataRegex != null) {
        throw new IllegalStateException(
            String.format("powerOnDataRegex has already been set to '%s'", this.powerOnDataRegex));
      }

      try {
        Pattern.compile(powerOnDataRegex);
      } catch (PatternSyntaxException exception) {
        throw new IllegalArgumentException(
            String.format("Invalid regular expression: '%s'.", powerOnDataRegex));
      }

      this.powerOnDataRegex = powerOnDataRegex;
      return this;
    }

    /**
     * Requests a DF Name-based filtering by defining in a byte array the AID that will be included
     * in the standard SELECT APPLICATION command sent to the card during the selection process.
     *
     * <p>The provided AID can be a right truncated image of the target DF Name (see ISO 7816-4
     * 4.2).
     *
     * @param aid A byte array containing {@value AID_MIN_LENGTH} to {@value AID_MAX_LENGTH} bytes.
     * @return The object instance.
     * @throws IllegalArgumentException If the provided array is null or out of range.
     * @throws IllegalStateException If this parameter has already been set.
     * @since 2.0
     */
    public Builder filterByDfName(byte[] aid) {

      Assert.getInstance()
          .notNull(aid, "aid")
          .isInRange(aid.length, AID_MIN_LENGTH, AID_MAX_LENGTH, "aid");

      if (this.aid != null) {
        throw new IllegalStateException(
            String.format("aid has already been set to '%s'", ByteArrayUtil.toHex(this.aid)));
      }

      this.aid = aid;
      return this;
    }

    /**
     * Requests a DF Name-based filtering by defining in a hexadecimal string the AID that will be
     * included in the standard SELECT APPLICATION command sent to the card during the selection
     * process.
     *
     * <p>The provided AID can be a right truncated image of the target DF Name (see ISO 7816-4
     * 4.2).
     *
     * @param aid A hexadecimal string representation of {@value AID_MIN_LENGTH} to {@value
     *     AID_MAX_LENGTH} bytes.
     * @return The object instance.
     * @throws IllegalArgumentException If the provided AID is null, invalid or out of range.
     * @throws IllegalStateException If this parameter has already been set.
     * @since 2.0
     */
    public Builder filterByDfName(String aid) {
      return filterByDfName(ByteArrayUtil.fromHex(aid));
    }

    /**
     * Sets the file occurrence mode (see ISO7816-4).
     *
     * <p>The default value is {@link FileOccurrence#FIRST}.
     *
     * @param fileOccurrence The {@link FileOccurrence}.
     * @return The object instance.
     * @throws IllegalArgumentException If fileOccurrence is null.
     * @throws IllegalStateException If this parameter has already been set.
     * @since 2.0
     */
    public Builder setFileOccurrence(FileOccurrence fileOccurrence) {
      Assert.getInstance().notNull(fileOccurrence, "fileOccurrence");
      if (this.fileOccurrence != null) {
        throw new IllegalStateException(
            String.format("fileOccurrence has already been set to '%s'", this.fileOccurrence));
      }
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
     * @throws IllegalArgumentException If fileControlInformation is null.
     * @throws IllegalStateException If this parameter has already been set.
     * @since 2.0
     */
    public Builder setFileControlInformation(FileControlInformation fileControlInformation) {
      Assert.getInstance().notNull(fileControlInformation, "fileControlInformation");
      if (this.fileControlInformation != null) {
        throw new IllegalStateException(
            String.format(
                "fileControlInformation has already been set to '%s'",
                this.fileControlInformation));
      }
      this.fileControlInformation = fileControlInformation;
      return this;
    }

    /**
     * Add a status word to be accepted to the list of successful select application status words.
     *
     * @param statusWord The status word to be accepted.
     * @return The object instance.
     * @since 2.0
     */
    public Builder addSuccessfulStatusWord(int statusWord) {
      this.successfulSelectionStatusWords.add(statusWord);
      return this;
    }

    /**
     * Creates an instance of {@link CalypsoCardSelectorAdapter}.
     *
     * @return A not null reference.
     * @since 2.0
     */
    public CardSelector build() {
      return new CalypsoCardSelectorAdapter(this);
    }
  }

  /**
   * (private)<br>
   * Created an instance of {@link CalypsoCardSelectorAdapter}.
   *
   * @param builder The {@link Builder}.
   */
  private CalypsoCardSelectorAdapter(Builder builder) {
    this.cardProtocol = builder.cardProtocol;
    this.powerOnDataRegex = builder.powerOnDataRegex;
    this.aid = builder.aid;
    this.fileOccurrence =
        builder.fileOccurrence == null ? FileOccurrence.FIRST : builder.fileOccurrence;
    this.fileControlInformation =
        builder.fileControlInformation == null
            ? FileControlInformation.FCI
            : builder.fileControlInformation;
    this.successfulSelectionStatusWords = builder.successfulSelectionStatusWords;
  }

  /**
   * Creates builder to build a {@link CalypsoCardSelectorAdapter}.
   *
   * @return Created builder.
   * @since 2.0
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public final String getCardProtocol() {
    return cardProtocol;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public String getPowerOnDataRegex() {
    return powerOnDataRegex;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getAid() {
    return aid;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public FileOccurrence getFileOccurrence() {
    return fileOccurrence;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public FileControlInformation getFileControlInformation() {
    return fileControlInformation;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public Set<Integer> getSuccessfulSelectionStatusWords() {
    return successfulSelectionStatusWords;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public void addSuccessfulStatusWord(int statusWord) {
    this.successfulSelectionStatusWords.add(statusWord);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean powerOnDataMatches(byte[] powerOnData) {
    if (powerOnDataRegex != null) {
      return ByteArrayUtil.toHex(powerOnData).matches(powerOnDataRegex);
    } else {
      return true;
    }
  }

  @Override
  public String toString() {
    return "CARD_SELECTOR = " + JsonUtil.toJson(this);
  }
}
