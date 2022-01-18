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

import org.calypsonet.terminal.calypso.SearchCommandData;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.calypso.card.CalypsoCardSelection;
import org.calypsonet.terminal.calypso.card.DirectoryHeader;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.card.FileHeader;
import org.calypsonet.terminal.calypso.card.SvDebitLogRecord;
import org.calypsonet.terminal.calypso.card.SvLoadLogRecord;
import org.calypsonet.terminal.calypso.sam.CalypsoSamSelection;
import org.calypsonet.terminal.calypso.transaction.CardSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.CardTransactionManager;
import org.calypsonet.terminal.card.CardApiProperties;
import org.calypsonet.terminal.reader.CardReader;
import org.calypsonet.terminal.reader.ReaderApiProperties;
import org.eclipse.keyple.core.common.CommonApiProperties;
import org.eclipse.keyple.core.common.KeypleCardExtension;
import org.eclipse.keyple.core.service.resource.spi.CardResourceProfileExtension;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.json.JsonUtil;

/**
 * Card extension dedicated to the management of Calypso cards.
 *
 * @since 2.0.0
 */
public final class CalypsoExtensionService implements KeypleCardExtension {

  /** singleton instance of CalypsoExtensionService */
  private static final CalypsoExtensionService INSTANCE = new CalypsoExtensionService();

  public static final String PRODUCT_TYPE = "productType";

  static {
    // Register additional JSON adapters.
    JsonUtil.registerTypeAdapter(
        DirectoryHeader.class, new DirectoryHeaderJsonDeserializerAdapter(), false);
    JsonUtil.registerTypeAdapter(
        ElementaryFile.class, new ElementaryFileJsonDeserializerAdapter(), false);
    JsonUtil.registerTypeAdapter(FileHeader.class, new FileHeaderJsonDeserializerAdapter(), false);
    JsonUtil.registerTypeAdapter(
        SvLoadLogRecord.class, new SvLoadLogRecordJsonDeserializerAdapter(), false);
    JsonUtil.registerTypeAdapter(
        SvDebitLogRecord.class, new SvDebitLogRecordJsonDeserializerAdapter(), false);
  }

  /** Private constructor. */
  private CalypsoExtensionService() {}

  /**
   * Gets the single instance of CalypsoExtensionService.
   *
   * @return The instance of CalypsoExtensionService.
   * @since 2.0.0
   */
  public static CalypsoExtensionService getInstance() {
    return INSTANCE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getReaderApiVersion() {
    return ReaderApiProperties.VERSION;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getCardApiVersion() {
    return CardApiProperties.VERSION;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getCommonApiVersion() {
    return CommonApiProperties.VERSION;
  }

  /**
   * Creates an instance of {@link SearchCommandData} to be used to define the parameters of the
   * "Search Record Multiple" card command.
   *
   * <p>See methods:
   *
   * <ul>
   *   <li>{@link CalypsoCardSelection#prepareSearchRecordMultiple(SearchCommandData)}
   *   <li>{@link CardTransactionManager#prepareSearchRecordMultiple(SearchCommandData)}
   * </ul>
   *
   * @return A not null reference.
   * @since 2.1.0
   */
  public SearchCommandData createSearchCommandData() {
    return new SearchCommandDataAdapter();
  }

  /**
   * Creates an instance of {@link CalypsoCardSelection} that can be supplemented later with
   * specific commands.
   *
   * @return A not null reference.
   * @since 2.0.0
   */
  public CalypsoCardSelection createCardSelection() {
    return new CalypsoCardSelectionAdapter();
  }

  /**
   * Creates an instance of {@link CalypsoCardSelection}.
   *
   * @return A not null reference.
   * @since 2.0.0
   */
  public CalypsoSamSelection createSamSelection() {
    return new CalypsoSamSelectionAdapter();
  }

  /**
   * Creates an instance of {@link CardResourceProfileExtension} to be provided to the {@link
   * org.eclipse.keyple.core.service.resource.CardResourceService}.
   *
   * <p>The provided argument defines the selection rules to be applied to the SAM when detected by
   * the card resource service.
   *
   * @param calypsoSamSelection A not null {@link
   *     org.calypsonet.terminal.calypso.sam.CalypsoSamSelection}.
   * @return A not null reference.
   * @throws IllegalArgumentException If calypsoSamSelection is null.
   * @since 2.0.0
   */
  public CardResourceProfileExtension createSamResourceProfileExtension(
      CalypsoSamSelection calypsoSamSelection) {
    Assert.getInstance().notNull(calypsoSamSelection, "calypsoSamSelection");
    return new CalypsoSamResourceProfileExtensionAdapter(calypsoSamSelection);
  }

  /**
   * Creates an instance of {@link CalypsoCardSelection} that can be supplemented later with
   * specific commands.
   *
   * @return A not null reference.
   * @since 2.0.0
   */
  public CardSecuritySetting createCardSecuritySetting() {
    return new CardSecuritySettingAdapter();
  }

  /**
   * Creates a card transaction manager to handle operations secured with a SAM.
   *
   * <p>The reader and the card's initial data are those from the selection.<br>
   * The provided {@link CardSecuritySetting} must match the specific needs of the card (SAM card
   * resource profile and other optional settings).
   *
   * @param reader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @param cardSecuritySetting The security settings.
   * @return A not null reference.
   * @throws IllegalArgumentException If one of the provided argument is null or if the CalypsoCard
   *     has a null or unknown product type.
   * @since 2.0.0
   */
  public CardTransactionManager createCardTransaction(
      CardReader reader, CalypsoCard calypsoCard, CardSecuritySetting cardSecuritySetting) {

    Assert.getInstance()
        .notNull(reader, "reader")
        .notNull(calypsoCard, "calypsoCard")
        .notNull(calypsoCard.getProductType(), PRODUCT_TYPE)
        .isTrue(calypsoCard.getProductType() != CalypsoCard.ProductType.UNKNOWN, PRODUCT_TYPE)
        .notNull(cardSecuritySetting, "cardSecuritySetting");

    return new CardTransactionManagerAdapter(reader, calypsoCard, cardSecuritySetting);
  }

  /**
   * Creates a card transaction manager to handle non-secured operations.
   *
   * @param reader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @return A not null reference.
   * @throws IllegalArgumentException If one of the provided argument is null or if the CalypsoCard
   *     has a null or unknown product type.
   * @since 2.0.0
   */
  public CardTransactionManager createCardTransactionWithoutSecurity(
      CardReader reader, CalypsoCard calypsoCard) {

    Assert.getInstance()
        .notNull(reader, "reader")
        .notNull(calypsoCard, "calypsoCard")
        .notNull(calypsoCard.getProductType(), PRODUCT_TYPE)
        .isTrue(calypsoCard.getProductType() != CalypsoCard.ProductType.UNKNOWN, PRODUCT_TYPE);

    return new CardTransactionManagerAdapter(reader, calypsoCard);
  }
}
