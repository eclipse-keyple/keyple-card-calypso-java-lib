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

import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.calypso.card.CalypsoCardSelection;
import org.calypsonet.terminal.calypso.sam.CalypsoSamSelection;
import org.calypsonet.terminal.calypso.transaction.CardSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.CardTransactionService;
import org.calypsonet.terminal.card.CardApiProperties;
import org.calypsonet.terminal.reader.CardReader;
import org.calypsonet.terminal.reader.ReaderApiProperties;
import org.eclipse.keyple.core.common.CommonsApiProperties;
import org.eclipse.keyple.core.common.KeypleCardExtension;
import org.eclipse.keyple.core.service.resource.spi.CardResourceProfileExtension;

/**
 * Card extension dedicated to the management of Calypso cards.
 *
 * @since 2.0
 */
public final class CalypsoExtensionService implements KeypleCardExtension {

  /** singleton instance of CalypsoExtensionService */
  private static final CalypsoExtensionService uniqueInstance = new CalypsoExtensionService();

  /** Private constructor. */
  private CalypsoExtensionService() {}

  /**
   * Gets the single instance of CalypsoExtensionService.
   *
   * @return The instance of CalypsoExtensionService.
   * @since 2.0
   */
  public static CalypsoExtensionService getInstance() {
    return uniqueInstance;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public String getReaderApiVersion() {
    return ReaderApiProperties.VERSION;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public String getCardApiVersion() {
    return CardApiProperties.VERSION;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public String getCommonsApiVersion() {
    return CommonsApiProperties.VERSION;
  }

  /**
   * Creates an instance of {@link CalypsoCardSelection} that can be supplemented later with
   * specific commands.
   *
   * @return A not null reference.
   * @since 2.0
   */
  public CalypsoCardSelection createCardSelection() {
    return new CalypsoCardSelectionAdapter();
  }

  /**
   * Creates an instance of {@link CalypsoCardSelection}.
   *
   * @return A not null reference.
   * @since 2.0
   */
  public CalypsoSamSelection createSamSelection() {
    return new CalypsoSamCardSelectionAdapter();
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
   * @since 2.0
   */
  public CardResourceProfileExtension createSamResourceProfileExtension(
      CalypsoSamSelection calypsoSamSelection) {
    return new CalypsoSamResourceProfileExtensionAdapter(calypsoSamSelection);
  }

  /**
   * Creates an instance of {@link CalypsoCardSelection} that can be supplemented later with
   * specific commands.
   *
   * @return A not null reference.
   * @since 2.0
   */
  public CardSecuritySetting createCardSecuritySetting() {
    return new CardSecuritySettingAdapter();
  }

  /**
   * Creates a card transaction service to handle operations secured with a SAM.
   *
   * <p>The reader and the card's initial data are those from the selection.<br>
   * The provided {@link CardSecuritySetting} must match the specific needs of the card (SAM card
   * resource profile and other optional settings).
   *
   * @param reader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @param cardSecuritySetting The security settings.
   * @return A not null reference.
   * @since 2.0
   */
  public CardTransactionService createCardTransaction(
      CardReader reader, CalypsoCard calypsoCard, CardSecuritySetting cardSecuritySetting) {
    return new CardTransactionServiceAdapter(reader, calypsoCard, cardSecuritySetting);
  }

  /**
   * Creates a card transaction service to handle non secured operations.
   *
   * @param reader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @return A not null reference.
   * @since 2.0
   */
  public CardTransactionService createCardTransactionWithoutSecurity(
      CardReader reader, CalypsoCard calypsoCard) {
    return new CardTransactionServiceAdapter(reader, calypsoCard);
  }
}
