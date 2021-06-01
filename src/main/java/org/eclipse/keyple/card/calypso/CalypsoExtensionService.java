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

import org.calypsonet.terminal.card.CardApiProperties;
import org.calypsonet.terminal.reader.CardReader;
import org.calypsonet.terminal.reader.ReaderApiProperties;
import org.calypsonet.terminal.reader.selection.spi.CardSelector;
import org.eclipse.keyple.card.calypso.card.CalypsoCard;
import org.eclipse.keyple.card.calypso.card.CalypsoCardSelection;
import org.eclipse.keyple.card.calypso.sam.CalypsoSamResourceProfileExtension;
import org.eclipse.keyple.card.calypso.transaction.CardSecuritySetting;
import org.eclipse.keyple.card.calypso.transaction.CardTransactionService;
import org.eclipse.keyple.core.common.CommonsApiProperties;
import org.eclipse.keyple.core.common.KeypleCardExtension;

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
   * Creates an instance of {@link CalypsoSelector}.
   *
   * @return A not null reference.
   * @since 2.0
   */
  public CalypsoSelector createCardSelector() {
    return new CalypsoSelectorAdapter();
  }

  /**
   * Creates an instance of {@link CalypsoCardSelection} that can be supplemented later with
   * specific commands.
   *
   * @param cardSelector A Calypso card selector.
   * @param acceptInvalidatedCard true if invalidated card must be accepted, false if not.
   * @return A not null reference.
   * @since 2.0
   */
  public CalypsoCardSelection createCardSelection(
      CardSelector cardSelector, boolean acceptInvalidatedCard) {
    return new CalypsoCardSelectionAdapter(cardSelector, acceptInvalidatedCard);
  }

  /**
   * Creates an instance of {@link CalypsoSamResourceProfileExtension} to be provided to the {@link
   * org.eclipse.keyple.core.service.resource.CardResourceService}.
   *
   * @return A not null reference.
   * @since 2.0
   */
  public CalypsoSamResourceProfileExtension createSamResourceProfileExtension() {
    return new CalypsoSamResourceProfileExtensionAdapter();
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
