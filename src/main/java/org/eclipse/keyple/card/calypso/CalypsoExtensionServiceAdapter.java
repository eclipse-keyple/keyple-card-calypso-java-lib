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
import org.calypsonet.terminal.reader.ReaderApiProperties;
import org.calypsonet.terminal.reader.selection.spi.CardSelector;
import org.eclipse.keyple.card.calypso.card.CalypsoCard;
import org.eclipse.keyple.card.calypso.card.CalypsoCardSelection;
import org.eclipse.keyple.card.calypso.sam.CalypsoSamResourceProfileExtension;
import org.eclipse.keyple.card.calypso.transaction.CardSecuritySetting;
import org.eclipse.keyple.card.calypso.transaction.CardTransactionService;
import org.eclipse.keyple.core.common.CommonsApiProperties;
import org.eclipse.keyple.core.service.Reader;

/**
 * (package-private)<br>
 * Implementation of {@link CalypsoExtensionService}.
 *
 * @since 2.0
 */
final class CalypsoExtensionServiceAdapter implements CalypsoExtensionService {

  /** singleton instance of CalypsoExtensionServiceAdapter */
  private static final CalypsoExtensionServiceAdapter uniqueInstance =
      new CalypsoExtensionServiceAdapter();

  /** Private constructor. */
  private CalypsoExtensionServiceAdapter() {}

  /**
   * (package-private)<br>
   * Gets the single instance of CalypsoExtensionServiceAdapter.
   *
   * @return The instance of CalypsoExtensionServiceAdapter.
   * @since 2.0
   */
  static CalypsoExtensionServiceAdapter getInstance() {
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
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoCardSelection createCardSelection(
      CardSelector cardSelector, boolean acceptInvalidatedCard) {
    return new CalypsoCardSelectionAdapter(cardSelector, acceptInvalidatedCard);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoSamResourceProfileExtension createSamResourceProfileExtension() {
    return new CalypsoSamResourceProfileExtensionAdapter();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardTransactionService createCardTransaction(
      Reader reader, CalypsoCard calypsoCard, CardSecuritySetting cardSecuritySetting) {
    return new CardTransactionServiceAdapter(reader, calypsoCard, cardSecuritySetting);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardTransactionService createCardTransactionWithoutSecurity(
      Reader reader, CalypsoCard calypsoCard) {
    return new CardTransactionServiceAdapter(reader, calypsoCard);
  }
}
