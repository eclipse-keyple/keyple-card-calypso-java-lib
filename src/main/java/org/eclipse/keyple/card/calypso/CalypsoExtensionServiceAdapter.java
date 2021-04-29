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

import org.eclipse.keyple.card.calypso.po.CalypsoCard;
import org.eclipse.keyple.card.calypso.po.PoCardSelection;
import org.eclipse.keyple.card.calypso.sam.CalypsoSamResourceProfileExtension;
import org.eclipse.keyple.card.calypso.transaction.CardTransactionService;
import org.eclipse.keyple.card.calypso.transaction.PoSecuritySetting;
import org.eclipse.keyple.core.card.CardApiProperties;
import org.eclipse.keyple.core.card.spi.CardExtensionSpi;
import org.eclipse.keyple.core.common.CommonsApiProperties;
import org.eclipse.keyple.core.service.Reader;
import org.eclipse.keyple.core.service.ServiceApiProperties;
import org.eclipse.keyple.core.service.selection.CardSelector;

/**
 * (package-private)<br>
 * Implementation of {@link CalypsoExtensionService}.
 *
 * @since 2.0
 */
final class CalypsoExtensionServiceAdapter implements CalypsoExtensionService, CardExtensionSpi {

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
  public String getCardApiVersion() {
    return CardApiProperties.VERSION;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public String getServiceApiVersion() {
    return ServiceApiProperties.VERSION;
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
  public PoCardSelection createCardSelection(
      CardSelector cardSelector, boolean acceptInvalidatedPo) {
    return new PoCardSelectionAdapter(cardSelector, acceptInvalidatedPo);
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
      Reader reader, CalypsoCard calypsoCard, PoSecuritySetting poSecuritySetting) {
    return new CardTransactionServiceAdapter(reader, calypsoCard, poSecuritySetting);
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
