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

import org.eclipse.keyple.calypso.po.PoCardSelection;
import org.eclipse.keyple.calypso.po.PoCardSelector;
import org.eclipse.keyple.calypso.po.PoSmartCard;
import org.eclipse.keyple.calypso.sam.SamCardResourceProfileExtension;
import org.eclipse.keyple.calypso.transaction.PoSecuritySetting;
import org.eclipse.keyple.calypso.transaction.PoTransactionService;
import org.eclipse.keyple.core.card.CardApiProperties;
import org.eclipse.keyple.core.card.spi.CardExtensionSpi;
import org.eclipse.keyple.core.common.CommonsApiProperties;
import org.eclipse.keyple.core.service.Reader;
import org.eclipse.keyple.core.service.ServiceApiProperties;

/**
 * (package-private)<br>
 * Implementation of {@link CalypsoCardExtension}.
 *
 * @since 2.0
 */
final class CalypsoCardExtensionAdapter implements CalypsoCardExtension, CardExtensionSpi {

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
  public PoCardSelection createPoSelection(PoCardSelector poCardSelector) {
    return null;
  }

  @Override
  public SamCardResourceProfileExtension createSamCardResourceProfileExtension() {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoSecuritySettingBuilder getPoSecuritySettingBuilder(String samCardResourceProfileName) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoTransactionService createPoSecuredTransaction(
      Reader reader, PoSmartCard poSmartCard, PoSecuritySetting poSecuritySetting) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoTransactionService createPoUnsecuredTransaction(Reader reader, PoSmartCard poSmartCard) {
    return null;
  }
}
