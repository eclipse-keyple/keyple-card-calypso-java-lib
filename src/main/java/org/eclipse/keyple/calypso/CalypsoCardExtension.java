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

import org.eclipse.keyple.calypso.po.CalypsoPoCardSelection;
import org.eclipse.keyple.calypso.po.CalypsoPoCardSelector;
import org.eclipse.keyple.calypso.po.CalypsoPoSmartCard;
import org.eclipse.keyple.calypso.sam.SamResource;
import org.eclipse.keyple.calypso.transaction.PoSecuritySetting;
import org.eclipse.keyple.calypso.transaction.PoTransactionService;
import org.eclipse.keyple.core.common.KeypleCardExtension;
import org.eclipse.keyple.core.service.Reader;

/**
 * Card extension dedicated to the management of Calypso cards.
 *
 * @since 2.0
 */
public interface CalypsoCardExtension extends KeypleCardExtension {

  /**
   * @param calypsoPoCardSelector
   * @return
   * @since 2.0
   */
  CalypsoPoCardSelection createPoSelection(CalypsoPoCardSelector calypsoPoCardSelector);

  /**
   * @return
   * @since 2.0
   */
  SamResourceManagerBuilder getSamResourceManagerBuilder();

  /**
   * @param samResource
   * @return
   * @since 2.0
   */
  PoSecuritySettingBuilder getPoSecuritySettingBuilder(SamResource samResource);

  /**
   * @param reader
   * @param calypsoPoSmartCard
   * @param poSecuritySetting
   * @return
   * @since 2.0
   */
  PoTransactionService createPoSecuredTransaction(
      Reader reader, CalypsoPoSmartCard calypsoPoSmartCard, PoSecuritySetting poSecuritySetting);

  /**
   * @param reader
   * @param calypsoPoSmartCard
   * @return
   * @since 2.0
   */
  PoTransactionService createPoSecuredTransaction(
      Reader reader, CalypsoPoSmartCard calypsoPoSmartCard);
}
