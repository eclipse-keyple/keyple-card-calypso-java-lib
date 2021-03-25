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
import org.eclipse.keyple.calypso.sam.SamResourceManager;
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
   * Creates an instance of {@link CalypsoPoCardSelection} that can be extended later with specific
   * commands.
   *
   * @param calypsoPoCardSelector A PO card selector.
   * @return A not null reference.
   * @since 2.0
   */
  CalypsoPoCardSelection createPoSelection(CalypsoPoCardSelector calypsoPoCardSelector);

  /**
   * Gets the {@link SamResourceManager} as a singleton.
   *
   * @return A not null reference.
   * @since 2.0
   */
  SamResourceManager getSamResourceManager();

  /**
   * Gets a builder of {@link PoSecuritySetting} for the provided SAM profile name.
   *
   * <p>The SAM profile name must match one of the profiles configured in the {@link
   * SamResourceManager}.
   *
   * @param samProfileName A SAM profile name.
   * @return A not null reference.
   * @since 2.0
   */
  PoSecuritySettingBuilder getPoSecuritySettingBuilder(String samProfileName);

  /**
   * Creates a PO transaction service to handle operations secured with a SAM.
   *
   * <p>The reader and the PO's initial data are those from the selection.<br>
   * The security settings must match the specific needs of the PO and must have been built with a
   * {@link PoSecuritySettingBuilder}.
   *
   * @param reader The reader through which the card communicates.
   * @param calypsoPoSmartCard The initial PO data provided by the selection process.
   * @param poSecuritySetting The security settings.
   * @return A not null reference.
   * @since 2.0
   */
  PoTransactionService createPoSecuredTransaction(
      Reader reader, CalypsoPoSmartCard calypsoPoSmartCard, PoSecuritySetting poSecuritySetting);

  /**
   * Creates a PO transaction service to handle operations non secured.
   *
   * @param reader The reader through which the card communicates.
   * @param calypsoPoSmartCard The initial PO data provided by the selection process.
   * @return A not null reference.
   * @since 2.0
   */
  PoTransactionService createPoSecuredTransaction(
      Reader reader, CalypsoPoSmartCard calypsoPoSmartCard);
}
