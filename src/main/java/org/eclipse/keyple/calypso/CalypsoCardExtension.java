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
   * Creates an instance of {@link PoCardSelection} that can be extended later with specific
   * commands.
   *
   * @param poCardSelector A PO card selector.
   * @return A not null reference.
   * @since 2.0
   */
  PoCardSelection createPoCardSelection(PoCardSelector poCardSelector);

  /**
   * Creates an instance of {@link SamCardResourceProfileExtension} to be provided to the {@link
   * org.eclipse.keyple.core.service.CardResourceService}.
   *
   * @return A not null reference.
   * @since 2.0
   */
  SamCardResourceProfileExtension createSamCardResourceProfileExtension();

  /**
   * Creates a PO transaction service to handle operations secured with a SAM.
   *
   * <p>The reader and the PO's initial data are those from the selection.<br>
   * The provided {@link PoSecuritySetting} must match the specific needs of the PO (SAM card
   * resource profile and other optional settings).
   *
   * @param reader The reader through which the card communicates.
   * @param poSmartCard The initial PO data provided by the selection process.
   * @param poSecuritySetting The security settings.
   * @return A not null reference.
   * @since 2.0
   */
  PoTransactionService createPoSecuredTransaction(
      Reader reader, PoSmartCard poSmartCard, PoSecuritySetting poSecuritySetting);

  /**
   * Creates a PO transaction service to handle non secured operations.
   *
   * @param reader The reader through which the card communicates.
   * @param poSmartCard The initial PO data provided by the selection process.
   * @return A not null reference.
   * @since 2.0
   */
  PoTransactionService createPoUnsecuredTransaction(Reader reader, PoSmartCard poSmartCard);
}
