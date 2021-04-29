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
import org.eclipse.keyple.card.calypso.transaction.PoSecuritySetting;
import org.eclipse.keyple.card.calypso.transaction.PoTransactionService;
import org.eclipse.keyple.core.common.KeypleCardExtension;
import org.eclipse.keyple.core.service.Reader;
import org.eclipse.keyple.core.service.selection.CardSelector;

/**
 * Card extension dedicated to the management of Calypso cards.
 *
 * @since 2.0
 */
public interface CalypsoExtensionService extends KeypleCardExtension {

  /**
   * Creates an instance of {@link PoCardSelection} that can be supplemented later with specific
   * commands.
   *
   * @param poCardSelector A PO card selector.
   * @param acceptInvalidatedPo true if invalidated PO must be accepted, false if not.
   * @return A not null reference.
   * @since 2.0
   */
  PoCardSelection createPoCardSelection(CardSelector poCardSelector, boolean acceptInvalidatedPo);

  /**
   * Creates an instance of {@link CalypsoSamResourceProfileExtension} to be provided to the {@link
   * org.eclipse.keyple.core.service.resource.CardResourceService}.
   *
   * @return A not null reference.
   * @since 2.0
   */
  CalypsoSamResourceProfileExtension createSamCardResourceProfileExtension();

  /**
   * Creates a PO transaction service to handle operations secured with a SAM.
   *
   * <p>The reader and the PO's initial data are those from the selection.<br>
   * The provided {@link PoSecuritySetting} must match the specific needs of the PO (SAM card
   * resource profile and other optional settings).
   *
   * @param reader The reader through which the card communicates.
   * @param calypsoCard The initial PO data provided by the selection process.
   * @param poSecuritySetting The security settings.
   * @return A not null reference.
   * @since 2.0
   */
  PoTransactionService createPoSecuredTransaction(
      Reader reader, CalypsoCard calypsoCard, PoSecuritySetting poSecuritySetting);

  /**
   * Creates a PO transaction service to handle non secured operations.
   *
   * @param reader The reader through which the card communicates.
   * @param calypsoCard The initial PO data provided by the selection process.
   * @return A not null reference.
   * @since 2.0
   */
  PoTransactionService createPoUnsecuredTransaction(Reader reader, CalypsoCard calypsoCard);
}
