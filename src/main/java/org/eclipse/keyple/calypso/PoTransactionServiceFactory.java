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

import org.eclipse.keyple.calypso.po.CalypsoPoSmartCard;
import org.eclipse.keyple.calypso.transaction.PoSecuritySetting;
import org.eclipse.keyple.calypso.transaction.PoTransactionService;
import org.eclipse.keyple.core.service.Reader;

/**
 * Factory of {@link PoTransactionService}
 *
 * @since 2.0
 */
public class PoTransactionServiceFactory {
  /**
   * (private)<br>
   * Constructor
   */
  private PoTransactionServiceFactory() {}

  /**
   * Gets an instance of a {@link PoTransactionService} to operate a Calypso Secure session.
   *
   * <p>The PO security settings is a set of security settings ({@link PoSecuritySetting}) including
   * the name of the SAM profile to request from the SAM resource manager.
   *
   * @param poReader The reader through which the card communicates.
   * @param calypsoPoSmartCard The initial PO data provided by the selection process.
   * @param poSecuritySetting The PO security settings
   * @return A not null reference.
   * @since 2.0
   */
  public static PoTransactionService getService(
      Reader poReader, CalypsoPoSmartCard calypsoPoSmartCard, PoSecuritySetting poSecuritySetting) {
    return new PoTransactionServiceAdapter(poReader, calypsoPoSmartCard, poSecuritySetting);
  }

  /**
   * Gets an instance of a {@link PoTransactionService} to operate non-secure Calypso commands.
   *
   * @param poReader The reader through which the card communicates.
   * @param calypsoPoSmartCard The initial PO data provided by the selection process.
   * @return A not null reference.
   * @since 2.0
   */
  public static PoTransactionService getService(
      Reader poReader, CalypsoPoSmartCard calypsoPoSmartCard) {
    return new PoTransactionServiceAdapter(poReader, calypsoPoSmartCard);
  }
}
