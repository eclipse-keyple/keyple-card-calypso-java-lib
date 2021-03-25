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
import org.eclipse.keyple.calypso.sam.CalypsoSamSmartCard;
import org.eclipse.keyple.calypso.transaction.PoSecuritySetting;
import org.eclipse.keyple.calypso.transaction.PoTransactionService;
import org.eclipse.keyple.core.service.Reader;
import org.eclipse.keyple.core.service.selection.CardResource;

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
   * <p>The required PO resource (combination of {@link Reader} and {@link CalypsoPoSmartCard}).
   * <br>
   * The PO security settings is a set of security settings ({@link PoSecuritySetting}) including a
   * {@link CardResource} based on a {@link CalypsoSamSmartCard}.
   *
   * @param poResource The PO resource.
   * @param poSecuritySetting The PO security settings
   * @return A not null reference.
   * @since 2.0
   */
  public static PoTransactionService getService(
      CardResource<CalypsoPoSmartCard> poResource, PoSecuritySetting poSecuritySetting) {
    return new PoTransactionServiceAdapter(poResource, poSecuritySetting);
  }

  /**
   * Gets an instance of a {@link PoTransactionService} to operate non-secured Calypso commands.
   *
   * <p>The required PO resource (combination of {@link Reader} and {@link CalypsoPoSmartCard}).
   *
   * @param poResource The PO resource.
   * @return A not null reference.
   * @since 2.0
   */
  public static PoTransactionService getService(CardResource<CalypsoPoSmartCard> poResource) {
    return new PoTransactionServiceAdapter(poResource);
  }
}
