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

import org.eclipse.keyple.calypso.smartcard.po.CalypsoPoSmartCard;
import org.eclipse.keyple.calypso.smartcard.sam.CalypsoSamSmartCard;
import org.eclipse.keyple.calypso.transaction.PoSecuritySettingsInterface;
import org.eclipse.keyple.calypso.transaction.PoTransaction;
import org.eclipse.keyple.core.service.Reader;
import org.eclipse.keyple.core.service.selection.CardResource;

/**
 * Factory of {@link PoTransaction}
 *
 * @since 2.0
 */
public class PoTransactionFactory {
  /**
   * (private)<br>
   * Constructor
   */
  private PoTransactionFactory() {}

  /**
   * Gets an instance of a {@link PoTransaction} to operate a Calypso Secure session.
   *
   * <p>The required PO resource (combination of {@link Reader} and {@link CalypsoPoSmartCard}).
   * <br>
   * The PO security settings is a set of security settings ({@link PoSecuritySettings}) including a
   * {@link CardResource} based on a {@link CalypsoSamSmartCard}.
   *
   * @param poResource The PO resource.
   * @param poSecuritySettings The PO security settings
   * @return A not null reference.
   * @since 2.0
   */
  public static PoTransaction getService(
      CardResource<CalypsoPoSmartCard> poResource, PoSecuritySettingsInterface poSecuritySettings) {
    return new PoTransactionAdapter(poResource, poSecuritySettings);
  }

  /**
   * Gets an instance of a {@link PoTransaction} to operate non-secured Calypso commands.
   *
   * <p>The required PO resource (combination of {@link Reader} and {@link CalypsoPoSmartCard}).
   *
   * @param poResource The PO resource.
   * @return A not null reference.
   * @since 2.0
   */
  public static PoTransaction getService(CardResource<CalypsoPoSmartCard> poResource) {
    return new PoTransactionAdapter(poResource);
  }
}
