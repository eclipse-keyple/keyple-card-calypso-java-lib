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
package org.eclipse.keyple.calypso.selection.po;

import org.eclipse.keyple.core.service.selection.spi.CardSelector;

/**
 * Specific {@link CardSelector} dedicated to Calypso PO
 *
 * @since 2.0
 */
public final class CalypsoPoSelector extends CardSelector {

  private static final int SW_PO_INVALIDATED = 0x6283;

  private CalypsoPoSelector() {}

  /**
   * Indicates if an invalidated PO should be selected or not.
   *
   * <p>The acceptance of an invalid PO is determined with the additional successful status codes
   * specified in the {@link AidSelector}
   *
   * @since 2.0
   */
  public enum InvalidatedPo {
    REJECT,
    ACCEPT
  }

  /**
   * Sets the desired behaviour in case of invalidated POs
   *
   * @param invalidatedPo the {@link InvalidatedPo} wanted behaviour.
   * @return This object instance.
   * @since 2.0
   */
  public CalypsoPoSelector acceptInvalidatedPo(InvalidatedPo invalidatedPo) {
    if (invalidatedPo == InvalidatedPo.ACCEPT) {
      this.getAidSelector().addSuccessfulStatusCode(SW_PO_INVALIDATED);
    }
    return this;
  }
}
