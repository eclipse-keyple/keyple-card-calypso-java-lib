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

import org.eclipse.keyple.core.card.spi.SmartCardSpi;
import org.eclipse.keyple.core.service.selection.spi.SmartCard;

final class CalypsoSamSmartCardAdapter implements SmartCardSpi, SmartCard {

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean hasFci() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getFciBytes() {
    return new byte[0];
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean hasAtr() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getAtrBytes() {
    return new byte[0];
  }
}
