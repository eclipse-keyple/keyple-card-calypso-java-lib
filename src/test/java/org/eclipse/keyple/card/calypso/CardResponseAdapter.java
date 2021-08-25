/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
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

import java.util.List;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardResponseApi;

/**
 * (package-private)<br>
 * This POJO contains an ordered list of the responses received following a card request and
 * indicators related to the status of the channel and the completion of the card request.
 *
 * @see org.calypsonet.terminal.card.spi.CardRequestSpi
 * @since 2.0.0
 */
final class CardResponseAdapter implements CardResponseApi {

  private final List<ApduResponseApi> apduResponses;
  private final boolean isLogicalChannelOpen;

  /**
   * (package-private)<br>
   * Builds a card response from all {@link ApduResponseApi} received from the card and booleans
   * indicating if the logical channel is still open.
   *
   * @param apduResponses A not null list.
   * @param isLogicalChannelOpen true if the logical channel is open, false if not.
   * @since 2.0.0
   */
  CardResponseAdapter(List<ApduResponseApi> apduResponses, boolean isLogicalChannelOpen) {

    this.apduResponses = apduResponses;
    this.isLogicalChannelOpen = isLogicalChannelOpen;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public List<ApduResponseApi> getApduResponses() {
    return apduResponses;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isLogicalChannelOpen() {
    return isLogicalChannelOpen;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    CardResponseAdapter that = (CardResponseAdapter) o;

    if (isLogicalChannelOpen != that.isLogicalChannelOpen) return false;
    return apduResponses.equals(that.apduResponses);
  }

  @Override
  public int hashCode() {
    int result = apduResponses.hashCode();
    result = 31 * result + (isLogicalChannelOpen ? 1 : 0);
    return result;
  }
}
