/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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

import java.util.Arrays;
import java.util.List;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.card.ApduResponseApi;
import org.eclipse.keypop.card.CardResponseApi;
import org.eclipse.keypop.card.CardSelectionResponseApi;
import org.eclipse.keypop.card.spi.CardRequestSpi;

class TestDtoAdapters {

  private TestDtoAdapters() {}

  /**
   * (private)<br>
   * Implementation of {@link ApduResponseApi}.
   */
  static class ApduResponseAdapter implements ApduResponseApi {

    private final byte[] apdu;
    private final int statusWord;

    /** Constructor */
    public ApduResponseAdapter(byte[] apdu) {
      this.apdu = apdu;
      statusWord =
          ((apdu[apdu.length - 2] & 0x000000FF) << 8) + (apdu[apdu.length - 1] & 0x000000FF);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getApdu() {
      return apdu;
    }

    /** {@inheritDoc} */
    @Override
    public byte[] getDataOut() {
      return Arrays.copyOfRange(this.apdu, 0, this.apdu.length - 2);
    }

    /** {@inheritDoc} */
    @Override
    public int getStatusWord() {
      return statusWord;
    }

    /**
     * Converts the APDU response into a string where the data is encoded in a json format.
     *
     * @return A not empty String
     * @since 2.0.0
     */
    @Override
    public String toString() {
      return "APDU_RESPONSE = " + JsonUtil.toJson(this);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;

      ApduResponseAdapter that = (ApduResponseAdapter) o;

      return Arrays.equals(apdu, that.apdu);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(apdu);
    }
  }

  /**
   * (package-private)<br>
   * This POJO contains an ordered list of the responses received following a card request and
   * indicators related to the status of the channel and the completion of the card request.
   *
   * @see CardRequestSpi
   * @since 2.0.0
   */
  static final class CardResponseAdapter implements CardResponseApi {

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

  static class CardSelectionResponseAdapter implements CardSelectionResponseApi {

    private String powerOnData = null;
    private ApduResponseApi selectApplicationResponse = null;

    CardSelectionResponseAdapter(String powerOnData) {
      this.powerOnData = powerOnData;
    }

    CardSelectionResponseAdapter(ApduResponseApi selectApplicationResponse) {
      this.selectApplicationResponse = selectApplicationResponse;
    }

    @Override
    public String getPowerOnData() {
      return powerOnData;
    }

    @Override
    public ApduResponseApi getSelectApplicationResponse() {
      return selectApplicationResponse;
    }

    @Override
    public boolean hasMatched() {
      throw new UnsupportedOperationException("hasMatched");
    }

    @Override
    public CardResponseApi getCardResponse() {
      throw new UnsupportedOperationException("hasMatched");
    }
  }
}
