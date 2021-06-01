/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://www.calypsonet-asso.org/
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
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.calypsonet.terminal.card.spi.CardRequestSpi;
import org.eclipse.keyple.core.util.json.JsonUtil;

/**
 * (package-private)<br>
 * This POJO contains an ordered list of {@link ApduRequestSpi} and the associated status code check
 * policy.
 *
 * @since 2.0
 */
final class CardRequestAdapter implements CardRequestSpi {

  private final List<ApduRequestSpi> apduRequests;
  private final boolean isStatusCodesVerificationEnabled;

  /**
   * Builds a card request with a list of {@link ApduRequestSpi } and the flag indicating the
   * expected response checking behavior.
   *
   * <p>When the status code verification is enabled, the transmission of the APDUs must be
   * interrupted as soon as the status code of a response is unexpected.
   *
   * @param apduRequests A not empty list.
   * @param isStatusCodesVerificationEnabled true or false.
   * @since 2.0
   */
  public CardRequestAdapter(
      List<ApduRequestSpi> apduRequests, boolean isStatusCodesVerificationEnabled) {
    this.apduRequests = apduRequests;
    this.isStatusCodesVerificationEnabled = isStatusCodesVerificationEnabled;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public List<ApduRequestSpi> getApduRequests() {
    return apduRequests;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public boolean stopOnUnsuccessfulStatusWord() {
    return isStatusCodesVerificationEnabled;
  }

  /**
   * Converts the card request into a string where the data is encoded in a json format.
   *
   * @return A not empty String
   * @since 2.0
   */
  @Override
  public String toString() {
    return "CARD_REQUEST = " + JsonUtil.toJson(this);
  }
}
