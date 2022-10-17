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

import org.calypsonet.terminal.card.ApduResponseApi;
import org.calypsonet.terminal.card.CardResponseApi;
import org.calypsonet.terminal.card.CardSelectionResponseApi;

class CardSelectionResponseAdapter implements CardSelectionResponseApi {

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
