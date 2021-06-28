/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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
import org.calypsonet.terminal.card.ApduResponseApi;

/**
 * (private)<br>
 * Implementation of {@link ApduResponseApi}.
 */
class ApduResponseAdapter implements ApduResponseApi {

  private final byte[] apdu;
  private final int statusWord;

  /** Constructor */
  public ApduResponseAdapter(byte[] apdu) {
    this.apdu = apdu;
    statusWord = ((apdu[apdu.length - 2] & 0x000000FF) << 8) + (apdu[apdu.length - 1] & 0x000000FF);
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
