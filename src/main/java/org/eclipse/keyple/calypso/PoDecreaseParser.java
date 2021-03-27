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
package org.eclipse.keyple.calypso;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.card.ApduResponse;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Parses the Decrease response.
 *
 * @since 2.0
 */
final class PoDecreaseParser extends AbstractPoResponseParser {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduResponseParser.STATUS_TABLE);
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session.", CalypsoPoSessionBufferOverflowException.class));
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CalypsoPoIllegalParameterException.class));
    m.put(
        0x6981,
        new StatusProperties(
            "The current EF is not a Counters or Simulated Counter EF.",
            CalypsoPoDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (no session, wrong key, encryption required).",
            CalypsoPoSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, DF is invalidated, etc.)",
            CalypsoPoAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Command not allowed (no current EF).", CalypsoPoDataAccessException.class));
    m.put(0x6A80, new StatusProperties("Overflow error.", CalypsoPoDataOutOfBoundsException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CalypsoPoDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CalypsoPoDataAccessException.class));
    m.put(
        0x6103, new StatusProperties("Successful execution (possible only in ISO7816 T=0).", null));
    STATUS_TABLE = m;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  protected Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * Instantiates a new PoDecreaseParser.
   *
   * @param response the response from the PO.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public PoDecreaseParser(ApduResponse response, PoDecreaseBuilder builder) {
    super(response, builder);
  }

  /**
   * Returns the new counter value as an int between 0
   *
   * @return the new value
   * @since 2.0
   */
  public int getNewValue() {
    byte[] newValueBuffer = getApduResponse().getDataOut();
    if (newValueBuffer.length == 3) {
      return ByteArrayUtil.threeBytesToInt(newValueBuffer, 0);
    } else {
      throw new IllegalStateException(
          "No counter value available in response to the Decrease command.");
    }
  }
}
