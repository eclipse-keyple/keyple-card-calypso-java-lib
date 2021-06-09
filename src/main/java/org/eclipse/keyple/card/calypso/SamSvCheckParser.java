/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.card.ApduResponseApi;

/**
 * Parses the SV Check response.
 *
 * @since 2.0
 */
final class SamSvCheckParser extends AbstractSamResponseParser {
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamResponseParser.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "No active SV transaction.", CalypsoSamAccessForbiddenException.class));
    m.put(
        0x6988,
        new StatusProperties("Incorrect SV signature.", CalypsoSamSecurityDataException.class));
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
   * Instantiates a new SamSvCheckParser.
   *
   * @param response from the SAM.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public SamSvCheckParser(ApduResponseApi response, SamSvCheckBuilder builder) {
    super(response, builder);
  }
}
