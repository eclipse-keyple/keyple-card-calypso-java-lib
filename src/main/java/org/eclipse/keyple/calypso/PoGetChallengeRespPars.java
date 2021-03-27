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

import org.eclipse.keyple.core.card.ApduResponse;

/**
 * (package-private)<br>
 * Parses the PO Get challenge response.
 *
 * @since 2.0
 */
final class PoGetChallengeRespPars extends AbstractPoResponseParser {

  /**
   * Instantiates a new PoGetChallengeRespPars.
   *
   * @param response the response from PO Get Challenge APDU Command.
   * @param builder the reference to the builder that created this parser.
   * @since 2.0
   */
  public PoGetChallengeRespPars(ApduResponse response, PoGetChallengeBuilder builder) {
    super(response, builder);
  }

  /**
   * Gets the PO challenge
   *
   * @return An array of bytes
   * @since 2.0
   */
  public byte[] getPoChallenge() {
    return getApduResponse().getDataOut();
  }
}
