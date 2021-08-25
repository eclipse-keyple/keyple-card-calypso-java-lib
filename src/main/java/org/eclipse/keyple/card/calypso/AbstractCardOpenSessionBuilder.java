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

import org.calypsonet.terminal.calypso.card.CalypsoCard;

/**
 * (package-private)<br>
 * Builds the Open Secure Session APDU command.
 *
 * @since 2.0.0
 */
abstract class AbstractCardOpenSessionBuilder<T extends AbstractCardResponseParser>
    extends AbstractCardCommandBuilder<T> {

  private static boolean isExtendedModeSupported = false;

  /**
   * Instantiates a new AbstractCardOpenSessionBuilder.
   *
   * @param calypsoCard the {@link CalypsoCard}.
   * @throws IllegalArgumentException - if the key index is 0 and rev is 2.4
   * @throws IllegalArgumentException - if the request is inconsistent
   * @since 2.0.0
   */
  AbstractCardOpenSessionBuilder(CalypsoCard calypsoCard) {
    super(CalypsoCardCommand.getOpenSessionForRev(calypsoCard));
  }

  public static AbstractCardOpenSessionBuilder<AbstractCardOpenSessionParser> create(
      CalypsoCard calypsoCard,
      byte debitKeyIndex,
      byte[] sessionTerminalChallenge,
      int sfi,
      int recordNumber) {
    isExtendedModeSupported = calypsoCard.isExtendedModeSupported();
    switch (calypsoCard.getProductType()) {
      case PRIME_REVISION_1:
        return new CardOpenSession10Builder(
            calypsoCard, debitKeyIndex, sessionTerminalChallenge, sfi, recordNumber);
      case PRIME_REVISION_2:
        return new CardOpenSession24Builder(
            calypsoCard, debitKeyIndex, sessionTerminalChallenge, sfi, recordNumber);
      case PRIME_REVISION_3:
      case LIGHT:
      case BASIC:
        return new CardOpenSession3Builder(
            calypsoCard, debitKeyIndex, sessionTerminalChallenge, sfi, recordNumber);
      default:
        throw new IllegalArgumentException(
            "Product type " + calypsoCard.getProductType() + " isn't supported");
    }
  }

  /** @return the SFI of the file read while opening the secure session */
  abstract int getSfi();

  /** @return the record number to read */
  abstract int getRecordNumber();

  /**
   * (package-private)<br>
   *
   * @return True if the confidential session mode is supported.
   */
  boolean isIsExtendedModeSupported() {
    return isExtendedModeSupported;
  }
}
