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

import org.eclipse.keyple.card.calypso.card.CardRevision;

/**
 * (package-private)<br>
 * Builds the Open Secure Session APDU command.
 *
 * @since 2.0
 */
abstract class AbstractCardOpenSessionBuilder<T extends AbstractCardResponseParser>
    extends AbstractCardCommandBuilder<T> {

  /**
   * Instantiates a new AbstractCardOpenSessionBuilder.
   *
   * @param revision the revision of the card.
   * @throws IllegalArgumentException - if the key index is 0 and rev is 2.4
   * @throws IllegalArgumentException - if the request is inconsistent
   * @since 2.0
   */
  AbstractCardOpenSessionBuilder(CardRevision revision) {
    super(CalypsoCardCommand.getOpenSessionForRev(revision));
  }

  public static AbstractCardOpenSessionBuilder<AbstractCardOpenSessionParser> create(
      CardRevision revision,
      byte debitKeyIndex,
      byte[] sessionTerminalChallenge,
      int sfi,
      int recordNumber) {
    switch (revision) {
      case REV1_0:
        return new CardOpenSession10Builder(
            debitKeyIndex, sessionTerminalChallenge, sfi, recordNumber);
      case REV2_4:
        return new CardOpenSession24Builder(
            debitKeyIndex, sessionTerminalChallenge, sfi, recordNumber);
      case REV3_1:
      case REV3_1_CLAP:
        return new CardOpenSession31Builder(
            debitKeyIndex, sessionTerminalChallenge, sfi, recordNumber);
      case REV3_2:
        return new CardOpenSession32Builder(
            debitKeyIndex, sessionTerminalChallenge, sfi, recordNumber);
      default:
        throw new IllegalArgumentException("Revision " + revision + " isn't supported");
    }
  }

  /** @return the SFI of the file read while opening the secure session */
  abstract int getSfi();

  /** @return the record number to read */
  abstract int getRecordNumber();
}
