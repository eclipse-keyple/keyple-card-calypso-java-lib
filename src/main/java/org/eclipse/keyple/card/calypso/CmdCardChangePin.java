/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://calypsonet.org/
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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the Change PIN APDU command.
 *
 * @since 2.0.1
 */
final class CmdCardChangePin extends CardCommand {

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc value not supported (not 04h, 10h, 18h, 20h).",
            CardIllegalParameterException.class));
    m.put(0x6900, new StatusProperties("Transaction Counter is 0.", CardTerminatedException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (Get Challenge not done: challenge unavailable).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (a session is open or DF is invalidated).",
            CardAccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("Incorrect Cryptogram.", CardSecurityDataException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Decrypted message incorrect (key algorithm not supported, incorrect padding, etc.).",
            CardSecurityDataException.class));
    m.put(
        0x6A87,
        new StatusProperties("Lc not compatible with P2.", CardIllegalParameterException.class));
    m.put(0x6B00, new StatusProperties("Incorrect P1, P2.", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * Builds a Calypso Change PIN command
   *
   * @param calypsoCard The Calypso card.
   * @param newPinData The new PIN data either plain or encrypted.
   * @since 2.0.1
   */
  CmdCardChangePin(CalypsoCardAdapter calypsoCard, byte[] newPinData) {

    super(CardCommandRef.CHANGE_PIN, 0, calypsoCard);

    if (newPinData == null || (newPinData.length != 0x04 && newPinData.length != 0x10)) {
      throw new IllegalArgumentException("Bad PIN data length.");
    }

    byte cla = calypsoCard.getCardClass().getValue();
    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0xFF; // CL-PIN-MP1P2.1

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, getCommandRef().getInstructionByte(), p1, p2, newPinData, null)));
  }

  /**
   * {@inheritDoc}
   *
   * @return false
   * @since 2.0.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
