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

import static org.eclipse.keyple.card.calypso.DtoAdapters.ApduRequestAdapter;

import java.util.*;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * Builds the Manage Secure Session APDU command.
 *
 * @since 2.3.1
 */
final class CmdCardManageSession extends CardCommand {

  private static final CardCommandRef commandRef = CardCommandRef.MANAGE_SECURE_SESSION;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(CardCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CardIllegalParameterException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied:\n"
                + "- No secure session running in Extended mode.\n"
                + "- Manage Secure Session not authorized during the running\n"
                + "session (as indicated by the Flags byte of Open Secure Session).",
            CardSecurityDataException.class));
    m.put(
        0x6988,
        new StatusProperties(
            "Incorrect terminal Session MAC (the secure session is aborted).",
            CardSecurityDataException.class));
    m.put(
        0x6D00,
        new StatusProperties(
            "Extended mode not supported, or AES keys not supported.",
            CardSecurityContextException.class));
    STATUS_TABLE = m;
  }

  /** The card session MAC. */
  private byte[] cardSessionMac;

  /**
   * Instantiates a new Manage Secure Session card command depending on the product type of the
   * card.
   *
   * @param calypsoCard The Calypso card.
   * @param activateEncryption True if the activation of the encryption is required.
   * @param terminalSessionMac The terminal session MAC when the card authentication is required.
   * @since 2.3.1
   */
  CmdCardManageSession(
      CalypsoCardAdapter calypsoCard, boolean activateEncryption, byte[] terminalSessionMac) {

    super(commandRef, terminalSessionMac != null ? 8 : 0, calypsoCard);

    byte p2;
    Byte le;

    if (terminalSessionMac != null) {
      // case 4: this command contains incoming and outgoing data. We define le = 0, the actual
      // length will be processed by the lower layers.
      p2 = activateEncryption ? (byte) 0x03 : (byte) 0x01;
      le = 0;
    } else {
      // case 1: this command contains no data. We define le = null.
      p2 = activateEncryption ? (byte) 0x02 : (byte) 0x00;
      le = null;
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCard.getCardClass().getValue(),
                commandRef.getInstructionByte(),
                (byte) 0x00,
                p2,
                terminalSessionMac,
                le)));
  }

  /**
   * {@inheritDoc}
   *
   * @return False
   * @since 2.3.1
   */
  @Override
  boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Checks the card response length; the admissible lengths are 0, 4 or 8 bytes.
   *
   * @since 2.3.1
   */
  @Override
  void parseApduResponse(ApduResponseApi apduResponse) throws CardCommandException {
    try {
      super.parseApduResponse(apduResponse);
    } catch (CardSecurityDataException e) {
      if (apduResponse.getStatusWord() == 0x6985 && !getCalypsoCard().isExtendedModeSupported()) {
        throw new UnsupportedOperationException(
            "The 'Manage Secure Session' command is not available for this context (Card and/or SAM does not support the extended mode).");
      }
      throw e;
    }
    cardSessionMac = getApduResponse().getDataOut();
  }

  /**
   * Gets the low part of the session MAC.
   *
   * @return An empty or 8-byte array of bytes.
   * @since 2.3.1
   */
  byte[] getCardSessionMac() {
    return cardSessionMac;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.3.1
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }
}
