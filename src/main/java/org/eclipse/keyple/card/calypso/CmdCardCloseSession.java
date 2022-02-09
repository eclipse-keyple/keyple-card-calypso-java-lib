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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Builds the Close Secure Session APDU command.
 *
 * @since 2.0.1
 */
final class CmdCardCloseSession extends AbstractCardCommand {

  /** The command. */
  private static final CalypsoCardCommand command = CalypsoCardCommand.CLOSE_SESSION;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties(
            "Lc signatureLo not supported (e.g. Lc=4 with a Revision 3.2 mode for Open Secure Session).",
            CardIllegalParameterException.class));
    m.put(
        0x6B00,
        new StatusProperties(
            "P1 or P2 signatureLo not supported.", CardIllegalParameterException.class));
    m.put(0x6988, new StatusProperties("incorrect signatureLo.", CardSecurityDataException.class));
    m.put(
        0x6985, new StatusProperties("No session was opened.", CardAccessForbiddenException.class));
    STATUS_TABLE = m;
  }

  private final CalypsoCard calypsoCard;

  /** The signatureLo. */
  private byte[] signatureLo;

  /** The postponed data. */
  private byte[] postponedData;

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardCloseSession depending on the product type of the card.
   *
   * @param calypsoCard The {@link CalypsoCard}.
   * @param ratificationAsked the ratification asked.
   * @param terminalSessionSignature the sam half session signature.
   * @throws IllegalArgumentException If the signature is null or has a wrong length
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.0.1
   */
  CmdCardCloseSession(
      CalypsoCard calypsoCard, boolean ratificationAsked, byte[] terminalSessionSignature) {

    super(command, 0);

    this.calypsoCard = calypsoCard;

    // The optional parameter terminalSessionSignature could contain 4 or 8
    // bytes.
    if (terminalSessionSignature != null
        && terminalSessionSignature.length != 4
        && terminalSessionSignature.length != 8) {
      throw new IllegalArgumentException(
          "Invalid terminal sessionSignature: " + ByteArrayUtil.toHex(terminalSessionSignature));
    }

    byte p1 = ratificationAsked ? (byte) 0x80 : (byte) 0x00;
    /*
     * case 4: this command contains incoming and outgoing data. We define le = 0, the actual
     * length will be processed by the lower layers.
     */
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                ((CalypsoCardAdapter) calypsoCard).getCardClass().getValue(),
                command.getInstructionByte(),
                p1,
                (byte) 0x00,
                terminalSessionSignature,
                (byte) 0)));
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardCloseSession based on the product type of the card to generate an
   * abort session command (Close Secure Session with p1 = p2 = lc = 0).
   *
   * @param calypsoCard The {@link CalypsoCard}.
   * @since 2.0.1
   */
  CmdCardCloseSession(CalypsoCard calypsoCard) {

    super(command, 0);

    this.calypsoCard = calypsoCard;

    // CL-CSS-ABORTCMD.1
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                ((CalypsoCardAdapter) calypsoCard).getCardClass().getValue(),
                command.getInstructionByte(),
                (byte) 0x00,
                (byte) 0x00,
                null,
                (byte) 0)));
  }

  /**
   * {@inheritDoc}
   *
   * @return False
   * @since 2.0.1
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
   * @since 2.0.1
   */
  @Override
  CmdCardCloseSession setApduResponse(ApduResponseApi apduResponse) {
    super.setApduResponse(apduResponse);
    byte[] responseData = getApduResponse().getDataOut();
    if (calypsoCard.isExtendedModeSupported()) {
      // 8-byte signature
      if (responseData.length == 8) {
        // signature only
        signatureLo = Arrays.copyOfRange(responseData, 0, 8);
        postponedData = new byte[0];
      } else if (responseData.length == 12) {
        // signature + 3 postponed bytes (+1)
        signatureLo = Arrays.copyOfRange(responseData, 4, 12);
        postponedData = Arrays.copyOfRange(responseData, 1, 4);
      } else if (responseData.length == 15) {
        // signature + 6 postponed bytes (+1)
        signatureLo = Arrays.copyOfRange(responseData, 7, 15);
        postponedData = Arrays.copyOfRange(responseData, 1, 7);
      } else {
        if (responseData.length != 0) {
          throw new IllegalArgumentException(
              "Unexpected length in response to CloseSecureSession command: "
                  + responseData.length);
        }
        // session abort case
        signatureLo = new byte[0];
        postponedData = new byte[0];
      }
    } else {
      // 4-byte signature
      if (responseData.length == 4) {
        // signature only
        signatureLo = Arrays.copyOfRange(responseData, 0, 4);
        postponedData = new byte[0];
      } else if (responseData.length == 8) {
        // signature + 3 postponed bytes (+1)
        signatureLo = Arrays.copyOfRange(responseData, 4, 8);
        postponedData = Arrays.copyOfRange(responseData, 1, 4);
      } else if (responseData.length == 11) {
        // signature + 6 postponed bytes (+1)
        signatureLo = Arrays.copyOfRange(responseData, 7, 11);
        postponedData = Arrays.copyOfRange(responseData, 1, 7);
      } else {
        if (responseData.length != 0) {
          throw new IllegalArgumentException(
              "Unexpected length in response to CloseSecureSession command: "
                  + responseData.length);
        }
        // session abort case
        signatureLo = new byte[0];
        postponedData = new byte[0];
      }
    }
    return this;
  }

  /**
   * (package-private)<br>
   * Gets the low part of the session signature.
   *
   * @return A 4 or 8-byte array of bytes according to the extended mode availability.
   * @since 2.0.1
   */
  byte[] getSignatureLo() {
    return signatureLo;
  }

  /**
   * (package-private)<br>
   * Gets the secure session postponed data (e.g. Sv Signature).
   *
   * @return A 0, 3 or 6-byte array of bytes according to presence of postponed data and the
   *     extended mode usage.
   * @since 2.0.1
   */
  byte[] getPostponedData() {
    return postponedData;
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
