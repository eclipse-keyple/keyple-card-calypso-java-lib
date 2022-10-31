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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.HexUtil;

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
    m.put(
        0x6985, new StatusProperties("No session was opened.", CardAccessForbiddenException.class));
    m.put(0x6988, new StatusProperties("incorrect signatureLo.", CardSecurityDataException.class));
    STATUS_TABLE = m;
  }

  /** The signatureLo. */
  private byte[] signatureLo;

  /** The postponed data. */
  private final List<byte[]> postponedData = new ArrayList<byte[]>(0);

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
      CalypsoCardAdapter calypsoCard, boolean ratificationAsked, byte[] terminalSessionSignature) {

    super(command, 0, calypsoCard);

    // The optional parameter terminalSessionSignature could contain 4 or 8
    // bytes.
    if (terminalSessionSignature != null
        && terminalSessionSignature.length != 4
        && terminalSessionSignature.length != 8) {
      throw new IllegalArgumentException(
          "Invalid terminal sessionSignature: " + HexUtil.toHex(terminalSessionSignature));
    }

    byte p1 = ratificationAsked ? (byte) 0x80 : (byte) 0x00;
    /*
     * case 4: this command contains incoming and outgoing data. We define le = 0, the actual
     * length will be processed by the lower layers.
     */
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCard.getCardClass().getValue(),
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
  CmdCardCloseSession(CalypsoCardAdapter calypsoCard) {

    super(command, 0, calypsoCard);

    // CL-CSS-ABORTCMD.1
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCard.getCardClass().getValue(),
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
  void parseApduResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.parseApduResponse(apduResponse);
    byte[] responseData = getApduResponse().getDataOut();
    if (responseData.length > 0) {
      int signatureLength = getCalypsoCard().isExtendedModeSupported() ? 8 : 4;
      int i = 0;
      while (i < responseData.length - signatureLength) {
        byte[] data = Arrays.copyOfRange(responseData, i + 1, i + responseData[i]);
        postponedData.add(data);
        i += responseData[i];
      }
      signatureLo = Arrays.copyOfRange(responseData, i, signatureLength);
    } else {
      // session abort case
      signatureLo = new byte[0];
    }
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
   * Returns the secure session postponed data (e.g. Sv Signature).
   *
   * @return An empty list if there is no postponed data.
   * @since 2.0.1
   */
  List<byte[]> getPostponedData() {
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
