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

import java.util.*;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the "Increase/Decrease Multiple" APDU command.
 *
 * @since 2.1.0
 */
final class CmdCardIncreaseOrDecreaseMultiple extends AbstractCardCommand {

  private static final Logger logger =
      LoggerFactory.getLogger(CmdCardIncreaseOrDecreaseMultiple.class);
  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractCardCommand.STATUS_TABLE);
    m.put(
        0x6400,
        new StatusProperties(
            "Too many modifications in session.", CardSessionBufferOverflowException.class));
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CardIllegalParameterException.class));
    m.put(
        0x6981,
        new StatusProperties(
            "Incorrect EF type: not a Counters EF.", CardDataAccessException.class));
    m.put(
        0x6982,
        new StatusProperties(
            "Security conditions not fulfilled (no secure session, incorrect key, encryption required, PKI mode and not Always access mode).",
            CardSecurityContextException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Access forbidden (Never access mode, DF is invalid, etc.).",
            CardAccessForbiddenException.class));
    m.put(
        0x6986,
        new StatusProperties(
            "Incorrect file type: the Current File is not an EF. Supersedes 6981h.",
            CardDataAccessException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect command data (Overflow error, Incorrect counter number, Counter number present more than once).",
            CardIllegalParameterException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  private final byte sfi;
  private final Map<Integer, Integer> counterNumberToIncDecValueMap;

  /**
   * (package-private)<br>
   * Constructor.
   *
   * @param isDecreaseCommand True if it is a "Decrease Multiple" command, false if it is an
   *     "Increase Multiple" command.
   * @param calypsoCard The Calypso card.
   * @param sfi The SFI.
   * @param counterNumberToIncDecValueMap The map containing the counter numbers to be incremented
   *     and their associated increment values.
   * @since 2.1.0
   */
  CmdCardIncreaseOrDecreaseMultiple(
      boolean isDecreaseCommand,
      CalypsoCardAdapter calypsoCard,
      byte sfi,
      SortedMap<Integer, Integer> counterNumberToIncDecValueMap) {

    super(
        isDecreaseCommand
            ? CalypsoCardCommand.DECREASE_MULTIPLE
            : CalypsoCardCommand.INCREASE_MULTIPLE,
        0,
        calypsoCard);

    this.sfi = sfi;
    this.counterNumberToIncDecValueMap = counterNumberToIncDecValueMap;
    byte p1 = 0;
    byte p2 = (byte) (sfi * 8);
    byte[] dataIn = new byte[4 * counterNumberToIncDecValueMap.size()];
    int index = 0;
    for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
      dataIn[index] = entry.getKey().byteValue();
      Integer incDecValue = entry.getValue();
      ByteArrayUtil.copyBytes(incDecValue, dataIn, index + 1, 3);
      index += 4;
    }
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCard.getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                p1,
                p2,
                dataIn,
                (byte) 0)));

    if (logger.isDebugEnabled()) {
      StringBuilder extraInfo = new StringBuilder(String.format("SFI:%02Xh", sfi));
      for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
        extraInfo.append(", ");
        extraInfo.append(entry.getKey());
        extraInfo.append(":");
        extraInfo.append(entry.getValue());
      }
      addSubName(extraInfo.toString());
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command modified the contents of the card and therefore uses the session buffer.
   *
   * @return false
   * @since 2.1.0
   */
  @Override
  boolean isSessionBufferUsed() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  void parseApduResponse(ApduResponseApi apduResponse) throws CardCommandException {
    super.parseApduResponse(apduResponse);
    if (apduResponse.getDataOut().length > 0) {
      byte[] dataOut = apduResponse.getDataOut();
      int nbCounters = dataOut.length / 4;
      for (int i = 0; i < nbCounters; i++) {
        getCalypsoCard()
            .setCounter(
                sfi, dataOut[i * 4] & 0xFF, Arrays.copyOfRange(dataOut, (i * 4) + 1, (i * 4) + 4));
      }
    }
  }

  /**
   * (package-private)<br>
   *
   * @return The SFI.
   * @since 2.1.0
   */
  int getSfi() {
    return sfi;
  }

  /**
   * (package-private)<br>
   *
   * @return The counters/values map.
   * @since 2.1.0
   */
  public Map<Integer, Integer> getCounterNumberToIncDecValueMap() {
    return counterNumberToIncDecValueMap;
  }
}
