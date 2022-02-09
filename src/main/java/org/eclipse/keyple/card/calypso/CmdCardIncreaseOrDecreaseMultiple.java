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
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
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
  private final SortedMap<Integer, byte[]> newCounterValues = new TreeMap<Integer, byte[]>();

  /**
   * (package-private)<br>
   * Constructor.
   *
   * @param isDecreaseCommand True if it is a "Decrease Multiple" command, false if it is an
   *     "Increase Multiple" command.
   * @param calypsoCardClass The CLA field value.
   * @param sfi The SFI.
   * @param counterNumberToIncDecValueMap The map containing the counter numbers to be incremented
   *     and their associated increment values.
   * @since 2.1.0
   */
  CmdCardIncreaseOrDecreaseMultiple(
      boolean isDecreaseCommand,
      CalypsoCardClass calypsoCardClass,
      byte sfi,
      SortedMap<Integer, Integer> counterNumberToIncDecValueMap) {

    super(
        isDecreaseCommand
            ? CalypsoCardCommand.DECREASE_MULTIPLE
            : CalypsoCardCommand.INCREASE_MULTIPLE,
        0);

    this.sfi = sfi;
    this.counterNumberToIncDecValueMap = counterNumberToIncDecValueMap;
    byte p1 = 0;
    byte p2 = (byte) (sfi * 8);
    byte[] dataIn = new byte[4 * counterNumberToIncDecValueMap.size()];
    int index = 0;
    for (Map.Entry<Integer, Integer> entry : counterNumberToIncDecValueMap.entrySet()) {
      dataIn[index] = entry.getKey().byteValue();
      Integer incDecValue = entry.getValue();
      dataIn[index + 1] = (byte) ((incDecValue >> 16) & 0xFF);
      dataIn[index + 2] = (byte) ((incDecValue >> 8) & 0xFF);
      dataIn[index + 3] = (byte) (incDecValue & 0xFF);
      index += 4;
    }
    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(),
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
  CmdCardIncreaseOrDecreaseMultiple setApduResponse(ApduResponseApi apduResponse) {
    super.setApduResponse(apduResponse);
    if (apduResponse.getDataOut().length > 0) {
      byte[] dataOut = apduResponse.getDataOut();
      int nbCounters = dataOut.length / 4;
      for (int i = 0; i < nbCounters; i++) {
        newCounterValues.put(
            dataOut[i * 4] & 0xFF, Arrays.copyOfRange(dataOut, (i * 4) + 1, (i * 4) + 4));
      }
    }
    return this;
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

  /**
   * (package-private)<br>
   *
   * @return A not empty sorted map of counter values as 3-byte array by counter number, or an empty
   *     map if no data is available.
   * @since 2.1.0
   */
  SortedMap<Integer, byte[]> getNewCounterValues() {
    return newCounterValues;
  }
}
