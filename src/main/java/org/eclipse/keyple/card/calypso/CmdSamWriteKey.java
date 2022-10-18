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

import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the Write Key APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamWriteKey extends AbstractSamCommand {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.WRITE_KEY;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", CalypsoSamCounterOverflowException.class));
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied.", CalypsoSamAccessForbiddenException.class));
    m.put(
        0x6988,
        new StatusProperties("Incorrect signature.", CalypsoSamSecurityDataException.class));
    m.put(
        0x6A00,
        new StatusProperties("P1 or P2 incorrect.", CalypsoSamIllegalParameterException.class));
    m.put(
        0x6A80,
        new StatusProperties(
            "Incorrect plain or decrypted data.", CalypsoSamIncorrectInputDataException.class));
    m.put(
        0x6A83,
        new StatusProperties(
            "Record not found: deciphering key not found.", CalypsoSamDataAccessException.class));
    m.put(
        0x6A87,
        new StatusProperties(
            "Lc inconsistent with P1 or P2.", CalypsoSamIncorrectInputDataException.class));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * CalypsoSamCardSelectorBuilder constructor
   *
   * @param calypsoSam The Calypso SAM.
   * @param writingMode the writing mode (P1).
   * @param keyReference the key reference (P2).
   * @param keyData the key data.
   * @since 2.0.1
   */
  CmdSamWriteKey(
      CalypsoSamAdapter calypsoSam, byte writingMode, byte keyReference, byte[] keyData) {

    super(command, 0, calypsoSam);

    byte cla = SamUtilAdapter.getClassByte(calypsoSam.getProductType());

    if (keyData == null) {
      throw new IllegalArgumentException("Key data null!");
    }

    if (keyData.length < 48 || keyData.length > 80) {
      throw new IllegalArgumentException("Key data should be between 40 and 80 bytes long!");
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, command.getInstructionByte(), writingMode, keyReference, keyData, null)));
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
