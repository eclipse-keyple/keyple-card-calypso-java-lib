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
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the Read Event Counter APDU command.
 *
 * @since 2.0.0
 */
final class CmdSamReadEventCounter extends AbstractSamCommand {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.READ_EVENT_COUNTER;

  private static final int MAX_COUNTER_NUMB = 26;

  private static final int MAX_COUNTER_REC_NUMB = 3;

  /** Event counter operation type */
  enum SamEventCounterOperationType {
    /** Counter record */
    COUNTER_RECORD,
    /** Single counter */
    SINGLE_COUNTER
  }

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", CalypsoSamCounterOverflowException.class));
    m.put(0x6A00, new StatusProperties("Incorrect P2.", CalypsoSamIllegalParameterException.class));
    m.put(0x6200, new StatusProperties("Correct execution with warning: data not signed.", null));
    STATUS_TABLE = m;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * (package-private)<br>
   * Instantiate a new CmdSamReadEventCounter
   *
   * @param productType the SAM product type.
   * @param operationType the counter operation type.
   * @param index the counter index.
   * @since 2.0.0
   */
  CmdSamReadEventCounter(
      CalypsoSam.ProductType productType, SamEventCounterOperationType operationType, int index) {

    super(command);

    byte cla = SamUtilAdapter.getClassByte(productType);
    byte p2;

    if (operationType == SamEventCounterOperationType.COUNTER_RECORD) {
      if (index < 1 || index > MAX_COUNTER_REC_NUMB) {
        throw new IllegalArgumentException(
            "Record Number must be between 1 and " + MAX_COUNTER_REC_NUMB + ".");
      }
      p2 = (byte) (0xE0 + index);
    } else {
      // SINGLE_COUNTER
      if (index < 0 || index > MAX_COUNTER_NUMB) {
        throw new IllegalArgumentException(
            "Counter Number must be between 0 and " + MAX_COUNTER_NUMB + ".");
      }
      p2 = (byte) (0x80 + index);
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), (byte) 0x00, p2, null, (byte) 0x00)));
  }

  /**
   * (package-private)<br>
   * Gets the key parameters.
   *
   * @return the counter data (Value or Record)
   * @since 2.0.0
   */
  byte[] getCounterData() {
    return isSuccessful() ? getApduResponse().getDataOut() : null;
  }
}
