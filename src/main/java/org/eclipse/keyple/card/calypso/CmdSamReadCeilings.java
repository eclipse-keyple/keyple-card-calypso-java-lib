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
 * Builds the Read Ceilings APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamReadCeilings extends AbstractSamCommand {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.READ_CEILINGS;

  private static final int MAX_CEILING_NUMB = 26;

  private static final int MAX_CEILING_REC_NUMB = 3;

  /** Ceiling operation type */
  enum CeilingsOperationType {
    /** Ceiling record */
    CEILING_RECORD,
    /** Single ceiling */
    SINGLE_CEILING
  }

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(
        0x6900,
        new StatusProperties(
            "An event counter cannot be incremented.", CalypsoSamCounterOverflowException.class));
    m.put(
        0x6A00,
        new StatusProperties("Incorrect P1 or P2.", CalypsoSamIllegalParameterException.class));
    m.put(0x6200, new StatusProperties("Correct execution with warning: data not signed.", null));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdSamReadCeilings.
   *
   * @param productType the SAM product type.
   * @param operationType the counter operation type.
   * @param index the counter index.
   * @since 2.0.1
   */
  CmdSamReadCeilings(
      CalypsoSam.ProductType productType, CeilingsOperationType operationType, int index) {

    super(command, 0);

    byte cla = SamUtilAdapter.getClassByte(productType);

    byte p1;
    byte p2;

    if (operationType == CeilingsOperationType.CEILING_RECORD) {
      if (index < 0 || index > MAX_CEILING_REC_NUMB) {
        throw new IllegalArgumentException(
            "Record Number must be between 1 and " + MAX_CEILING_REC_NUMB + ".");
      }
      p1 = (byte) 0x00;
      p2 = (byte) (0xB0 + index);
    } else {
      // SINGLE_CEILING:

      if (index < 0 || index > MAX_CEILING_NUMB) {
        throw new IllegalArgumentException(
            "Counter Number must be between 0 and " + MAX_CEILING_NUMB + ".");
      }
      p1 = (byte) index;
      p2 = (byte) (0xB8);
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, null, (byte) 0x00)));
  }

  /**
   * (package-private)<br>
   * Gets the key parameters.
   *
   * @return The ceiling data (Value or Record)
   * @since 2.0.1
   */
  byte[] getCeilingsData() {
    return isSuccessful() ? getApduResponse().getDataOut() : null;
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
