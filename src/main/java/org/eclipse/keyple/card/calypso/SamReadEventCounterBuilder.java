/* **************************************************************************************
 * Copyright (c) 2019 Calypso Networks Association https://www.calypsonet-asso.org/
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

import org.eclipse.keyple.card.calypso.sam.SamRevision;
import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private) <br>
 * Builds the Read Event Counter APDU command.
 *
 * @since 2.0
 */
final class SamReadEventCounterBuilder
    extends AbstractSamCommandBuilder<SamReadEventCounterParser> {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.READ_EVENT_COUNTER;

  public static final int MAX_COUNTER_NUMB = 26;

  public static final int MAX_COUNTER_REC_NUMB = 3;

  /** Event counter operation type */
  public enum SamEventCounterOperationType {
    /** Counter record */
    COUNTER_RECORD,
    /** Single counter */
    SINGLE_COUNTER
  }

  /**
   * Instantiate a new SamReadEventCounterBuilder
   *
   * @param revision revision of the SAM.
   * @param operationType the counter operation type.
   * @param index the counter index.
   * @since 2.0
   */
  public SamReadEventCounterBuilder(
      SamRevision revision, SamEventCounterOperationType operationType, int index) {

    super(command);
    if (revision != null) {
      this.defaultRevision = revision;
    }

    byte cla = this.defaultRevision.getClassByte();
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
        new ApduRequest(
            ApduUtil.build(cla, command.getInstructionByte(), (byte) 0x00, p2, null, (byte) 0x00)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamReadEventCounterParser createResponseParser(ApduResponse apduResponse) {
    return new SamReadEventCounterParser(apduResponse, this);
  }
}
