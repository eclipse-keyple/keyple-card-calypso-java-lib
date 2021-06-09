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

import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private) <br>
 * Builds the Read Key Parameters APDU command.
 *
 * @since 2.0
 */
final class SamReadKeyParametersBuilder
    extends AbstractSamCommandBuilder<SamReadKeyParametersParser> {
  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.READ_KEY_PARAMETERS;

  public static final int MAX_WORK_KEY_REC_NUMB = 126;

  /** Source reference */
  public enum SourceRef {
    /** Work key */
    WORK_KEY,
    /** System key */
    SYSTEM_KEY
  }

  /** Navigation control */
  public enum NavControl {
    /** First */
    FIRST,
    /** Next */
    NEXT
  }

  public SamReadKeyParametersBuilder(CalypsoSam.ProductType revision) {

    super(command);
    if (revision != null) {
      this.defaultProductType = revision;
    }

    byte cla = SamUtilAdapter.getClassByte(this.defaultProductType);

    byte p2 = (byte) 0xE0;
    byte[] sourceKeyId = new byte[] {0x00, 0x00};

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, command.getInstructionByte(), (byte) 0x00, p2, sourceKeyId, (byte) 0x00)));
  }

  public SamReadKeyParametersBuilder(CalypsoSam.ProductType revision, byte kif) {

    super(command);
    if (revision != null) {
      this.defaultProductType = revision;
    }

    byte cla = SamUtilAdapter.getClassByte(this.defaultProductType);

    byte p2 = (byte) 0xC0;
    byte[] sourceKeyId = new byte[] {0x00, 0x00};

    sourceKeyId[0] = kif;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, command.getInstructionByte(), (byte) 0x00, p2, sourceKeyId, (byte) 0x00)));
  }

  public SamReadKeyParametersBuilder(CalypsoSam.ProductType revision, byte kif, byte kvc) {

    super(command);
    if (revision != null) {
      this.defaultProductType = revision;
    }

    byte cla = SamUtilAdapter.getClassByte(this.defaultProductType);

    byte p2 = (byte) 0xF0;
    byte[] sourceKeyId = new byte[] {0x00, 0x00};

    sourceKeyId[0] = kif;
    sourceKeyId[1] = kvc;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, command.getInstructionByte(), (byte) 0x00, p2, sourceKeyId, (byte) 0x00)));
  }

  public SamReadKeyParametersBuilder(
      CalypsoSam.ProductType revision, SourceRef sourceKeyRef, int recordNumber) {

    super(command);

    if (revision != null) {
      this.defaultProductType = revision;
    }

    if (recordNumber < 1 || recordNumber > MAX_WORK_KEY_REC_NUMB) {
      throw new IllegalArgumentException(
          "Record Number must be between 1 and " + MAX_WORK_KEY_REC_NUMB + ".");
    }

    byte cla = SamUtilAdapter.getClassByte(this.defaultProductType);

    byte p2;
    byte[] sourceKeyId = new byte[] {0x00, 0x00};

    switch (sourceKeyRef) {
      case WORK_KEY:
        p2 = (byte) recordNumber;
        break;

      case SYSTEM_KEY:
        p2 = (byte) (0xC0 + (byte) recordNumber);
        break;

      default:
        throw new IllegalStateException(
            "Unsupported SourceRef parameter " + sourceKeyRef.toString());
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, command.getInstructionByte(), (byte) 0x00, p2, sourceKeyId, (byte) 0x00)));
  }

  public SamReadKeyParametersBuilder(
      CalypsoSam.ProductType revision, byte kif, NavControl navControl) {

    super(command);
    if (revision != null) {
      this.defaultProductType = revision;
    }

    byte cla = SamUtilAdapter.getClassByte(this.defaultProductType);

    byte p2;
    byte[] sourceKeyId = new byte[] {0x00, 0x00};

    switch (navControl) {
      case FIRST:
        p2 = (byte) 0xF8;
        break;

      case NEXT:
        p2 = (byte) 0xFA;
        break;

      default:
        throw new IllegalStateException(
            "Unsupported NavControl parameter " + navControl.toString());
    }

    sourceKeyId[0] = kif;

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                cla, command.getInstructionByte(), (byte) 0x00, p2, sourceKeyId, (byte) 0x00)));
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamReadKeyParametersParser createResponseParser(ApduResponseApi apduResponse) {
    return new SamReadKeyParametersParser(apduResponse, this);
  }
}
