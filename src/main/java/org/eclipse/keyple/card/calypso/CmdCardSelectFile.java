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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.calypso.SelectFileControl;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.BerTlvUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Select File APDU commands.
 *
 * <p>The value of the Proprietary Information tag is extracted from the Select File response and
 * made available using the corresponding getter.
 *
 * @since 2.0.1
 */
final class CmdCardSelectFile extends AbstractCardCommand {

  private static final Logger logger = LoggerFactory.getLogger(CmdCardSelectFile.class);

  private static final CalypsoCardCommand command = CalypsoCardCommand.SELECT_FILE;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
    m.put(
        0x6700,
        new StatusProperties("Lc value not supported.", CardIllegalParameterException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    m.put(0x6119, new StatusProperties("Correct execution (ISO7816 T=0).", null));
    STATUS_TABLE = m;
  }

  private static final int TAG_PROPRIETARY_INFORMATION = 0x85;

  private byte[] proprietaryInformation;

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
   * DF.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param selectFileControl the selection mode control: FIRST, NEXT or CURRENT.
   * @since 2.0.1
   */
  CmdCardSelectFile(CalypsoCardClass calypsoCardClass, SelectFileControl selectFileControl) {

    super(command);

    byte cla = calypsoCardClass.getValue();
    byte p1;
    byte p2;
    byte[] selectData = new byte[] {0x00, 0x00};
    switch (selectFileControl) {
      case FIRST_EF:
        p1 = (byte) 0x02;
        p2 = (byte) 0x00;
        break;
      case NEXT_EF:
        p1 = (byte) 0x02;
        p2 = (byte) 0x02;
        break;
      case CURRENT_DF:
        p1 = (byte) 0x09;
        p2 = (byte) 0x00;
        break;
      default:
        throw new IllegalStateException(
            "Unsupported selectFileControl parameter " + selectFileControl.name());
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, selectData, (byte) 0x00)));

    if (logger.isDebugEnabled()) {
      addSubName("SELECTIONCONTROL" + selectFileControl);
    }
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
   * DF.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param selectionPath the file identifier path.
   * @since 2.0.1
   */
  CmdCardSelectFile(CalypsoCardClass calypsoCardClass, byte[] selectionPath) {
    super(command);

    // handle the REV1 case
    byte p1 = (byte) (calypsoCardClass == CalypsoCardClass.LEGACY ? 0x08 : 0x09);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(),
                command.getInstructionByte(),
                p1,
                (byte) 0x00,
                selectionPath,
                (byte) 0x00)));

    if (logger.isDebugEnabled()) {
      addSubName("SELECTIONPATH=" + ByteArrayUtil.toHex(selectionPath));
    }
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
   * (package-private)<br>
   *
   * @return The content of the proprietary information tag present in the response to the Select
   *     File command
   * @since 2.0.1
   */
  byte[] getProprietaryInformation() {
    if (proprietaryInformation == null) {
      Map<Integer, byte[]> tags = BerTlvUtil.parseSimple(getApduResponse().getDataOut(), true);
      proprietaryInformation = tags.get(TAG_PROPRIETARY_INFORMATION);
      if (proprietaryInformation == null) {
        throw new IllegalStateException("Proprietary information: tag not found.");
      }
      Assert.getInstance().isEqual(proprietaryInformation.length, 23, "proprietaryInformation");
    }
    return proprietaryInformation;
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
