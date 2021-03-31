/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.calypso;

import org.eclipse.keyple.calypso.po.SelectFileControl;
import org.eclipse.keyple.core.card.ApduRequest;
import org.eclipse.keyple.core.card.ApduResponse;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Select File APDU commands.
 *
 * @since 2.0
 */
final class PoSelectFileBuilder extends AbstractPoCommandBuilder<PoSelectFileParser> {
  private static final Logger logger = LoggerFactory.getLogger(PoSelectFileBuilder.class);

  private static final PoCommand command = PoCommand.SELECT_FILE;

  /* Construction arguments */
  private final byte[] path;
  private final SelectFileControl selectFileControl;

  /**
   * Instantiates a new PoSelectFileBuilder to select the first, next or current file in the current
   * DF.
   *
   * @param poClass indicates which CLA byte should be used for the Apdu.
   * @param selectFileControl the selection mode control: FIRST, NEXT or CURRENT.
   * @since 2.0
   */
  public PoSelectFileBuilder(PoClass poClass, SelectFileControl selectFileControl) {
    super(command);

    this.path = null;
    this.selectFileControl = selectFileControl;

    byte cla = poClass.getValue();
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
            "Unsupported selectFileControl parameter " + selectFileControl.toString());
    }

    setApduRequest(
        new ApduRequest(cla, command.getInstructionByte(), p1, p2, selectData, (byte) 0x00));

    if (logger.isDebugEnabled()) {
      this.addSubName("SELECTIONCONTROL" + selectFileControl);
    }
  }

  /**
   * Instantiates a new PoSelectFileBuilder to select the first, next or current file in the current
   * DF.
   *
   * @param poClass indicates which CLA byte should be used for the Apdu.
   * @param selectionPath the file identifier path.
   * @since 2.0
   */
  public PoSelectFileBuilder(PoClass poClass, byte[] selectionPath) {
    super(command);

    this.path = selectionPath;
    this.selectFileControl = null;

    // handle the REV1 case
    byte p1 = (byte) (poClass == PoClass.LEGACY ? 0x08 : 0x09);

    setApduRequest(
        new ApduRequest(
            poClass.getValue(),
            command.getInstructionByte(),
            p1,
            (byte) 0x00,
            selectionPath,
            (byte) 0x00));

    if (logger.isDebugEnabled()) {
      this.addSubName("SELECTIONPATH=" + ByteArrayUtil.toHex(selectionPath));
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoSelectFileParser createResponseParser(ApduResponse apduResponse) {
    return new PoSelectFileParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command doesn't modify the contents of the PO and therefore doesn't uses the session
   * buffer.
   *
   * @return false
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * The selection path can be null if the chosen constructor targets the current EF
   *
   * @return the selection path or null
   * @since 2.0
   */
  public byte[] getPath() {
    return path;
  }

  /**
   * The file selection control can be null if the chosen constructor targets an explicit path
   *
   * @return the select file control or null
   * @since 2.0
   */
  public SelectFileControl getSelectFileControl() {
    return selectFileControl;
  }
}
