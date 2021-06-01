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
package org.eclipse.keyple.card.calypso;

import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.card.calypso.card.SelectFileControl;
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Builds the Select File APDU commands.
 *
 * @since 2.0
 */
final class CardSelectFileBuilder extends AbstractCardCommandBuilder<CardSelectFileParser> {
  private static final Logger logger = LoggerFactory.getLogger(CardSelectFileBuilder.class);

  private static final CalypsoCardCommand command = CalypsoCardCommand.SELECT_FILE;

  /* Construction arguments */
  private final byte[] path;
  private final SelectFileControl selectFileControl;

  /**
   * Instantiates a new CardSelectFileBuilder to select the first, next or current file in the
   * current DF.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param selectFileControl the selection mode control: FIRST, NEXT or CURRENT.
   * @since 2.0
   */
  public CardSelectFileBuilder(
      CalypsoCardClass calypsoCardClass, SelectFileControl selectFileControl) {
    super(command);

    this.path = null;
    this.selectFileControl = selectFileControl;

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
            "Unsupported selectFileControl parameter " + selectFileControl.toString());
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, selectData, (byte) 0x00)));

    if (logger.isDebugEnabled()) {
      this.addSubName("SELECTIONCONTROL" + selectFileControl);
    }
  }

  /**
   * Instantiates a new CardSelectFileBuilder to select the first, next or current file in the
   * current DF.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @param selectionPath the file identifier path.
   * @since 2.0
   */
  public CardSelectFileBuilder(CalypsoCardClass calypsoCardClass, byte[] selectionPath) {
    super(command);

    this.path = selectionPath;
    this.selectFileControl = null;

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
      this.addSubName("SELECTIONPATH=" + ByteArrayUtil.toHex(selectionPath));
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CardSelectFileParser createResponseParser(ApduResponseApi apduResponse) {
    return new CardSelectFileParser(apduResponse, this);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This command doesn't modify the contents of the card and therefore doesn't uses the session
   * buffer.
   *
   * @return False
   * @since 2.0
   */
  @Override
  public boolean isSessionBufferUsed() {
    return false;
  }

  /**
   * The selection path can be null if the chosen constructor targets the current EF
   *
   * @return The selection path or null
   * @since 2.0
   */
  public byte[] getPath() {
    return path;
  }

  /**
   * The file selection control can be null if the chosen constructor targets an explicit path
   *
   * @return The select file control or null
   * @since 2.0
   */
  public SelectFileControl getSelectFileControl() {
    return selectFileControl;
  }
}
