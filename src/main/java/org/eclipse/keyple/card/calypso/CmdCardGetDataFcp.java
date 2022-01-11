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
import org.eclipse.keyple.core.util.ApduUtil;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.BerTlvUtil;

/**
 * (package-private)<br>
 * Builds the Get data APDU commands for the FCP tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because it would generate a
 * 6Cxx status and thus make calculation of the digest impossible.
 *
 * <p>The value of the Proprietary Information tag is extracted from the Select File response and
 * made available using the corresponding getter.
 *
 * @since 2.0.1
 */
final class CmdCardGetDataFcp extends AbstractCardCommand {

  private static final CalypsoCardCommand command = CalypsoCardCommand.GET_DATA;

  private static final int TAG_PROPRIETARY_INFORMATION = 0x85;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractApduCommand.STATUS_TABLE);
    m.put(
        0x6A88,
        new StatusProperties(
            "Data object not found (optional mode not available).", CardDataAccessException.class));
    m.put(0x6A82, new StatusProperties("File not found.", CardDataAccessException.class));
    m.put(
        0x6B00,
        new StatusProperties("P1 or P2 value not supported.", CardDataAccessException.class));
    STATUS_TABLE = m;
  }

  private byte[] proprietaryInformation;

  /**
   * (package-private)<br>
   * Instantiates a new CmdCardGetDataFci.
   *
   * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
   * @since 2.0.1
   */
  CmdCardGetDataFcp(CalypsoCardClass calypsoCardClass) {

    super(command);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                calypsoCardClass.getValue(),
                command.getInstructionByte(),
                (byte) 0x00,
                (byte) 0x62,
                null,
                (byte) 0x00)));
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
   * @return The content of the proprietary information tag present in the response to the Get Data
   *     (FCP) command
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
