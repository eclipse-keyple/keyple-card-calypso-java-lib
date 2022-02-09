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
 * Builds the Give Random APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamGiveRandom extends AbstractSamCommand {

  /** The command reference. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.GIVE_RANDOM;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(0x6700, new StatusProperties("Incorrect Lc.", CalypsoSamIllegalParameterException.class));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdSamDigestUpdate.
   *
   * @param productType the SAM product type.
   * @param random the random data.
   * @throws IllegalArgumentException If the random data is null or has a length not equal to 8 TODO
   *     implement specific settings for rev less than 3
   * @since 2.0.1
   */
  CmdSamGiveRandom(CalypsoSam.ProductType productType, byte[] random) {
    super(command, 0);

    byte cla = SamUtilAdapter.getClassByte(productType);
    byte p1 = (byte) 0x00;
    byte p2 = (byte) 0x00;

    if (random == null || random.length != 8) {
      throw new IllegalArgumentException("Random value should be an 8 bytes long");
    }

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(cla, command.getInstructionByte(), p1, p2, random, null)));
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
