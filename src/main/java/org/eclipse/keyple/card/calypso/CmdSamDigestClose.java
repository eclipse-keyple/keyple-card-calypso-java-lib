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
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.eclipse.keyple.core.util.ApduUtil;

/**
 * (package-private)<br>
 * Builds the Digest Close APDU command.
 *
 * @since 2.0.1
 */
final class CmdSamDigestClose extends AbstractSamCommand {

  /** The command. */
  private static final CalypsoSamCommand command = CalypsoSamCommand.DIGEST_CLOSE;

  private static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    Map<Integer, StatusProperties> m =
        new HashMap<Integer, StatusProperties>(AbstractSamCommand.STATUS_TABLE);
    m.put(
        0x6985,
        new StatusProperties(
            "Preconditions not satisfied.", CalypsoSamAccessForbiddenException.class));
    STATUS_TABLE = m;
  }

  /**
   * (package-private)<br>
   * Instantiates a new CmdSamDigestClose .
   *
   * @param productType the SAM product type.
   * @param expectedResponseLength the expected response length.
   * @since 2.0.1
   */
  CmdSamDigestClose(CalypsoSam.ProductType productType, int expectedResponseLength) {

    super(command, expectedResponseLength);

    setApduRequest(
        new ApduRequestAdapter(
            ApduUtil.build(
                SamUtilAdapter.getClassByte(productType),
                command.getInstructionByte(),
                (byte) 0x00,
                (byte) 0x00,
                null,
                (byte) expectedResponseLength)));
  }

  /**
   * (package-private)<br>
   * Gets the sam signature.
   *
   * @return The sam half session signature
   * @since 2.0.1
   */
  byte[] getSignature() {
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
