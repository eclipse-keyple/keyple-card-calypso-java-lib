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

import org.eclipse.keyple.core.card.ApduRequest;

/**
 * Provides the ApduRequest dedicated to the ratification command.
 *
 * <p>i.e. the command sent after closing the secure session to handle the ratification mechanism.
 * <br>
 * This particular builder is not associated with any parser since the response to this command is
 * always an error and is never checked.
 *
 * @since 2.0
 */
public final class PoRatificationBuilder {
  private PoRatificationBuilder() {}

  /**
   * @param poClass the PO class.
   * @return the ApduRequest ratification command according to the PO class provided
   * @since 2.0
   */
  public static ApduRequest getApduRequest(PoClass poClass) {
    byte[] ratificationApdu =
        new byte[] {poClass.getValue(), (byte) 0xB2, (byte) 0x00, (byte) 0x00, (byte) 0x00};

    return new ApduRequest(ratificationApdu, false);
  }
}
