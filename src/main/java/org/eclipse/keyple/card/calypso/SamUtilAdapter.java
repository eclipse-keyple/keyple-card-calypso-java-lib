/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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

/** (package-private)<br> */
final class SamUtilAdapter {
  /** Constructor */
  private SamUtilAdapter() {}

  /**
   * (package-private)<br>
   * Get the class byte to use for the provided product type.
   *
   * @param productType The SAM product type.
   * @return A byte.
   * @since 2.0.0
   */
  static byte getClassByte(CalypsoSam.ProductType productType) {
    if (productType == CalypsoSam.ProductType.SAM_S1DX) {
      return (byte) 0x94;
    }
    return (byte) 0x80;
  }
}
