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

/**
 * (package-private)<br>
 * Defines the two existing ISO7816 class bytes for a Calypso card command.: LEGACY for REV1 /
 * BPRIME type card, ISO for REV2/3 / B type
 *
 * @since 2.0.0
 */
enum CalypsoCardClass {

  /** Calypso product type 1/2 / B Prime protocol, regular commands */
  LEGACY((byte) 0x94),

  /** Calypso product type 1/2 / B Prime protocol, Stored Value commands */
  LEGACY_STORED_VALUE((byte) 0xFA),

  /** Calypso product type 3 and higher */
  ISO((byte) 0x00);

  private final byte cla;

  /**
   * Gets the class byte.
   *
   * @return A byte
   * @since 2.0.0
   */
  public byte getValue() {
    return cla;
  }

  /**
   * Constructor
   *
   * @param cla class byte value.
   */
  CalypsoCardClass(byte cla) {
    this.cla = cla;
  }
}
