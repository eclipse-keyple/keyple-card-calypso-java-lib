/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
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

import org.eclipse.keyple.core.util.Assert;

/**
 * This POJO contains additional parameters for the management of specific cases.
 *
 * @since 2.3.0
 */
public final class TerminalLimitationsSetting {
  private Integer contactReaderPayloadCapacity;

  /**
   * Defines the maximum size of APDUs that the library can generate when communicating with a
   * contact card.
   *
   * @param payloadCapacity A positive integer lower than 255.
   * @return The object instance.
   * @since 2.3.0
   */
  public TerminalLimitationsSetting setContactReaderPayloadCapacity(int payloadCapacity) {
    Assert.getInstance().isInRange(payloadCapacity, 0, 255, "payloadCapacity");
    this.contactReaderPayloadCapacity = payloadCapacity;
    return this;
  }

  /**
   * Returns the contact reader payload capacity.
   *
   * @return null if no payload capacity max has been defined.
   * @since 2.3.0
   */
  Integer getContactReaderPayloadCapacity() {
    return contactReaderPayloadCapacity;
  }
}
