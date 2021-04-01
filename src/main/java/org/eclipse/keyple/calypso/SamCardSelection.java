/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://www.calypsonet-asso.org/
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

import org.eclipse.keyple.calypso.sam.SamRevision;
import org.eclipse.keyple.core.service.selection.spi.CardSelection;

/**
 * (package-private)<br>
 * SAM specific {@link CardSelection} providing means to define commands to execute during the
 * selection phase.
 *
 * @since 2.0
 */
interface SamCardSelection extends CardSelection {

  /**
   * Prepares an APDU command to be sent to the SAM during the selection process to unlock it.
   *
   * <p>The provided unlock data will be sent to the SAM as payload of the UNLOCK APDU command.
   *
   * <p>Note that at this stage the SAM is not yet selected, so we can only presume what its version
   * is.
   *
   * @param samRevision The supposed {@link SamRevision}.
   * @param unlockData A byte array containing the unlock data (8 or 16 bytes).
   * @throws IllegalArgumentException If one of the provided argument is null or out of range.
   * @since 2.0
   */
  void prepareUnlock(SamRevision samRevision, byte[] unlockData);
}
