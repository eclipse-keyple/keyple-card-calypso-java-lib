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
package org.eclipse.keyple.calypso.sam;

import org.eclipse.keyple.core.common.KeypleCardResourceProfileExtension;

/**
 * Specific SAM Calypso Card Resource Profile Extension to identify and prepare Calyspo SAM within
 * the {@link org.eclipse.keyple.core.service.CardResourceService}.
 *
 * @since 2.0
 */
public interface SamCardResourceProfileExtension extends KeypleCardResourceProfileExtension {

  /**
   * Sets a filter to target all SAM having the provided specific {@link SamRevision}.
   *
   * <p>This parameter only applies to a regular plugin.
   *
   * @param samRevision The SAM revision.
   * @return Next configuration step.
   * @throws IllegalArgumentException If samRevision is null.
   * @throws IllegalStateException If this parameter has already been set.
   * @since 2.0
   */
  SamCardResourceProfileExtension setSamRevision(SamRevision samRevision);

  /**
   * Sets a filter targeting all SAMs having a serial number matching the provided regular
   * expression.
   *
   * <p>This parameter only applies to a regular plugin.
   *
   * <p>If set, only SAM resources having a SAM with a serial number matching the provided filter
   * will be allocated.<br>
   * The filter is regular expression that will be applied to the real serial number.
   *
   * <p>The regular expression is based on an hexadecimal representation of the serial number.
   *
   * <p>Example:
   *
   * <ul>
   *   <li>A filter targeting all SAMs having an 8-byte serial number starting with A0h would be
   *       "^A0.{6}$".
   *   <li>A filter targeting having the exact serial number 12345678h would be "12345678".
   * </ul>
   *
   * @param samSerialNumberRegex A regular expression.
   * @return Next configuration step.
   * @throws IllegalArgumentException If samSerialNumberRegex is null, empty or invalid.
   * @throws IllegalStateException If this parameter has already been set.
   * @since 2.0
   */
  SamCardResourceProfileExtension setSamSerialNumberRegex(String samSerialNumberRegex);

  /**
   * Sets the lock value expected by the SAM to be unlocked (8 or 16 bytes).
   *
   * <p>This parameter only applies to a regular plugin.
   *
   * @param samUnlockData A hexadecimal representation of the 16 or 32 digit long unlock value.
   * @return Next configuration step.
   * @throws IllegalArgumentException If unlockData is null, malformed or out of range.
   * @throws IllegalStateException If this parameter has already been set.
   * @since 2.0
   */
  SamCardResourceProfileExtension setSamUnlockData(String samUnlockData);
}
