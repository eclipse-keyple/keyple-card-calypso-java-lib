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

/**
 * (package-private)<br>
 * Provides the API to get CardCommand's name and instruction byte (INS).
 *
 * @since 2.0
 */
interface CardCommand {

  /**
   * Gets command's name.
   *
   * @return A String
   * @since 2.0
   */
  String getName();

  /**
   * Gets Instruction Byte (INS)
   *
   * @return A byte.
   * @since 2.0
   */
  byte getInstructionByte();
}
