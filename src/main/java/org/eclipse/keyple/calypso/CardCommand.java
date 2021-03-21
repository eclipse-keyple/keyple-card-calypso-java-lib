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

import java.io.Serializable;

/**
 * Provides the API to get CardCommand's name and instruction byte (INS).
 *
 * @since 2.0
 */
public interface CardCommand extends Serializable {

  /**
   * Gets command's name.
   *
   * @return a String
   * @since 2.0
   */
  String getName();

  /**
   * Gets Instruction Byte (INS)
   *
   * @return a byte.
   * @since 2.0
   */
  byte getInstructionByte();
}
