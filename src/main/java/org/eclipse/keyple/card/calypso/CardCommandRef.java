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
 * Defines all supported Calypso card APDU commands.
 *
 * @since 2.0.0
 */
enum CardCommandRef {
  GET_DATA("Get Data", (byte) 0xCA),
  OPEN_SECURE_SESSION("Open Secure Session", (byte) 0x8A),
  CLOSE_SECURE_SESSION("Close Secure Session", (byte) 0x8E),
  MANAGE_SECURE_SESSION("Manage Secure Session", (byte) 0x82),
  RATIFICATION("Ratification", (byte) 0xB2),
  READ_RECORDS("Read Records", (byte) 0xB2),
  UPDATE_RECORD("Update Record", (byte) 0xDC),
  WRITE_RECORD("Write Record", (byte) 0xD2),
  APPEND_RECORD("Append Record", (byte) 0xE2),
  READ_BINARY("Read Binary", (byte) 0xB0),
  UPDATE_BINARY("Update Binary", (byte) 0xD6),
  WRITE_BINARY("Write Binary", (byte) 0xD0),
  SEARCH_RECORD_MULTIPLE("Search Record Multiple", (byte) 0xA2),
  READ_RECORD_MULTIPLE("Read Record Multiple", (byte) 0xB3),
  GET_CHALLENGE("Get Challenge", (byte) 0x84),
  INCREASE("Increase", (byte) 0x32),
  DECREASE("Decrease", (byte) 0x30),
  INCREASE_MULTIPLE("Increase Multiple", (byte) 0x3A),
  DECREASE_MULTIPLE("Decrease Multiple", (byte) 0x38),
  SELECT_FILE("Select File", (byte) 0xA4),
  CHANGE_KEY("Change Key", (byte) 0xD8),
  CHANGE_PIN("Change PIN", (byte) 0xD8),
  VERIFY_PIN("Verify PIN", (byte) 0x20),
  SV_GET("SV Get", (byte) 0x7C),
  SV_DEBIT("SV Debit", (byte) 0xBA),
  SV_RELOAD("SV Reload", (byte) 0xB8),
  SV_UNDEBIT("SV Undebit", (byte) 0xBC),
  INVALIDATE("Invalidate", (byte) 0x04),
  REHABILITATE("Invalidate", (byte) 0x44);

  /** The command name. */
  private final String name;

  /** The instruction byte. */
  private final byte instructionByte;

  /**
   * The generic constructor of CalypsoCommands.
   *
   * @param name the name.
   * @param instructionByte the instruction byte.
   * @since 2.0.0
   */
  CardCommandRef(String name, byte instructionByte) {
    this.name = name;
    this.instructionByte = instructionByte;
  }

  /**
   * Gets the name.
   *
   * @return A String
   * @since 2.0.0
   */
  public String getName() {
    return name;
  }

  /**
   * Gets the instruction byte (INS).
   *
   * @return A byte
   * @since 2.0.0
   */
  public byte getInstructionByte() {
    return instructionByte;
  }
}
