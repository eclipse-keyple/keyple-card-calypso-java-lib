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
 * Defines all supported Calypso card APDU commands.
 *
 * @since 2.0.0
 */
enum CalypsoCardCommand implements CardCommand {

  /** get data. */
  GET_DATA("Get Data", (byte) 0xCA),

  /** open session. */
  OPEN_SESSION("Open Secure Session", (byte) 0x8A),

  /** close session. */
  CLOSE_SESSION("Close Secure Session", (byte) 0x8E),

  /** read records. */
  READ_RECORDS("Read Records", (byte) 0xB2),

  /** update record. */
  UPDATE_RECORD("Update Record", (byte) 0xDC),

  /** write record. */
  WRITE_RECORD("Write Record", (byte) 0xD2),

  /** append record. */
  APPEND_RECORD("Append Record", (byte) 0xE2),

  /** read binary. */
  READ_BINARY("Read Binary", (byte) 0xB0),

  /** update binary. */
  UPDATE_BINARY("Update Binary", (byte) 0xD6),

  /** write binary. */
  WRITE_BINARY("Write Binary", (byte) 0xD0),

  /** search record multiple. */
  SEARCH_RECORD_MULTIPLE("Search Record Multiple", (byte) 0xA2),

  /** read record multiple. */
  READ_RECORD_MULTIPLE("Read Record Multiple", (byte) 0xB3),

  /** get challenge. */
  GET_CHALLENGE("Get Challenge", (byte) 0x84),

  /** increase counter. */
  INCREASE("Increase", (byte) 0x32),

  /** decrease counter. */
  DECREASE("Decrease", (byte) 0x30),

  /** increase multiple counters. */
  INCREASE_MULTIPLE("Increase Multiple", (byte) 0x3A),

  /** decrease multiple counters. */
  DECREASE_MULTIPLE("Decrease Multiple", (byte) 0x38),

  /** decrease counter. */
  SELECT_FILE("Select File", (byte) 0xA4),

  /** change key */
  CHANGE_KEY("Change Key", (byte) 0xD8),

  /** change PIN */
  CHANGE_PIN("Change PIN", (byte) 0xD8),

  /** verify PIN */
  VERIFY_PIN("Verify PIN", (byte) 0x20),

  /** SV Get */
  SV_GET("SV Get", (byte) 0x7C),

  /** SV Debit */
  SV_DEBIT("SV Debit", (byte) 0xBA),

  /** SV Reload */
  SV_RELOAD("SV Reload", (byte) 0xB8),

  /** SV Undebit */
  SV_UNDEBIT("SV Undebit", (byte) 0xBC),

  /** invalidate */
  INVALIDATE("Invalidate", (byte) 0x04),

  /** rehabilitate */
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
  CalypsoCardCommand(String name, byte instructionByte) {
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
