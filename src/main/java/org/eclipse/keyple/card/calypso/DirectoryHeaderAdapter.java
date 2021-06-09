/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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

import java.util.EnumMap;
import org.calypsonet.terminal.calypso.WriteAccessLevel;
import org.calypsonet.terminal.calypso.card.DirectoryHeader;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.json.JsonUtil;

/**
 * (package-private)<br>
 * Implementation of {@link DirectoryHeader}.
 *
 * @since 2.0
 */
class DirectoryHeaderAdapter implements DirectoryHeader {

  private final short lid;
  private final byte[] accessConditions;
  private final byte[] keyIndexes;
  private final byte dfStatus;
  private final EnumMap<WriteAccessLevel, Byte> kif;
  private final EnumMap<WriteAccessLevel, Byte> kvc;
  private static final String LEVEL_STR = "level";

  /** Private constructor */
  private DirectoryHeaderAdapter(DirectoryHeaderBuilder builder) {
    this.lid = builder.lid;
    this.accessConditions = builder.accessConditions;
    this.keyIndexes = builder.keyIndexes;
    this.dfStatus = builder.dfStatus;
    this.kif = builder.kif;
    this.kvc = builder.kvc;
  }

  /**
   * (package-private)<br>
   * CalypsoSamCardSelectorBuilder pattern
   *
   * @since 2.0
   */
  static final class DirectoryHeaderBuilder {

    private short lid;
    private byte[] accessConditions;
    private byte[] keyIndexes;
    private byte dfStatus;
    private final EnumMap<WriteAccessLevel, Byte> kif =
        new EnumMap<WriteAccessLevel, Byte>(WriteAccessLevel.class);
    private final EnumMap<WriteAccessLevel, Byte> kvc =
        new EnumMap<WriteAccessLevel, Byte>(WriteAccessLevel.class);

    /** Private constructor */
    private DirectoryHeaderBuilder() {}

    /**
     * (package-private)<br>
     * Sets the LID.
     *
     * @param lid the LID.
     * @return the builder instance
     * @since 2.0
     */
    DirectoryHeaderBuilder lid(short lid) {
      this.lid = lid;
      return this;
    }

    /**
     * (package-private)<br>
     * Sets a reference to the provided access conditions byte array.
     *
     * @param accessConditions the access conditions (should be not null and 4 bytes length).
     * @return the builder instance
     * @since 2.0
     */
    DirectoryHeaderBuilder accessConditions(byte[] accessConditions) {
      this.accessConditions = accessConditions;
      return this;
    }

    /**
     * (package-private)<br>
     * Sets a reference to the provided key indexes byte array.
     *
     * @param keyIndexes the key indexes (should be not null and 4 bytes length).
     * @return the builder instance
     * @since 2.0
     */
    DirectoryHeaderBuilder keyIndexes(byte[] keyIndexes) {
      this.keyIndexes = keyIndexes;
      return this;
    }

    /**
     * (package-private)<br>
     * Sets the DF status.
     *
     * @param dfStatus the DF status (byte).
     * @return the builder instance
     * @since 2.0
     */
    DirectoryHeaderBuilder dfStatus(byte dfStatus) {
      this.dfStatus = dfStatus;
      return this;
    }

    /**
     * (package-private)<br>
     * Add a KIF.
     *
     * @param level the KIF session access level (should be not null).
     * @param kif the KIF value.
     * @return the builder instance
     * @since 2.0
     */
    DirectoryHeaderBuilder kif(WriteAccessLevel level, byte kif) {
      this.kif.put(level, kif);
      return this;
    }

    /**
     * (package-private)<br>
     * Add a KVC.
     *
     * @param level the KVC session access level (should be not null).
     * @param kvc the KVC value.
     * @return the builder instance
     * @since 2.0
     */
    DirectoryHeaderBuilder kvc(WriteAccessLevel level, byte kvc) {
      this.kvc.put(level, kvc);
      return this;
    }

    /**
     * (package-private)<br>
     * Build a new {@code DirectoryHeader}.
     *
     * @return a new instance
     * @since 2.0
     */
    DirectoryHeader build() {
      return new DirectoryHeaderAdapter(this);
    }
  }

  @Override
  public short getLid() {
    return lid;
  }

  @Override
  public byte[] getAccessConditions() {
    return accessConditions;
  }

  @Override
  public byte[] getKeyIndexes() {
    return keyIndexes;
  }

  @Override
  public byte getDfStatus() {
    return dfStatus;
  }

  @Override
  public byte getKif(WriteAccessLevel writeAccessLevel) {

    Assert.getInstance().notNull(writeAccessLevel, LEVEL_STR);

    return kif.get(writeAccessLevel);
  }

  @Override
  public byte getKvc(WriteAccessLevel lwriteAccessLevelvel) {

    Assert.getInstance().notNull(lwriteAccessLevelvel, LEVEL_STR);

    return kvc.get(lwriteAccessLevelvel);
  }

  /**
   * (package-private)<br>
   * Gets a new builder.
   *
   * @return a new builder instance
   * @since 2.0
   */
  static DirectoryHeaderBuilder builder() {
    return new DirectoryHeaderBuilder();
  }

  /**
   * Comparison is based on field "lid".
   *
   * @param o the object to compare.
   * @return the comparison evaluation
   * @since 2.0
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    DirectoryHeaderAdapter that = (DirectoryHeaderAdapter) o;

    return lid == that.lid;
  }

  /**
   * Comparison is based on field "lid".
   *
   * @return the hashcode
   * @since 2.0
   */
  @Override
  public int hashCode() {
    return lid;
  }

  /**
   * Gets the object content as a Json string.
   *
   * @return A not empty string.
   * @since 2.0
   */
  @Override
  public String toString() {
    return JsonUtil.toJson(this);
  }
}
