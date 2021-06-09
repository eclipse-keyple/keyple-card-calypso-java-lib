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

import java.util.Arrays;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.card.FileHeader;
import org.eclipse.keyple.core.util.json.JsonUtil;

/**
 * (package-private)<br>
 * Implementation of {@link FileHeader}.
 *
 * @since 2.0
 */
class FileHeaderAdapter implements FileHeader {

  private final short lid;
  private final int recordsNumber;
  private final int recordSize;
  private final ElementaryFile.Type type;
  private final byte[] accessConditions;
  private final byte[] keyIndexes;
  private final byte dfStatus;
  private final Short sharedReference;

  /** Private constructor */
  private FileHeaderAdapter(FileHeaderBuilder builder) {
    this.lid = builder.lid;
    this.recordsNumber = builder.recordsNumber;
    this.recordSize = builder.recordSize;
    this.type = builder.type;
    this.accessConditions = builder.accessConditions;
    this.keyIndexes = builder.keyIndexes;
    this.dfStatus = builder.dfStatus;
    this.sharedReference = builder.sharedReference;
  }

  /**
   * (package-private)<br>
   * CalypsoSamCardSelectorBuilder pattern
   *
   * @since 2.0
   */
  static final class FileHeaderBuilder {

    private short lid;
    private int recordsNumber;
    private int recordSize;
    private ElementaryFile.Type type;
    private byte[] accessConditions;
    private byte[] keyIndexes;
    private byte dfStatus;
    private Short sharedReference;

    /** Private constructor */
    private FileHeaderBuilder() {}

    /**
     * (package-private)<br>
     * Sets the LID.
     *
     * @param lid the LID.
     * @return The builder instance
     * @since 2.0
     */
    FileHeaderBuilder lid(short lid) {
      this.lid = lid;
      return this;
    }

    /**
     * (package-private)<br>
     * Sets the number of records.
     *
     * @param recordsNumber the number of records (should be {@code >=} 1).
     * @return The builder instance
     * @since 2.0
     */
    FileHeaderBuilder recordsNumber(int recordsNumber) {
      this.recordsNumber = recordsNumber;
      return this;
    }

    /**
     * (package-private)<br>
     * Sets the size of a record.
     *
     * @param recordSize the size of a record (should be {@code >=} 1).
     * @return The builder instance
     * @since 2.0
     */
    FileHeaderBuilder recordSize(int recordSize) {
      this.recordSize = recordSize;
      return this;
    }

    /**
     * (package-private)<br>
     * Sets the file type.
     *
     * @param type the file type (should be not null).
     * @return The builder instance
     * @since 2.0
     */
    FileHeaderBuilder type(ElementaryFile.Type type) {
      this.type = type;
      return this;
    }

    /**
     * (package-private)<br>
     * Sets a reference to the provided access conditions byte array.
     *
     * @param accessConditions the access conditions (should be not null and 4 bytes length).
     * @return The builder instance
     * @since 2.0
     */
    FileHeaderBuilder accessConditions(byte[] accessConditions) {
      this.accessConditions = accessConditions;
      return this;
    }

    /**
     * (package-private)<br>
     * Sets a reference to the provided key indexes byte array.
     *
     * @param keyIndexes the key indexes (should be not null and 4 bytes length).
     * @return The builder instance
     * @since 2.0
     */
    FileHeaderBuilder keyIndexes(byte[] keyIndexes) {
      this.keyIndexes = keyIndexes;
      return this;
    }

    /**
     * (package-private)<br>
     * Sets the DF status.
     *
     * @param dfStatus the DF status (byte).
     * @return The builder instance
     * @since 2.0
     */
    FileHeaderBuilder dfStatus(byte dfStatus) {
      this.dfStatus = dfStatus;
      return this;
    }

    /**
     * (package-private)<br>
     * Sets the shared reference.
     *
     * @param sharedReference the shared reference.
     * @return The builder instance
     * @since 2.0
     */
    FileHeaderBuilder sharedReference(short sharedReference) {
      this.sharedReference = sharedReference;
      return this;
    }

    /**
     * (package-private)<br>
     * Build a new {@code FileHeader}.
     *
     * @return A new instance
     * @since 2.0
     */
    FileHeader build() {
      return new FileHeaderAdapter(this);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public short getLid() {
    return lid;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getRecordsNumber() {
    return recordsNumber;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public int getRecordSize() {
    return recordSize;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public ElementaryFile.Type getEfType() {
    return type;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getAccessConditions() {
    return accessConditions;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getKeyIndexes() {
    return keyIndexes;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte getDfStatus() {
    return dfStatus;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public Short getSharedReference() {
    return sharedReference;
  }

  /**
   * (package-private)<br>
   * Gets a new builder.
   *
   * @return A new builder instance
   * @since 2.0
   */
  static FileHeaderBuilder builder() {
    return new FileHeaderBuilder();
  }

  /**
   * (package-private)<br>
   * Constructor used to create a clone of the provided file header.
   *
   * @param source the header to be cloned.
   * @since 2.0
   */
  FileHeaderAdapter(FileHeader source) {
    this.lid = source.getLid();
    this.recordsNumber = source.getRecordsNumber();
    this.recordSize = source.getRecordSize();
    this.type = source.getEfType();
    this.accessConditions =
        Arrays.copyOf(source.getAccessConditions(), source.getAccessConditions().length);
    this.keyIndexes = Arrays.copyOf(source.getKeyIndexes(), source.getKeyIndexes().length);
    this.dfStatus = source.getDfStatus();
    this.sharedReference = source.getSharedReference();
  }

  /**
   * Comparison is based on field "lid".
   *
   * @param o the object to compare.
   * @return The comparison evaluation
   * @since 2.0
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    FileHeaderAdapter that = (FileHeaderAdapter) o;

    return lid == that.lid;
  }

  /**
   * Comparison is based on field "lid".
   *
   * @return The hashcode
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
