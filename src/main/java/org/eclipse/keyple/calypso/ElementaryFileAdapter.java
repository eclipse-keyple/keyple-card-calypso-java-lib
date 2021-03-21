/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://www.calypsonet-asso.org/
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
 * (package-private)<br>
 * Implementation of {@link ElementaryFile}.
 *
 * @since 2.0
 */
class ElementaryFileAdapter implements Serializable, ElementaryFile {

  private final byte sfi;
  private FileHeader header;
  private final FileDataAdapter data;

  /**
   * (package-private)<br>
   * Constructor
   *
   * @param sfi the associated SFI.
   * @since 2.0
   */
  ElementaryFileAdapter(byte sfi) {
    this.sfi = sfi;
    this.data = new FileDataAdapter();
  }

  /**
   * (package-private)<br>
   * Constructor used to create a clone of the provided EF.
   *
   * @param source the EF to be cloned.
   * @since 2.0
   */
  ElementaryFileAdapter(ElementaryFile source) {
    this.sfi = source.getSfi();
    if (source.getHeader() != null) {
      this.header = new FileHeaderAdapter(source.getHeader());
    }
    this.data = new FileDataAdapter(source.getData());
  }

  /**
   * (package-private)<br>
   * Sets the file header.
   *
   * @param header the file header (should be not null).
   * @return the current instance.
   * @since 2.0
   */
  ElementaryFile setHeader(FileHeader header) {
    this.header = header;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte getSfi() {
    return sfi;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public FileHeader getHeader() {
    return header;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public FileData getData() {
    return data;
  }

  /**
   * Comparison is based on field "sfi".
   *
   * @param o the object to compare.
   * @return the comparison evaluation
   * @since 2.0
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    ElementaryFileAdapter that = (ElementaryFileAdapter) o;

    return sfi == that.sfi;
  }

  /**
   * Comparison is based on field "sfi".
   *
   * @return the hashcode
   * @since 2.0
   */
  @Override
  public int hashCode() {
    return sfi;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("ElementaryFile{");
    sb.append("sfi=").append(sfi);
    sb.append(", header=").append(header);
    sb.append(", data=").append(data);
    sb.append('}');
    return sb.toString();
  }
}
