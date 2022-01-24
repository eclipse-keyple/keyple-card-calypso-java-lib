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

import java.util.ArrayList;
import java.util.List;
import org.calypsonet.terminal.calypso.transaction.SearchCommandData;

/**
 * (package-private)<br>
 * Implementation of {@link SearchCommandData}.
 *
 * @since 2.1.0
 */
final class SearchCommandDataAdapter implements SearchCommandData {

  private byte sfi = 1;
  private int recordNumber = 1;
  private int offset;
  private boolean enableRepeatedOffset;
  private byte[] searchData;
  private byte[] mask;
  private boolean fetchFirstMatchingResult;
  private final List<Integer> matchingRecordNumbers = new ArrayList<Integer>(1);

  /**
   * (package-private)<br>
   * Constructor.
   *
   * @since 2.1.0
   */
  SearchCommandDataAdapter() {}

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public SearchCommandData setSfi(byte sfi) {
    this.sfi = sfi;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public SearchCommandData startAtRecord(int recordNumber) {
    this.recordNumber = recordNumber;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public SearchCommandData setOffset(int offset) {
    this.offset = offset;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public SearchCommandData enableRepeatedOffset() {
    this.enableRepeatedOffset = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public SearchCommandData setSearchData(byte[] data) {
    this.searchData = data;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public SearchCommandData setMask(byte[] mask) {
    this.mask = mask;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public SearchCommandData fetchFirstMatchingResult() {
    this.fetchFirstMatchingResult = true;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.1.0
   */
  @Override
  public List<Integer> getMatchingRecordNumbers() {
    return matchingRecordNumbers;
  }

  /**
   * (package-private)<br>
   *
   * @return The provided SFI or 0 if it is not set.
   * @since 2.1.0
   */
  byte getSfi() {
    return sfi;
  }

  /**
   * (package-private)<br>
   *
   * @return The provided record number or 1 if it is not set.
   * @since 2.1.0
   */
  int getRecordNumber() {
    return recordNumber;
  }

  /**
   * (package-private)<br>
   *
   * @return The provided offset or 0 if it is not set.
   * @since 2.1.0
   */
  int getOffset() {
    return offset;
  }

  /**
   * (package-private)<br>
   *
   * @return True if repeated offset is enabled.
   * @since 2.1.0
   */
  boolean isEnableRepeatedOffset() {
    return enableRepeatedOffset;
  }

  /**
   * (package-private)<br>
   *
   * @return A not empty array of search data. It is required to check input data first using {@link
   *     #checkInputData()} method.
   * @since 2.1.0
   */
  byte[] getSearchData() {
    return searchData;
  }

  /**
   * (package-private)<br>
   *
   * @return Null if the mask is not set.
   * @since 2.1.0
   */
  byte[] getMask() {
    return mask;
  }

  /**
   * (package-private)<br>
   *
   * @return True if first matching result needs to be fetched.
   * @since 2.1.0
   */
  boolean isFetchFirstMatchingResult() {
    return fetchFirstMatchingResult;
  }
}
