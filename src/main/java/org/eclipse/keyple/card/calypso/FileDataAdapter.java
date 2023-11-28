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

import java.util.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.card.card.FileData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link FileData}.
 *
 * @since 2.0.0
 */
class FileDataAdapter implements FileData {

  private static final Logger logger = LoggerFactory.getLogger(FileDataAdapter.class);

  private final TreeMap<Integer, byte[]> records = new TreeMap<Integer, byte[]>();

  /**
   * Constructor
   *
   * @since 2.0.0
   */
  FileDataAdapter() {}

  /**
   * Constructor used to create a clone of the provided file file data.
   *
   * @param source the header to be cloned.
   * @since 2.0.0
   */
  FileDataAdapter(FileData source) {
    SortedMap<Integer, byte[]> sourceContent = source.getAllRecordsContent();
    for (Map.Entry<Integer, byte[]> entry : sourceContent.entrySet()) {
      records.put(entry.getKey(), Arrays.copyOf(entry.getValue(), entry.getValue().length));
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public SortedMap<Integer, byte[]> getAllRecordsContent() {
    return records;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] getContent() {
    return getContent(1);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] getContent(int numRecord) {
    byte[] content = records.get(numRecord);
    if (content == null) {
      logger.warn("Record #{} is not set.", numRecord);
      content = new byte[0];
    }
    return content;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] getContent(int numRecord, int dataOffset, int dataLength) {

    Assert.getInstance()
        .greaterOrEqual(dataOffset, 0, "dataOffset")
        .greaterOrEqual(dataLength, 1, "dataLength");

    byte[] content = records.get(numRecord);
    if (content == null) {
      logger.warn("Record #{} is not set.", numRecord);
      return new byte[0];
    }
    if (dataOffset >= content.length) {
      throw new IndexOutOfBoundsException(
          "Offset [" + dataOffset + "] >= content length [" + content.length + "].");
    }
    int toIndex = dataOffset + dataLength;
    if (toIndex > content.length) {
      throw new IndexOutOfBoundsException(
          "Offset ["
              + dataOffset
              + "] + Length ["
              + dataLength
              + "] = ["
              + toIndex
              + "] > content length ["
              + content.length
              + "].");
    }
    return Arrays.copyOfRange(content, dataOffset, toIndex);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public Integer getContentAsCounterValue(int numCounter) {

    Assert.getInstance().greaterOrEqual(numCounter, 1, "numCounter");

    byte[] rec1 = records.get(1);
    if (rec1 == null) {
      logger.warn("Record #1 is not set.");
      return null;
    }
    int counterIndex = (numCounter - 1) * 3;
    if (counterIndex >= rec1.length) {
      logger.warn(
          "Counter #{} is not set (nb of actual counters = {}).", numCounter, rec1.length / 3);
      return null;
    }
    if (counterIndex + 3 > rec1.length) {
      throw new IndexOutOfBoundsException(
          "Counter #"
              + numCounter
              + " has a truncated value (nb of actual counters = "
              + (rec1.length / 3)
              + ").");
    }
    return ByteArrayUtil.extractInt(rec1, counterIndex, 3, false);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public SortedMap<Integer, Integer> getAllCountersValue() {
    SortedMap<Integer, Integer> result = new TreeMap<Integer, Integer>();
    byte[] rec1 = records.get(1);
    if (rec1 == null) {
      logger.warn("Record #1 is not set.");
      return result;
    }
    int length = rec1.length - (rec1.length % 3);
    for (int i = 0, c = 1; i < length; i += 3, c++) {
      result.put(c, ByteArrayUtil.extractInt(rec1, i, 3, false));
    }
    return result;
  }

  /**
   * Sets or replaces the entire content of the specified record #numRecord by the provided content.
   *
   * @param numRecord the record number (should be {@code >=} 1).
   * @param content the content (should be not empty).
   * @since 2.0.0
   */
  void setContent(int numRecord, byte[] content) {
    records.put(numRecord, content);
  }

  /**
   * Sets a counter value in record #1.
   *
   * @param numCounter the counter number (should be {@code >=} 1).
   * @param content the counter value (should be not null and 3 bytes length).
   * @since 2.0.0
   */
  void setCounter(int numCounter, byte[] content) {
    setContent(1, content, (numCounter - 1) * 3);
  }

  /**
   * Sets or replaces the content at the specified offset of record #numRecord by a copy of the
   * provided content.<br>
   * If actual record content is not set or has a size {@code <} offset, then missing data will be
   * padded with 0.
   *
   * @param numRecord the record number (should be {@code >=} 1).
   * @param content the content (should be not empty).
   * @param offset the offset (should be {@code >=} 0).
   * @since 2.0.0
   */
  void setContent(int numRecord, byte[] content, int offset) {
    byte[] newContent;
    int newLength = offset + content.length;
    byte[] oldContent = records.get(numRecord);
    if (oldContent == null) {
      newContent = new byte[newLength];
    } else if (oldContent.length <= offset) {
      newContent = new byte[newLength];
      System.arraycopy(oldContent, 0, newContent, 0, oldContent.length);
    } else if (oldContent.length < newLength) {
      newContent = new byte[newLength];
      System.arraycopy(oldContent, 0, newContent, 0, offset);
    } else {
      newContent = oldContent;
    }
    System.arraycopy(content, 0, newContent, offset, content.length);
    records.put(numRecord, newContent);
  }

  /**
   * Fills the content at the specified offset of the specified record using a binary OR operation
   * with the provided content.<br>
   * If actual record content is not set or has a size {@code <} offset + content size, then missing
   * data will be completed by the provided content.
   *
   * @param numRecord the record number (should be {@code >=} 1).
   * @param content the content (should be not empty).
   * @param offset the offset (should be {@code >=} 0).
   * @since 2.0.0
   */
  void fillContent(int numRecord, byte[] content, int offset) {
    byte[] contentLeftPadded = content;
    if (offset != 0) {
      contentLeftPadded = new byte[offset + content.length];
      System.arraycopy(content, 0, contentLeftPadded, offset, content.length);
    }
    byte[] actualContent = records.get(numRecord);
    if (actualContent == null) {
      records.put(numRecord, contentLeftPadded);
    } else if (actualContent.length < contentLeftPadded.length) {
      for (int i = 0; i < actualContent.length; i++) {
        contentLeftPadded[i] |= actualContent[i];
      }
      records.put(numRecord, contentLeftPadded);
    } else {
      for (int i = 0; i < contentLeftPadded.length; i++) {
        actualContent[i] |= contentLeftPadded[i];
      }
    }
  }

  /**
   * Adds cyclic content at record #1 by rolling previously all actual records contents (record #1
   * -> record #2, record #2 -> record #3,...).<br>
   * This is useful for cyclic files.<br>
   * Note that records are infinitely shifted.
   *
   * @param content the content (should be not empty).
   * @since 2.0.0
   */
  void addCyclicContent(byte[] content) {
    ArrayList<Integer> descendingKeys = new ArrayList<Integer>(records.descendingKeySet());
    for (Integer i : descendingKeys) {
      records.put(i + 1, records.get(i));
    }
    records.put(1, content);
  }

  /**
   * Gets the object content as a Json string.
   *
   * @return A not empty string.
   * @since 2.0.0
   */
  @Override
  public String toString() {
    return JsonUtil.toJson(this);
  }
}
