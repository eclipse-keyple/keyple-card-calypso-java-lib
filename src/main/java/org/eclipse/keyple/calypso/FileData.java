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
import java.util.*;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * This POJO contains all known data content of a Calypso EF.
 *
 * @since 2.0
 */
public class FileData implements Serializable {

  private final TreeMap<Integer, byte[]> records = new TreeMap<Integer, byte[]>();

  /**
   * (package-private)<br>
   * Constructor
   *
   * @since 2.0
   */
  FileData() {}

  /**
   * (package-private)<br>
   * Constructor used to create a clone of the provided file file data.
   *
   * @param source the header to be cloned.
   * @since 2.0
   */
  FileData(FileData source) {
    SortedMap<Integer, byte[]> sourceContent = source.getAllRecordsContent();
    for (Map.Entry<Integer, byte[]> entry : sourceContent.entrySet()) {
      records.put(entry.getKey(), Arrays.copyOf(entry.getValue(), entry.getValue().length));
    }
  }

  /**
   * Gets a reference to all known records content.
   *
   * @return a not null map eventually empty if there's no content.
   * @since 2.0
   */
  public SortedMap<Integer, byte[]> getAllRecordsContent() {
    return records;
  }

  /**
   * Gets a reference to the known content of record #1.<br>
   * For a Binary file, it means all the bytes of the file.
   *
   * @return a not empty reference to the record content.
   * @throws NoSuchElementException if record #1 is not set.
   * @since 2.0
   */
  public byte[] getContent() {
    return getContent(1);
  }

  /**
   * Gets a reference to the known content of a specific record.
   *
   * @param numRecord the record number.
   * @return a not empty reference to the record content.
   * @throws NoSuchElementException if record #numRecord is not set.
   * @since 2.0
   */
  public byte[] getContent(int numRecord) {
    byte[] content = records.get(numRecord);
    if (content == null) {
      throw new NoSuchElementException("Record #" + numRecord + " is not set.");
    }
    return content;
  }

  /**
   * Gets a copy of a known content subset of a specific record from dataOffset to dataLength.
   *
   * @param numRecord the record number.
   * @param dataOffset the offset index (should be {@code >=} 0).
   * @param dataLength the data length (should be {@code >=} 1).
   * @return a copy not empty of the record subset content.
   * @throws IllegalArgumentException if dataOffset {@code <} 0 or dataLength {@code <} 1.
   * @throws NoSuchElementException if record #numRecord is not set.
   * @throws IndexOutOfBoundsException if dataOffset {@code >=} content length or (dataOffset +
   *     dataLength) {@code >} content length.
   * @since 2.0
   */
  public byte[] getContent(int numRecord, int dataOffset, int dataLength) {

    Assert.getInstance()
        .greaterOrEqual(dataOffset, 0, "dataOffset")
        .greaterOrEqual(dataLength, 1, "dataLength");

    byte[] content = records.get(numRecord);
    if (content == null) {
      throw new NoSuchElementException("Record #" + numRecord + " is not set.");
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
   * Gets the known value of the counter #numCounter.<br>
   * The counter value is extracted from the 3 next bytes at the index [(numCounter - 1) * 3] of the
   * record #1.<br>
   * e.g. if numCounter == 2, then value is extracted from bytes indexes [3,4,5].
   *
   * @param numCounter the counter number (should be {@code >=} 1).
   * @return the counter value.
   * @throws IllegalArgumentException if numCounter is {@code <} 1.
   * @throws NoSuchElementException if record #1 or numCounter is not set.
   * @throws IndexOutOfBoundsException if numCounter has a truncated value (when size of record #1
   *     modulo 3 != 0).
   * @since 2.0
   */
  public int getContentAsCounterValue(int numCounter) {

    Assert.getInstance().greaterOrEqual(numCounter, 1, "numCounter");

    byte[] rec1 = records.get(1);
    if (rec1 == null) {
      throw new NoSuchElementException("Record #1 is not set.");
    }
    int counterIndex = (numCounter - 1) * 3;
    if (counterIndex >= rec1.length) {
      throw new NoSuchElementException(
          "Counter #"
              + numCounter
              + " is not set (nb of actual counters = "
              + (rec1.length / 3)
              + ").");
    }
    if (counterIndex + 3 > rec1.length) {
      throw new IndexOutOfBoundsException(
          "Counter #"
              + numCounter
              + " has a truncated value (nb of actual counters = "
              + (rec1.length / 3)
              + ").");
    }
    return ByteArrayUtil.threeBytesToInt(rec1, counterIndex);
  }

  /**
   * Gets all known counters value.<br>
   * The counters values are extracted from record #1.<br>
   * If last counter has a truncated value (when size of record #1 modulo 3 != 0), then last counter
   * value is not returned.
   *
   * @return a not empty object.
   * @throws NoSuchElementException if record #1 is not set.
   * @since 2.0
   */
  public SortedMap<Integer, Integer> getAllCountersValue() {
    SortedMap<Integer, Integer> result = new TreeMap<Integer, Integer>();
    byte[] rec1 = records.get(1);
    if (rec1 == null) {
      throw new NoSuchElementException("Record #1 is not set.");
    }
    int length = rec1.length - (rec1.length % 3);
    for (int i = 0, c = 1; i < length; i += 3, c++) {
      result.put(c, ByteArrayUtil.threeBytesToInt(rec1, i));
    }
    return result;
  }

  /**
   * (package-private)<br>
   * Set or replace the entire content of the specified record #numRecord by the provided content.
   *
   * @param numRecord the record number (should be {@code >=} 1).
   * @param content the content (should be not empty).
   * @since 2.0
   */
  void setContent(int numRecord, byte[] content) {
    records.put(numRecord, content);
  }

  /**
   * (package-private)<br>
   * Sets a counter value in record #1.
   *
   * @param numCounter the counter number (should be {@code >=} 1).
   * @param content the counter value (should be not null and 3 bytes length).
   * @since 2.0
   */
  void setCounter(int numCounter, byte[] content) {
    setContent(1, content, (numCounter - 1) * 3);
  }

  /**
   * (package-private)<br>
   * Set or replace the content at the specified offset of record #numRecord by a copy of the
   * provided content.<br>
   * If actual record content is not set or has a size {@code <} offset, then missing data will be
   * padded with 0.
   *
   * @param numRecord the record number (should be {@code >=} 1).
   * @param content the content (should be not empty).
   * @param offset the offset (should be {@code >=} 0).
   * @since 2.0
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
   * (package-private)<br>
   * Fill the content of the specified #numRecord using a binary OR operation with the provided
   * content.<br>
   * If actual record content is not set or has a size {@code <} content size, then missing data
   * will be completed by the provided content.
   *
   * @param numRecord the record number (should be {@code >=} 1).
   * @param content the content (should be not empty).
   * @since 2.0
   */
  void fillContent(int numRecord, byte[] content) {
    byte[] actualContent = records.get(numRecord);
    if (actualContent == null) {
      records.put(numRecord, content);
    } else if (actualContent.length < content.length) {
      for (int i = 0; i < actualContent.length; i++) {
        content[i] |= actualContent[i];
      }
      records.put(numRecord, content);
    } else {
      for (int i = 0; i < content.length; i++) {
        actualContent[i] |= content[i];
      }
    }
  }

  /**
   * (package-private)<br>
   * Add cyclic content at record #1 by rolling previously all actual records contents (record #1 ->
   * record #2, record #2 -> record #3,...).<br>
   * This is useful for cyclic files.<br>
   * Note that records are infinitely shifted.
   *
   * @param content the content (should be not empty).
   * @since 2.0
   */
  void addCyclicContent(byte[] content) {
    ArrayList<Integer> descendingKeys = new ArrayList<Integer>(records.descendingKeySet());
    for (Integer i : descendingKeys) {
      records.put(i + 1, records.get(i));
    }
    records.put(1, content);
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("FileData{");
    sb.append("records={");
    for (Map.Entry<Integer, byte[]> rec : records.entrySet()) {
      sb.append("(");
      sb.append(rec.getKey());
      sb.append("=0x");
      sb.append(ByteArrayUtil.toHex(rec.getValue()));
      sb.append(")");
    }
    sb.append("}}");
    return sb.toString();
  }
}
