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

import java.util.HashSet;
import java.util.Set;
import org.calypsonet.terminal.card.spi.ApduRequestSpi;
import org.eclipse.keyple.core.util.json.JsonUtil;

/**
 * (package-private)<br>
 * This POJO contains a set of data related to an ISO-7816 APDU command.
 *
 * <ul>
 *   <li>A byte array containing the raw APDU data.
 *   <li>A flag indicating if the APDU is of type 4 (ingoing and outgoing data).
 *   <li>An optional set of integers corresponding to valid status words in response to this APDU.
 * </ul>
 *
 * Attaching an optional name to the request facilitates the enhancement of the application logs
 * using the toString method.
 *
 * @since 2.0
 */
final class ApduRequestAdapter implements ApduRequestSpi {

  private static final int DEFAULT_SUCCESSFUL_CODE = 0x9000;

  private final byte[] bytes;
  private final Set<Integer> successfulStatusWords;
  private String name;

  /**
   * Builds an APDU request from a raw byte buffer.
   *
   * <p>The default status words list is initialized with the standard successful code 9000h.
   *
   * @param bytes The bytes of the APDU's body.
   * @since 2.0
   */
  public ApduRequestAdapter(byte[] bytes) {
    this.bytes = bytes;
    this.successfulStatusWords = new HashSet<Integer>();
    this.successfulStatusWords.add(DEFAULT_SUCCESSFUL_CODE);
  }

  /**
   * Adds a status word to the list of those that should be considered successful for the APDU.
   *
   * <p>Note: initially, the list contains the standard successful status word {@code 9000h}.
   *
   * @param successfulStatusWord A positive int &le; {@code FFFFh}.
   * @return the object instance.
   * @since 2.0
   */
  public ApduRequestAdapter addSuccessfulStatusWord(int successfulStatusWord) {
    this.successfulStatusWords.add(successfulStatusWord);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public Set<Integer> getSuccessfulStatusWords() {
    return successfulStatusWords;
  }

  /**
   * Names the APDU request.
   *
   * <p>This string is dedicated to improve the readability of logs and should therefore only be
   * invoked conditionally (e.g. when log level &gt;= debug).
   *
   * @param name The request name (free text).
   * @return The object instance.
   * @since 2.0
   */
  public ApduRequestAdapter setName(final String name) {
    this.name = name;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public String getName() {
    return name;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public byte[] getBytes() {
    return this.bytes;
  }

  /**
   * Converts the APDU request into a string where the data is encoded in a json format.
   *
   * @return A not empty String
   * @since 2.0
   */
  @Override
  public String toString() {
    return "APDU_REQUEST = " + JsonUtil.toJson(this);
  }
}
