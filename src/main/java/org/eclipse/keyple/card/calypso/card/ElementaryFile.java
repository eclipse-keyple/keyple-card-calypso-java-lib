/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.card.calypso.card;

/**
 * This POJO contains the description of a Calypso EF.
 *
 * @since 2.0
 */
public interface ElementaryFile {
  /**
   * Gets the associated SFI.
   *
   * @return The SFI
   * @since 2.0
   */
  byte getSfi();

  /**
   * Gets the file header.
   *
   * @return A header reference or null if header is not yet set.
   * @since 2.0
   */
  FileHeader getHeader();

  /**
   * Gets the file data.
   *
   * @return A not null data reference.
   * @since 2.0
   */
  FileData getData();
}
