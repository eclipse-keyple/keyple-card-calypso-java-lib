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

import java.util.NoSuchElementException;
import org.eclipse.keyple.card.calypso.transaction.CardTransactionService;

/**
 * This POJO contains all metadata of a Calypso DF.
 *
 * @since 2.0
 */
public interface DirectoryHeader {
  /**
   * Gets the associated LID.
   *
   * @return The LID
   * @since 2.0
   */
  short getLid();

  /**
   * Gets a reference to access conditions.
   *
   * @return A not empty byte array
   * @since 2.0
   */
  byte[] getAccessConditions();

  /**
   * Gets a reference to keys indexes.
   *
   * @return A not empty byte array
   * @since 2.0
   */
  byte[] getKeyIndexes();

  /**
   * Gets the DF status.
   *
   * @return The DF status byte
   * @since 2.0
   */
  byte getDfStatus();

  /**
   * Returns true if the KIF for the provided level is available.
   *
   * @param level the session access level (should be not null).
   * @return True if the KIF for the provided level is available
   * @since 2.0
   */
  boolean isKifAvailable(CardTransactionService.SessionAccessLevel level);

  /**
   * Returns true if the KVC for the provided level is available.
   *
   * @param level the session access level (should be not null).
   * @return True if the KVC for the provided level is available
   * @since 2.0
   */
  boolean isKvcAvailable(CardTransactionService.SessionAccessLevel level);

  /**
   * Gets the KIF associated to the provided session access level.
   *
   * @param level the session access level (should be not null).
   * @return A not null value
   * @throws IllegalArgumentException if level is null.
   * @throws NoSuchElementException if KIF is not found.
   * @since 2.0
   */
  byte getKif(CardTransactionService.SessionAccessLevel level);

  /**
   * Gets the KVC associated to the provided session access level.
   *
   * @param level the session access level (should be not null).
   * @return A not null value
   * @throws IllegalArgumentException if level is null.
   * @throws NoSuchElementException if KVC is not found.
   * @since 2.0
   */
  byte getKvc(CardTransactionService.SessionAccessLevel level);
}
