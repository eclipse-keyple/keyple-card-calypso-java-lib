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
package org.eclipse.keyple.calypso.sam;

import org.eclipse.keyple.core.service.Reader;

/**
 * Contains a {@link SamSmartCard} and its associated {@link Reader}.
 *
 * @since 2.0
 */
public interface SamResource {

  /**
   * Gets the reader
   *
   * @return the current {@link Reader} for this card
   * @since 2.0
   */
  Reader getReader();

  /**
   * Gets the {@link SamSmartCard}.
   *
   * @return A not null reference.
   * @since 2.0
   */
  SamSmartCard getSmartCard();
}
