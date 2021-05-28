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

import org.calypsonet.terminal.card.ApduResponseApi;
import org.eclipse.keyple.card.calypso.sam.SamRevision;

/**
 * (package-private)<br>
 * Superclass for all SAM command builders.
 *
 * @since 2.0
 */
abstract class AbstractSamCommandBuilder<T extends AbstractSamResponseParser>
    extends AbstractApduCommandBuilder {

  protected SamRevision defaultRevision = SamRevision.C1;

  protected AbstractSamCommandBuilder(CalypsoSamCommand reference) {
    super(reference);
  }

  /**
   * Create the response parser matching the builder
   *
   * @param apduResponse the response data from the the card.
   * @return an {@link AbstractApduResponseParser}
   */
  public abstract T createResponseParser(ApduResponseApi apduResponse);

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public CalypsoSamCommand getCommandRef() {
    return (CalypsoSamCommand) commandRef;
  }
}
