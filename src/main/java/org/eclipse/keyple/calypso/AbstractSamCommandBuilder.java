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
package org.eclipse.keyple.calypso;

import org.eclipse.keyple.calypso.sam.SamRevision;
import org.eclipse.keyple.core.card.ApduResponse;

/**
 * Superclass for all SAM command builders.
 *
 * @since 2.0
 */
abstract class AbstractSamCommandBuilder<T extends AbstractSamResponseParser>
    extends AbstractApduCommandBuilder {

  protected SamRevision defaultRevision = SamRevision.C1;

  protected AbstractSamCommandBuilder(SamCommand reference) {
    super(reference);
  }

  /**
   * Create the response parser matching the builder
   *
   * @param apduResponse the response data from the the card.
   * @return an {@link AbstractApduResponseParser}
   */
  public abstract T createResponseParser(ApduResponse apduResponse);

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamCommand getCommandRef() {
    return (SamCommand) commandRef;
  }
}
