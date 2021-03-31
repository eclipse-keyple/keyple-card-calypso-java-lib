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
package org.eclipse.keyple.calypso;

import org.eclipse.keyple.calypso.sam.SamResource;
import org.eclipse.keyple.calypso.sam.SamSmartCard;
import org.eclipse.keyple.core.service.Reader;

class SamResourceAdapter implements SamResource {
  private final Reader reader;
  private final SamSmartCard smartCard;

  public SamResourceAdapter(Reader reader, SamSmartCard smartCard) {
    this.reader = reader;
    this.smartCard = smartCard;
  }

  @Override
  public Reader getReader() {
    return this.reader;
  }

  @Override
  public SamSmartCard getSmartCard() {
    return this.smartCard;
  }
}
