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

import java.util.List;
import org.eclipse.keyple.calypso.sam.SamResource;
import org.eclipse.keyple.calypso.sam.SamResourceService;
import org.eclipse.keyple.calypso.sam.SamResourceServiceConfigurator;

/**
 * (package-private)<br>
 * Implementation of {@link SamResourceService}.
 *
 * @since 2.0
 */
class SamResourceServiceAdapter implements SamResourceService {

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamResourceServiceConfigurator getConfigurator() {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public void start() {}

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public void stop() {}

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public List<SamResource> getSamResources(String samProfileName) {
    return null;
  }
}
