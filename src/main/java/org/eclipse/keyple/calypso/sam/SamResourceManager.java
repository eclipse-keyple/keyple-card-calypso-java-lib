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

import java.util.List;

/**
 * Singleton managing SAM resources that are accessed by plugins and readers.
 *
 * @since 2.0
 */
public interface SamResourceManager {

  /**
   * Gets the configuration tool to setup the manager.
   *
   * @return A not null reference.
   * @since 2.0
   */
  SamResourceManagerConfigurator getConfigurator();

  /**
   * Gets the current SAM resources available for the provided profile name.
   *
   * @param samProfileName A String.
   * @return An empty list if no SAM resource is available.
   * @since 2.0
   */
  List<SamResource> getSamResources(String samProfileName);
}
