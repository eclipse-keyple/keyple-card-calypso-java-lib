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
 * SAM Resource Management Service.
 *
 * @since 2.0
 */
public interface SamResourceService {

  /**
   * Gets the configuration tool to setup the service.
   *
   * @return A not null reference.
   * @since 2.0
   */
  SamResourceServiceConfigurator getConfigurator();

  /**
   * Starts the service using the current configuration, initializes the list of SAM resources,
   * activates the required monitoring, if any.
   *
   * @throws IllegalStateException If no configuration was done.
   * @since 2.0
   */
  void start();

  /**
   * Stops the service.
   *
   * <p>All monitoring processes are stopped, all SAM resources are released.
   *
   * @since 2.0
   */
  void stop();

  /**
   * Gets the current SAM resources available for the provided profile name.
   *
   * @param samProfileName A String.
   * @return An empty list if no SAM resource is available.
   * @throws IllegalStateException If the service is not started.
   * @since 2.0
   */
  List<SamResource> getSamResources(String samProfileName);
}
