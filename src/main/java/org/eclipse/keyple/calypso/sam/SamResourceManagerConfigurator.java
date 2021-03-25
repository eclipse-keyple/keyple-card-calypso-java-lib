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

/**
 * Step to configure the SAM manager with plugins.
 *
 * @since 2.0
 */
public interface SamResourceManagerConfigurator {

  /**
   * Configures the SAM resource manager with one or more {@link
   * org.eclipse.keyple.core.service.Plugin}.
   *
   * @return next configuration step
   * @since 2.0
   */
  SamResourceAllocationStrategyStep withPlugins();

  /**
   * Configures the SAM resource manager with one or more {@link
   * org.eclipse.keyple.core.service.PoolPlugin}.
   *
   * @return next configuration step
   * @since 2.0
   */
  PoolPluginSamResourceAllocationStrategyStep withPoolPlugins();

  /**
   * Terminates the plugins configuration step.
   *
   * @return next configuration step
   * @since 2.0
   */
  SamResourceAllocationTimeoutStep endPluginsConfiguration();
}
