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
 * Step to configure the SAM manager pool and regular plugin priority strategy.
 *
 * @since 2.0
 */
public interface PoolPluginSamResourceAllocationStrategyStep {

  /**
   * Configures the SAM resource manager to search for available SAMs in pool plugins before regular
   * plugins.
   *
   * @return next configuration step
   * @since 2.0
   */
  PoolPluginStep usingPoolPluginFirstAllocationStrategy();

  /**
   * Configures the SAM resource manager to search for available SAMs in regular plugins before pool
   * plugins.
   *
   * @return next configuration step
   * @since 2.0
   */
  PoolPluginStep usingPoolPluginLastAllocationStrategy();
}
