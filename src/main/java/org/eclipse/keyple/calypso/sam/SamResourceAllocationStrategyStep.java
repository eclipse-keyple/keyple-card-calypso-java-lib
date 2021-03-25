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
 * Step to configure the SAM manager allocation strategy.
 *
 * @since 2.0
 */
public interface SamResourceAllocationStrategyStep {

  /**
   * Configures the SAM resource manager to provide the first available SAM when a SAM allocation is
   * made.
   *
   * @return next configuration step
   * @since 2.0
   */
  PluginStep usingFirstSamAvailableAllocationStrategy();

  /**
   * Configures the SAM resource manager to provide available SAMs on a cyclical basis to avoid
   * always providing the same SAM.
   *
   * @return next configuration step
   * @since 2.0
   */
  PluginStep usingCyclicAllocationStrategy();

  /**
   * Configures the SAM resource manager to provide available SAMs randomly to avoid always
   * providing the same SAM.
   *
   * @return next configuration step
   * @since 2.0
   */
  PluginStep usingRandomAllocationStrategy();
}
