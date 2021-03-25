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

import org.eclipse.keyple.core.service.PoolPlugin;

/**
 * Step to add pool plugins to the SAM manager.
 *
 * @since 2.0
 */
public interface PoolPluginStep {

  /**
   * Adds a {@link PoolPlugin} with or without observation.
   *
   * @param poolPlugin The pool plugin to add.
   * @param withReaderObservation true if the readers have to be observed, false if not.
   * @throws IllegalArgumentException if the provided pool plugin is null.
   * @throws IllegalStateException If the observation is required and the readers are not
   *     observable.
   * @return next configuration step
   * @since 2.0
   */
  PoolPluginStep addPoolPlugin(PoolPlugin poolPlugin, boolean withReaderObservation);

  /**
   * Terminates the addition of pool plugins.
   *
   * @return next configuration step
   * @since 2.0
   */
  SamResourceManagerConfigurator addNoMorePoolPlugins();
}
