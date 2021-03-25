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

import org.eclipse.keyple.core.service.Plugin;

/**
 * Step to add pool plugins to the SAM manager.
 *
 * @since 2.0
 */
public interface PluginStep {

  /**
   * Adds a {@link Plugin} with or without plugin and reader observation.
   *
   * @param plugin The plugin to add.
   * @param withPluginObservation true if the plugin has to be observed, false if not.
   * @param withReaderObservation true if the readers have to be observed, false if not.
   * @return next configuration step
   * @throws IllegalArgumentException if the provided plugin is null.
   * @throws IllegalStateException If the observation is required and the plugin or the readers are
   *     not observable.
   * @since 2.0
   */
  PluginStep addPlugin(Plugin plugin, boolean withPluginObservation, boolean withReaderObservation);

  /**
   * Terminates the addition of pool plugins.
   *
   * @return next configuration step
   * @since 2.0
   */
  SamResourceManagerConfigurator addNoMorePlugins();
}
