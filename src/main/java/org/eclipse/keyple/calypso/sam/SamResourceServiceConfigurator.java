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
import org.eclipse.keyple.core.service.PoolPlugin;

/**
 * Configurator of the SAM resource service.
 *
 * <p>The configuration consists in a sequence of steps including:
 *
 * <ul>
 *   <li>Assignment of plugins to be used with or without automatic refresh.
 *   <li>Selection of strategies and parameters of SAM allocation.
 *   <li>Creation of SAM profiles.
 * </ul>
 *
 * @since 2.0
 */
public interface SamResourceServiceConfigurator {

  /**
   * Configures the SAM resource service with one or more {@link
   * org.eclipse.keyple.core.service.Plugin} or {@link
   * org.eclipse.keyple.core.service.ObservablePlugin}.
   *
   * @return Next configuration step.
   * @throws IllegalStateException If this step has already been performed.
   * @since 2.0
   */
  SamResourceAllocationStrategyStep withPlugins();

  /**
   * Configures the SAM resource service with one or more {@link
   * org.eclipse.keyple.core.service.PoolPlugin}.
   *
   * @return Next configuration step.
   * @throws IllegalStateException If this step has already been performed.
   * @since 2.0
   */
  PoolPluginSamResourceAllocationStrategyStep withPoolPlugins();

  /**
   * Terminates the plugins configuration step.
   *
   * @return Next configuration step.
   * @throws IllegalStateException If no plugin has been added.
   * @since 2.0
   */
  SamResourceAllocationTimingParameterStep endPluginsConfiguration();

  /**
   * Step to add pool plugins to the SAM resource service.
   *
   * @since 2.0
   */
  interface PluginStep {

    /**
     * Adds a {@link Plugin} or {@link org.eclipse.keyple.core.service.ObservablePlugin} to the
     * default list of all SAM profiles.
     *
     * <p><u>Note:</u> The order of the plugins is important because it will be kept during the
     * allocation process unless redefined by SAM profiles.
     *
     * @param plugin The plugin to add.
     * @param withReaderMonitoring true if the plugin must be observed to automatically detect
     *     reader connections/disconnections, false otherwise.
     * @param withCardMonitoring true if the readers must be observed to automatically detect card
     *     insertions/removals, false otherwise.
     * @return Next configuration step.
     * @throws IllegalArgumentException If the provided plugin is null.
     * @throws IllegalStateException If the observation is required and the plugin or the readers
     *     are not observable.
     * @since 2.0
     */
    PluginStep addPlugin(Plugin plugin, boolean withReaderMonitoring, boolean withCardMonitoring);

    /**
     * Terminates the addition of plugins.
     *
     * @return Next configuration step.
     * @throws IllegalStateException If no plugin has been added.
     * @since 2.0
     */
    SamResourceServiceConfigurator addNoMorePlugins();
  }

  /**
   * Step to add pool plugins to the SAM resource service.
   *
   * @since 2.0
   */
  interface PoolPluginStep {

    /**
     * Adds a {@link PoolPlugin} to the default list of all SAM profiles.
     *
     * <p><u>Note:</u> The order of the plugins is importan because it will be kept during the
     * allocation process unless redefined by SAM profiles.
     *
     * @param poolPlugin The pool plugin to add.
     * @param withCardMonitoring true if the readers must be observed to automatically detect card
     *     insertions/removals, false otherwise.
     * @throws IllegalArgumentException If the provided pool plugin is null.
     * @throws IllegalStateException If the observation is required and the readers are not
     *     observable.
     * @return Next configuration step.
     * @since 2.0
     */
    PoolPluginStep addPoolPlugin(PoolPlugin poolPlugin, boolean withCardMonitoring);

    /**
     * Terminates the addition of pool plugins.
     *
     * @return Next configuration step.
     * @throws IllegalStateException If no pool plugin has been added.
     * @since 2.0
     */
    SamResourceServiceConfigurator addNoMorePoolPlugins();
  }

  /**
   * Step to configure the SAM resource service with allocation timeouts.
   *
   * @since 2.0
   */
  interface SamResourceAllocationTimingParameterStep {

    /**
     * Configures the SAM resource service with the default timing parameters used during the
     * allocation process.
     *
     * @return Next configuration step.
     * @see #usingAllocationTimingParameters(int, int)
     * @since 2.0
     */
    SamProfileStep usingDefaultAllocationTimingParameters();

    /**
     * Configures the SAM resource service with the provided timing parameters used during the
     * allocation process.
     *
     * <p>The cycle duration is the time between two attempts to find an available SAM.
     *
     * <p>The timeout is the maximum amount of time the allocation method will attempt to find an
     * available SAM.
     *
     * @param cycleDurationMillis A positive int.
     * @param timeoutMillis A positive int.
     * @return Next configuration step.
     * @since 2.0
     */
    SamProfileStep usingAllocationTimingParameters(int cycleDurationMillis, int timeoutMillis);
  }

  /**
   * Step to configure the SAM resource service pool and regular plugins priority strategy.
   *
   * @since 2.0
   */
  interface PoolPluginSamResourceAllocationStrategyStep {

    /**
     * Configures the SAM resource service to search for available SAMs in pool plugins before
     * regular plugins.
     *
     * @return Next configuration step.
     * @since 2.0
     */
    PoolPluginStep usingPoolPluginFirstAllocationStrategy();

    /**
     * Configures the SAM resource service to search for available SAMs in regular plugins before
     * pool plugins.
     *
     * @return Next configuration step.
     * @since 2.0
     */
    PoolPluginStep usingPoolPluginLastAllocationStrategy();
  }

  /**
   * Step to configure the SAM resource service allocation strategy.
   *
   * @since 2.0
   */
  interface SamResourceAllocationStrategyStep {

    /**
     * Configures the SAM resource service to provide the first available SAM when a SAM allocation
     * is made.
     *
     * @return Next configuration step.
     * @since 2.0
     */
    PluginStep usingFirstSamAvailableAllocationStrategy();

    /**
     * Configures the SAM resource service to provide available SAMs on a cyclical basis to avoid
     * always providing the same SAM.
     *
     * @return Next configuration step.
     * @since 2.0
     */
    PluginStep usingCyclicAllocationStrategy();

    /**
     * Configures the SAM resource service to provide available SAMs randomly to avoid always
     * providing the same SAM.
     *
     * @return Next configuration step.
     * @since 2.0
     */
    PluginStep usingRandomAllocationStrategy();
  }

  /**
   * Step to configure the SAM resource service with SAM profiles.
   *
   * @since 2.0
   */
  interface SamProfileStep {

    /**
     * Creates a SAM profile with the provided name.
     *
     * @param name The SAM profile name.
     * @return Next configuration step.
     * @throws IllegalArgumentException If the name is null or empty.
     * @throws IllegalStateException If the name is already in use.
     * @since 2.0
     */
    SamProfileParameterStep addSamProfile(String name);

    /**
     * Terminates the creation of SAM profiles.
     *
     * @return Next configuration step.
     * @throws IllegalStateException If no SAM profile has been added.
     * @since 2.0
     */
    ConfigurationStep addNoMoreSamProfiles();
  }

  /**
   * Step to configure a SAM profile with parameters.
   *
   * @since 2.0
   */
  interface SamProfileParameterStep {

    /**
     * Sets a filter to target all SAM having the provided specific {@link SamRevision}.
     *
     * <p>This parameter only applies to a regular plugin.
     *
     * @param samRevision The SAM revision.
     * @return Next configuration step.
     * @throws IllegalArgumentException If samRevision is null.
     * @throws IllegalStateException If this parameter has already been set.
     * @since 2.0
     */
    SamProfileParameterStep setSamRevision(SamRevision samRevision);

    /**
     * Sets a filter targeting all SAMs having a serial number matching the provided regular
     * expression.
     *
     * <p>This parameter only applies to a regular plugin.
     *
     * <p>If set, only SAM resources having a SAM with a serial number matching the provided filter
     * will be allocated.<br>
     * The filter is regular expression that will be applied to the real serial number.
     *
     * <p>The regular expression is based on an hexadecimal representation of the serial number.
     *
     * <p>Example:
     *
     * <ul>
     *   <li>A filter targeting all SAMs having an 8-byte serial number starting with A0h would be
     *       "^A0.{6}$".
     *   <li>A filter targeting having the exact serial number 12345678h would be "12345678".
     * </ul>
     *
     * @param samSerialNumberRegex A regular expression.
     * @return Next configuration step.
     * @throws IllegalArgumentException If samSerialNumberRegex is null, empty or invalid.
     * @throws IllegalStateException If this parameter has already been set.
     * @since 2.0
     */
    SamProfileParameterStep setSamSerialNumberRegex(String samSerialNumberRegex);

    /**
     * Sets a filter to target all SAM having the provided specific key group reference.
     *
     * <p>This parameter only applies to a pool plugin.
     *
     * @param samKeyGroupReference A key group reference.
     * @return Next configuration step.
     * @throws IllegalArgumentException If samKeyGroupReference is null or empty.
     * @throws IllegalStateException If this parameter has already been set.
     * @since 2.0
     */
    SamProfileParameterStep setSamKeyGroupReference(String samKeyGroupReference);

    /**
     * Restricts the scope of the search during the allocation process to the provided plugins.
     *
     * <p>If this method is not invoked, all configured plugins will be used as search domain during
     * the allocation process.
     *
     * <p><u>Note:</u> The order of the plugins is important because it will be kept during the
     * allocation process.
     *
     * @param plugins An ordered list of plugins.
     * @return Next configuration step.
     * @throws IllegalArgumentException If one or more plugin are null or empty.
     * @throws IllegalStateException If one or more plugins are not previously configured.
     * @since 2.0
     */
    SamProfileParameterStep setPlugins(Plugin... plugins);

    /**
     * Sets a filter targeting all SAM readers having a name matching the provided regular
     * expression.
     *
     * @param readerNameRegex A regular expression.
     * @return Next configuration step.
     * @throws IllegalArgumentException If the readerNameRegex is null, empty or invalid.
     * @since 2.0
     */
    SamProfileParameterStep setReaderNameRegex(String readerNameRegex);

    /**
     * Sets the lock value expected by the SAM to be unlocked.
     *
     * <p>This parameter only applies to a regular plugin.
     *
     * @param unlockData An hexadecimal representation of the unlock value.
     * @return Next configuration step.
     * @throws IllegalArgumentException If unlockData is null or malformed.
     * @throws IllegalStateException If this parameter has already been set.
     * @since 2.0
     */
    SamProfileParameterStep setUnlockData(String unlockData);

    /**
     * Terminates the addition of parameters.
     *
     * @return Next configuration step.
     * @since 2.0
     */
    SamProfileStep addNoMoreParameters();
  }

  /**
   * Last step to configure the SAM resource service.
   *
   * @since 2.0
   */
  interface ConfigurationStep {

    /**
     * Finalizes the configuration of the SAM resource service.
     *
     * <p>If the service is already started, the new configuration is applied immediately. <br>
     * Any previous configuration will be overwritten.
     *
     * @since 2.0
     * @throws IllegalStateException If .
     */
    void configure();
  }
}
