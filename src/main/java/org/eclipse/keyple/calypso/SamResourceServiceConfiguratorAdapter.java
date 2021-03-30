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

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.eclipse.keyple.calypso.sam.SamResourceServiceConfigurator;
import org.eclipse.keyple.calypso.sam.SamRevision;
import org.eclipse.keyple.core.service.Plugin;
import org.eclipse.keyple.core.service.PoolPlugin;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;

/**
 * (package-private)<br>
 * Implementation of {@link SamResourceServiceConfigurator}.
 *
 * @since 2.0
 */
class SamResourceServiceConfiguratorAdapter
    implements SamResourceServiceConfigurator,
        SamResourceServiceConfigurator.PluginStep,
        SamResourceServiceConfigurator.PoolPluginStep,
        SamResourceServiceConfigurator.SamResourceAllocationTimingParameterStep,
        SamResourceServiceConfigurator.PoolPluginSamResourceAllocationStrategyStep,
        SamResourceServiceConfigurator.SamResourceAllocationStrategyStep,
        SamResourceServiceConfigurator.SamProfileStep,
        SamResourceServiceConfigurator.SamProfileParameterStep,
        SamResourceServiceConfigurator.ConfigurationStep {

  private static final int DEFAULT_CYCLE_DURATION_MILLIS = 100;
  private static final int DEFAULT_TIMEOUT_MILLIS = 10000;

  private SamResourceAllocationStrategy samResourceAllocationStrategy;
  private PoolPluginSamResourceAllocationStrategy poolPluginSamResourceAllocationStrategy;
  private final Set<Plugin> configuredPlugins;
  private final List<ConfiguredRegularPlugin> configuredRegularPlugins;
  private final List<ConfiguredPoolPlugin> configuredPoolPlugins;
  private final List<SamProfile> samProfiles;
  private int cycleDurationMillis;
  private int timeoutMillis;
  private SamProfile samProfile;

  /** (private) */
  private SamResourceServiceConfiguratorAdapter() {
    samResourceAllocationStrategy = SamResourceAllocationStrategy.FIRST;
    poolPluginSamResourceAllocationStrategy = PoolPluginSamResourceAllocationStrategy.POOL_FIRST;
    configuredPlugins = new HashSet<Plugin>();
    configuredRegularPlugins = new ArrayList<ConfiguredRegularPlugin>();
    configuredPoolPlugins = new ArrayList<ConfiguredPoolPlugin>();
    samProfiles = new ArrayList<SamProfile>();
  }

  /**
   * (package-private)<br>
   * The different allocation strategies for regular plugins.
   *
   * @since 2.0
   */
  enum SamResourceAllocationStrategy {
    FIRST,
    CYCLIC,
    RANDOM
  }

  /**
   * (package-private)<br>
   * The different allocation strategies when a {@link PoolPlugin } is available.
   *
   * @since 2.0
   */
  enum PoolPluginSamResourceAllocationStrategy {
    POOL_FIRST,
    POOL_LAST
  }

  /**
   * (package-private)<br>
   * This POJO contains a plugin and the parameters that have been associated with it.
   *
   * @since 2.0
   */
  static class ConfiguredRegularPlugin {
    private final Plugin plugin;
    private final boolean withReaderMonitoring;
    private final boolean withCardMonitoring;

    private ConfiguredRegularPlugin(
        Plugin plugin, boolean withReaderMonitoring, boolean withCardMonitoring) {
      this.plugin = plugin;
      this.withReaderMonitoring = withReaderMonitoring;
      this.withCardMonitoring = withCardMonitoring;
    }

    /**
     * (package-private)<br>
     *
     * @return A not null {@link Plugin} reference.
     */
    Plugin getPlugin() {
      return plugin;
    }

    /**
     * (package-private)<br>
     *
     * @return true if the reader monitoring is required.
     */
    boolean isWithReaderMonitoring() {
      return withReaderMonitoring;
    }

    /**
     * (package-private)<br>
     *
     * @return true if the card monitoring is required.
     */
    boolean isWithCardMonitoring() {
      return withCardMonitoring;
    }
  }

  /**
   * (package-private)<br>
   * This POJO contains a pool plugin and the parameters that have been associated with it.
   *
   * @since 2.0
   */
  static class ConfiguredPoolPlugin {
    private final PoolPlugin poolPlugin;
    private final boolean withCardMonitoring;

    private ConfiguredPoolPlugin(PoolPlugin poolPlugin, boolean withCardMonitoring) {
      this.poolPlugin = poolPlugin;
      this.withCardMonitoring = withCardMonitoring;
    }

    /**
     * (package-private)<br>
     *
     * @return A not null {@link PoolPlugin} reference.
     */
    PoolPlugin getPoolPlugin() {
      return poolPlugin;
    }

    /**
     * (package-private)<br>
     *
     * @return true if the card monitoring is required.
     */
    boolean isWithCardMonitoring() {
      return withCardMonitoring;
    }
  }

  /**
   * (package-private)<br>
   * This POJO contains all the elements defining a SAM profile.
   *
   * @since 2.0
   */
  static class SamProfile {
    private final String name;
    private SamRevision samRevision;
    private String samSerialNumberRegex;
    private String readerGroupReference;
    private List<Plugin> plugins;
    private String readerNameRegex;
    private String unlockData;

    private SamProfile(String name) {
      this.name = name;
    }

    private void setSamRevision(SamRevision samRevision) {
      this.samRevision = samRevision;
    }

    private void setSamSerialNumberRegex(String samSerialNumberRegex) {
      this.samSerialNumberRegex = samSerialNumberRegex;
    }

    private void setReaderGroupReference(String readerGroupReference) {
      this.readerGroupReference = readerGroupReference;
    }

    private void setPlugins(Plugin... plugins) {
      this.plugins = Arrays.asList(plugins);
    }

    private void setReaderNameRegex(String readerNameRegex) {
      this.readerNameRegex = readerNameRegex;
    }

    private void setUnlockData(String unlockData) {
      this.unlockData = unlockData;
    }

    /**
     * (package-private)<br>
     *
     * @return A not empty String containing the name of the profile.
     */
    String getName() {
      return name;
    }

    /**
     * (package-private)<br>
     *
     * @return The expected {@link SamRevision} or null if not specified.
     */
    SamRevision getSamRevision() {
      return samRevision;
    }

    /**
     * (package-private)<br>
     *
     * @return The expected {@link SamRevision} or null if not specified.
     */
    String getReaderGroupReference() {
      return readerGroupReference;
    }

    String getSamSerialNumberRegex() {
      return samSerialNumberRegex;
    }

    List<Plugin> getPlugins() {
      return plugins;
    }

    String getReaderNameRegex() {
      return readerNameRegex;
    }

    String getUnlockData() {
      return unlockData;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamResourceAllocationStrategyStep withPlugins() {
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PluginStep usingFirstAllocationStrategy() {
    samResourceAllocationStrategy = SamResourceAllocationStrategy.FIRST;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PluginStep usingCyclicAllocationStrategy() {
    samResourceAllocationStrategy = SamResourceAllocationStrategy.CYCLIC;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PluginStep usingRandomAllocationStrategy() {
    samResourceAllocationStrategy = SamResourceAllocationStrategy.RANDOM;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PluginStep addPlugin(
      Plugin plugin, boolean withReaderMonitoring, boolean withCardMonitoring) {

    Assert.getInstance().notNull(plugin, "plugin");

    configuredPlugins.add(plugin);
    configuredRegularPlugins.add(
        new ConfiguredRegularPlugin(plugin, withReaderMonitoring, withCardMonitoring));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamResourceServiceConfigurator addNoMorePlugins() {

    if (configuredRegularPlugins.isEmpty()) {
      throw new IllegalStateException("No plugin has been added.");
    }

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoolPluginSamResourceAllocationStrategyStep withPoolPlugins() {
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoolPluginStep usingPoolPluginFirstAllocationStrategy() {
    poolPluginSamResourceAllocationStrategy = PoolPluginSamResourceAllocationStrategy.POOL_FIRST;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoolPluginStep usingPoolPluginLastAllocationStrategy() {
    poolPluginSamResourceAllocationStrategy = PoolPluginSamResourceAllocationStrategy.POOL_LAST;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoolPluginStep addPoolPlugin(PoolPlugin poolPlugin, boolean withCardMonitoring) {

    Assert.getInstance().notNull(poolPlugin, "poolPlugin");

    configuredPlugins.add(poolPlugin);
    configuredPoolPlugins.add(new ConfiguredPoolPlugin(poolPlugin, withCardMonitoring));

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamResourceServiceConfigurator addNoMorePoolPlugins() {

    if (configuredRegularPlugins.isEmpty()) {
      throw new IllegalStateException("No pool plugin has been added.");
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamResourceAllocationTimingParameterStep endPluginsConfiguration() {

    if (configuredRegularPlugins.isEmpty() && configuredPoolPlugins.isEmpty()) {
      throw new IllegalStateException("No plugin has been added.");
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamProfileStep usingDefaultAllocationTimingParameters() {
    cycleDurationMillis = DEFAULT_CYCLE_DURATION_MILLIS;
    timeoutMillis = DEFAULT_TIMEOUT_MILLIS;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamProfileStep usingAllocationTimingParameters(
      int cycleDurationMillis, int timeoutMillis) {
    this.cycleDurationMillis = cycleDurationMillis;
    this.timeoutMillis = timeoutMillis;
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamProfileParameterStep addSamProfile(String name) {
    samProfile = new SamProfile(name);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public ConfigurationStep addNoMoreSamProfiles() {

    if (samProfiles.isEmpty()) {
      throw new IllegalStateException("No SAM profile has been added.");
    }

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamProfileParameterStep setSamRevision(SamRevision samRevision) {

    Assert.getInstance().notNull(samRevision, "samRevision");

    if (samProfile.getSamRevision() != null) {
      throw new IllegalStateException("SAM revision has already been set.");
    }

    samProfile.setSamRevision(samRevision);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamProfileParameterStep setSamSerialNumberRegex(String samSerialNumberRegex) {

    Assert.getInstance().notEmpty(samSerialNumberRegex, "samSerialNumberRegex");

    if (samProfile.getSamSerialNumberRegex() != null) {
      throw new IllegalStateException("SAM serial number regex has already been set.");
    }

    try {
      Pattern.compile(samSerialNumberRegex);
    } catch (PatternSyntaxException exception) {
      throw new IllegalArgumentException("Invalid regular expression: " + samSerialNumberRegex);
    }

    samProfile.setSamSerialNumberRegex(samSerialNumberRegex);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamProfileParameterStep setReaderGroupReference(String readerGroupReference) {

    Assert.getInstance().notEmpty(readerGroupReference, "readerGroupReference");

    if (samProfile.getReaderGroupReference() != null) {
      throw new IllegalStateException("SAM reader group reference has already been set.");
    }

    samProfile.setReaderGroupReference(readerGroupReference);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamProfileParameterStep setPlugins(Plugin... plugins) {

    // check if all provided plugins are valid and known as configured regular or pool plugins.
    for (Plugin plugin : plugins) {
      Assert.getInstance().notNull(plugin, "plugin");
      if (!configuredPlugins.contains(plugin)) {
        throw new IllegalStateException("Plugin not configured: " + plugin.getName());
      }
    }

    samProfile.setPlugins(plugins);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamProfileParameterStep setReaderNameRegex(String readerNameRegex) {

    Assert.getInstance().notEmpty(readerNameRegex, "readerNameRegex");

    if (samProfile.getReaderNameRegex() != null) {
      throw new IllegalStateException("Reader name regex has already been set.");
    }

    try {
      Pattern.compile(readerNameRegex);
    } catch (PatternSyntaxException exception) {
      throw new IllegalArgumentException("Invalid regular expression: " + readerNameRegex);
    }

    samProfile.setReaderNameRegex(readerNameRegex);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamProfileParameterStep setUnlockData(String unlockData) {

    Assert.getInstance().notEmpty(unlockData, "unlockData");

    if (!ByteArrayUtil.isValidHexString(unlockData)) {
      throw new IllegalArgumentException("Invalid hexadecimal string.");
    }

    samProfile.setUnlockData(unlockData);

    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public SamProfileStep addNoMoreParameters() {

    samProfiles.add(samProfile);

    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public void configure() {
    ((SamResourceServiceAdapter) CalypsoCardExtensionProvider.getService().getSamResourceService())
        .configure(this);
  }

  SamResourceAllocationStrategy getSamResourceAllocationStrategy() {
    return samResourceAllocationStrategy;
  }

  PoolPluginSamResourceAllocationStrategy getPoolPluginAllocationStrategy() {
    return poolPluginSamResourceAllocationStrategy;
  }

  List<ConfiguredRegularPlugin> getConfiguredRegularPlugins() {
    return configuredRegularPlugins;
  }

  List<ConfiguredPoolPlugin> getConfiguredPoolPlugins() {
    return configuredPoolPlugins;
  }

  List<SamProfile> getSamProfiles() {
    return samProfiles;
  }

  int getCycleDurationMillis() {
    return cycleDurationMillis;
  }

  int getTimeoutMillis() {
    return timeoutMillis;
  }
}
