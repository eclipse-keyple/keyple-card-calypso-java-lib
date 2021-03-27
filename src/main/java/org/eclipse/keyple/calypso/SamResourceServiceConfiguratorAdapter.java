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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.eclipse.keyple.calypso.sam.SamResourceServiceConfigurator;
import org.eclipse.keyple.calypso.sam.SamRevision;
import org.eclipse.keyple.core.service.ObservablePlugin;
import org.eclipse.keyple.core.service.Plugin;
import org.eclipse.keyple.core.service.PoolPlugin;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;

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

  private SamAllocationStrategy samAllocationStrategy;
  private PoolPluginAllocationStrategy poolPluginAllocationStrategy;
  private final List<ConfiguredRegularPlugin> configuredRegularPlugins;
  private final List<ConfiguredPoolPlugin> configuredPoolPlugins;
  private final List<SamProfile> samProfiles;
  private int cycleDurationMillis;
  private int timeoutMillis;
  private SamProfile samProfile;

  /** (private) */
  private SamResourceServiceConfiguratorAdapter() {
    samAllocationStrategy = SamAllocationStrategy.FIRST_SAM_AVAILABLE;
    poolPluginAllocationStrategy = PoolPluginAllocationStrategy.POOL_FIRST;
    configuredRegularPlugins = new ArrayList<ConfiguredRegularPlugin>();
    configuredPoolPlugins = new ArrayList<ConfiguredPoolPlugin>();
    samProfiles = new ArrayList<SamProfile>();
    cycleDurationMillis = DEFAULT_CYCLE_DURATION_MILLIS;
    timeoutMillis = DEFAULT_TIMEOUT_MILLIS;
  }

  /** The different allocation strategies for regular plugins. */
  private enum SamAllocationStrategy {
    FIRST_SAM_AVAILABLE,
    CYCLIC,
    RANDOM
  }

  /** The different allocation strategies when a {@link PoolPlugin } is available. */
  private enum PoolPluginAllocationStrategy {
    POOL_FIRST,
    POOL_LAST
  }

  /**
   * (private)<br>
   * This POJO contains a plugin and the parameters that have been associated with it.
   */
  private class ConfiguredRegularPlugin {
    private final Plugin plugin;
    private final boolean withReaderMonitoring;
    private final boolean withCardMonitoring;
    private final SamAllocationStrategy samAllocationStrategy;

    ConfiguredRegularPlugin(
        Plugin plugin,
        boolean withReaderMonitoring,
        boolean withCardMonitoring,
        SamAllocationStrategy samAllocationStrategy) {
      this.plugin = plugin;
      this.withReaderMonitoring = withReaderMonitoring;
      this.withCardMonitoring = withCardMonitoring;
      this.samAllocationStrategy = samAllocationStrategy;
    }

    public Plugin getPlugin() {
      return plugin;
    }

    public boolean isWithReaderMonitoring() {
      return withReaderMonitoring;
    }

    public boolean isWithCardMonitoring() {
      return withCardMonitoring;
    }

    public SamAllocationStrategy getSamAllocationStrategy() {
      return samAllocationStrategy;
    }
  }

  /**
   * (private)<br>
   * This POJO contains a pool plugin and the parameters that have been associated with it.
   */
  private class ConfiguredPoolPlugin {
    private final PoolPlugin poolPlugin;
    private final boolean withCardMonitoring;
    private final PoolPluginAllocationStrategy poolPluginAllocationStrategy;

    public ConfiguredPoolPlugin(
        PoolPlugin poolPlugin,
        boolean withCardMonitoring,
        PoolPluginAllocationStrategy poolPluginAllocationStrategy) {
      this.poolPlugin = poolPlugin;
      this.withCardMonitoring = withCardMonitoring;
      this.poolPluginAllocationStrategy = poolPluginAllocationStrategy;
    }

    public PoolPlugin getPoolPlugin() {
      return poolPlugin;
    }

    public boolean isWithCardMonitoring() {
      return withCardMonitoring;
    }

    public PoolPluginAllocationStrategy getPoolPluginAllocationStrategy() {
      return poolPluginAllocationStrategy;
    }
  }

  /**
   * (private)<br>
   * This POJO contains all the elements defining a SAM profile.
   */
  private class SamProfile {
    private final String name;
    private SamRevision samRevision;
    private String samSerialNumberRegex;
    private String samKeyGroupReference;
    private List<Plugin> plugins;
    private String readerNameRegex;
    private String unlockData;

    private SamProfile(String name) {
      this.name = name;
    }

    public String getName() {
      return name;
    }

    public SamRevision getSamRevision() {
      return samRevision;
    }

    public void setSamRevision(SamRevision samRevision) {
      this.samRevision = samRevision;
    }

    public String getSamSerialNumberRegex() {
      return samSerialNumberRegex;
    }

    public void setSamSerialNumberRegex(String samSerialNumberRegex) {
      this.samSerialNumberRegex = samSerialNumberRegex;
    }

    public String getSamKeyGroupReference() {
      return samKeyGroupReference;
    }

    public void setSamKeyGroupReference(String samKeyGroupReference) {
      this.samKeyGroupReference = samKeyGroupReference;
    }

    public List<Plugin> getPlugins() {
      return plugins;
    }

    public void setPlugins(Plugin... plugins) {
      this.plugins = Arrays.asList(plugins);
    }

    public String getReaderNameRegex() {
      return readerNameRegex;
    }

    public void setReaderNameRegex(String readerNameRegex) {
      this.readerNameRegex = readerNameRegex;
    }

    public String getUnlockData() {
      return unlockData;
    }

    public void setUnlockData(String unlockData) {
      this.unlockData = unlockData;
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
  public PluginStep usingFirstSamAvailableAllocationStrategy() {
    samAllocationStrategy = SamAllocationStrategy.FIRST_SAM_AVAILABLE;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PluginStep usingCyclicAllocationStrategy() {
    samAllocationStrategy = SamAllocationStrategy.CYCLIC;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PluginStep usingRandomAllocationStrategy() {
    samAllocationStrategy = SamAllocationStrategy.RANDOM;
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

    if (withReaderMonitoring && !(plugin instanceof ObservablePlugin)) {
      throw new IllegalStateException(
          "Reader monitoring is requested but the provided plugin is not observable.");
    }

    configuredRegularPlugins.add(
        new ConfiguredRegularPlugin(
            plugin, withReaderMonitoring, withCardMonitoring, samAllocationStrategy));

    samAllocationStrategy = SamAllocationStrategy.FIRST_SAM_AVAILABLE;
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
    poolPluginAllocationStrategy = PoolPluginAllocationStrategy.POOL_FIRST;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0
   */
  @Override
  public PoolPluginStep usingPoolPluginLastAllocationStrategy() {
    poolPluginAllocationStrategy = PoolPluginAllocationStrategy.POOL_LAST;
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

    configuredPoolPlugins.add(
        new ConfiguredPoolPlugin(poolPlugin, withCardMonitoring, poolPluginAllocationStrategy));

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

    if (configuredRegularPlugins.isEmpty() || configuredPoolPlugins.isEmpty()) {
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
  // TODO rename to createSamProfile????
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

    if (samProfile == null) {
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
  public SamProfileParameterStep setSamKeyGroupReference(String samKeyGroupReference) {

    Assert.getInstance().notEmpty(samKeyGroupReference, "samKeyGroupReference");

    if (samProfile.getSamRevision() != null) {
      throw new IllegalStateException("SAM key group reference has already been set.");
    }

    samProfile.setSamKeyGroupReference(samKeyGroupReference);

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
      boolean pluginConfigured = false;
      for (ConfiguredRegularPlugin configuredRegularPlugin : configuredRegularPlugins) {
        if (plugin.equals(configuredRegularPlugin.getPlugin())) {
          pluginConfigured = true;
          break;
        }
      }
      if (pluginConfigured) {
        continue;
      }
      pluginConfigured = false;
      for (ConfiguredPoolPlugin configuredPoolPlugin : configuredPoolPlugins) {
        if (plugin.equals(configuredPoolPlugin.getPoolPlugin())) {
          pluginConfigured = true;
          break;
        }
      }
      if (!pluginConfigured) {
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

    if (ByteArrayUtil.fromHex(unlockData).length == 0) {
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
  public void configure() {}
}
