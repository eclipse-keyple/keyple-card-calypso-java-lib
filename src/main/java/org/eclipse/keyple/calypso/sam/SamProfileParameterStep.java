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
 * Step to configure a SAM profile with parameters.
 *
 * @since 2.0
 */
public interface SamProfileParameterStep {

  /**
   * Sets the targeted SAM revision.
   *
   * @param samRevision The SAM revision.
   * @return next configuration step
   * @throws IllegalArgumentException If samRevision is null.
   * @since 2.0
   */
  SamProfileParameterStep setSamRevisionFilter(SamRevision samRevision);

  /**
   * Sets a regex based SAM serial number filter.
   *
   * @param samSerialNumber A string.
   * @return next configuration step
   * @throws IllegalArgumentException If samSerialNumber is null or empty.
   * @since 2.0
   */
  SamProfileParameterStep setSamSerialNumberFilter(String samSerialNumber);

  /**
   * Sets the targeted key group reference.
   *
   * @param samKeyGroupReference A string.
   * @return next configuration step
   * @throws IllegalArgumentException If samKeyGroupReference is null or empty.
   * @since 2.0
   */
  SamProfileParameterStep setSamKeyGroupReferenceFilter(String samKeyGroupReference);

  /**
   * Adds the name of a targeted plugin.
   *
   * @param pluginName string.
   * @return next configuration step
   * @throws IllegalArgumentException If pluginName is null or empty.
   * @throws IllegalStateException If the plugin name is unknown.
   * @since 2.0
   */
  SamProfileParameterStep addPluginNameFilter(String pluginName);

  /**
   * Adds the name of a targeted reader.
   *
   * <p>The provided string can be a substring of the real name of the targeted reader.
   *
   * @param readerName string.
   * @return next configuration step
   * @throws IllegalArgumentException If pluginName is null or empty.
   * @since 2.0
   */
  SamProfileParameterStep addReaderNameFilter(String readerName);

  /**
   * Sets the lock value expected by the SAM to be unlocked.
   *
   * @param hexData An hexadecimal representation of the lock value.
   * @return next configuration step
   * @throws IllegalArgumentException If hexData is null or malformed.
   * @since 2.0
   */
  SamProfileParameterStep setUnlockData(String hexData);

  /**
   * Terminates the addition of parameters.
   *
   * @return next configuration step
   * @since 2.0
   */
  SamProfileStep addNoMoreParameters();
}
