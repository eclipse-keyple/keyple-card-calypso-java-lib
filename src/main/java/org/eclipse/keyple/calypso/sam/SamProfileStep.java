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
 * Step to configure the SAM manager with SAM profiles.
 *
 * @since 2.0
 */
public interface SamProfileStep {

  /**
   * Adds a SAM profile with the provided name.
   *
   * @param name A string.
   * @return next configuration step
   * @throws IllegalArgumentException If the name is null or empty.
   * @throws IllegalStateException If the name is already in use.
   * @since 2.0
   */
  SamProfileParameterStep addSamProfile(String name);

  /**
   * Terminates the addition of SAM profiles.
   *
   * @return next configuration step
   * @since 2.0
   */
  ConfigurationStep addNoMoreSamProfiles();
}
