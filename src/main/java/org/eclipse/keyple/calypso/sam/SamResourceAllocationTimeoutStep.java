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
 * Step to configure the SAM manager with allocation timeouts.
 *
 * @since 2.0
 */
public interface SamResourceAllocationTimeoutStep {

  /**
   * Configures the SAM resource manager with the default timeouts used during the allocation
   * process.
   *
   * @return next configuration step
   * @see #usingAllocationTimeout(int, int)
   * @since 2.0
   */
  SamProfileStep usingDefaultAllocationTimeout();

  /**
   * Configures the SAM resource manager with the provided timeouts used during the allocation
   * process.
   *
   * <p>The cycle duration is the time between two attempts find a available SAM.
   *
   * <p>The timeout is the maximum amount of time the allocation method will attempt to find an
   * available SAM.
   *
   * @param cycleDurationInMillis A positive int.
   * @param timeoutInMillis A positive int.
   * @return next configuration step
   * @since 2.0
   */
  SamProfileStep usingAllocationTimeout(int cycleDurationInMillis, int timeoutInMillis);
}
