/* **************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.card.calypso;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Control SAM Transaction Manager.
 *
 * @since 2.2.0
 */
final class SamControlSamTransactionManagerAdapter
    extends CommonControlSamTransactionManagerAdapter {

  private static final Logger logger =
      LoggerFactory.getLogger(SamControlSamTransactionManagerAdapter.class);

  private final CalypsoSamAdapter controlSam;
  private final CalypsoSamAdapter targetSam;
  private final SamSecuritySettingAdapter samSecuritySetting;

  /**
   * (package-private)<br>
   * Creates a new instance to control a SAM.
   *
   * @param targetSam The target SAM to control provided by the selection process.
   * @param securitySetting The associated SAM security settings.
   * @param transactionAuditData The original transaction data to fill.
   * @since 2.2.0
   */
  SamControlSamTransactionManagerAdapter(
      CalypsoSamAdapter targetSam,
      SamSecuritySettingAdapter securitySetting,
      List<byte[]> transactionAuditData) {
    super(targetSam, securitySetting, targetSam.getSerialNumber(), transactionAuditData);
    this.controlSam = securitySetting.getControlSam();
    this.targetSam = targetSam;
    this.samSecuritySetting = securitySetting;
  }
}
