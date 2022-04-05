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
import org.calypsonet.terminal.calypso.transaction.SamSecuritySetting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Control SAM Transaction Manager.
 *
 * @since 2.2.0
 */
final class ControlSamTransactionManagerAdapter extends CommonSamTransactionManagerAdapter {

  private static final Logger logger =
      LoggerFactory.getLogger(ControlSamTransactionManagerAdapter.class);

  private final CalypsoCardAdapter targetCard;
  private final CardSecuritySettingAdapter cardSecuritySetting;

  private final CalypsoSamAdapter targetSam;
  private final SamSecuritySettingAdapter samSecuritySetting;

  /**
   * (package-private)<br>
   * Creates a new instance to control a card.
   *
   * @param targetCard The target card to control provided by the selection process.
   * @param securitySetting The associated card security settings.
   * @param defaultKeyDiversifier The full serial number of the target card to be used by default
   *     when diversifying keys.
   * @param transactionAuditData The original transaction data to fill.
   * @since 2.2.0
   */
  ControlSamTransactionManagerAdapter(
      CalypsoCardAdapter targetCard,
      CardSecuritySettingAdapter securitySetting,
      byte[] defaultKeyDiversifier,
      List<byte[]> transactionAuditData) {
    super(targetCard, securitySetting, defaultKeyDiversifier, transactionAuditData);
    this.targetCard = targetCard;
    this.cardSecuritySetting = securitySetting;
    this.targetSam = null;
    this.samSecuritySetting = null;
  }

  /**
   * (package-private)<br>
   * Creates a new instance to control a SAM.
   *
   * @param targetSam The target SAM to control provided by the selection process.
   * @param securitySetting The associated SAM security settings.
   * @param defaultKeyDiversifier The full serial number of the target SAM to be used by default
   *     when diversifying keys.
   * @param transactionAuditData The original transaction data to fill.
   * @since 2.2.0
   */
  ControlSamTransactionManagerAdapter(
      CalypsoSamAdapter targetSam,
      SamSecuritySettingAdapter securitySetting,
      byte[] defaultKeyDiversifier,
      List<byte[]> transactionAuditData) {
    super(targetSam, securitySetting, defaultKeyDiversifier, transactionAuditData);
    this.targetCard = null;
    this.cardSecuritySetting = null;
    this.targetSam = targetSam;
    this.samSecuritySetting = securitySetting;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SamSecuritySetting getSecuritySetting() {
    return null; // No security settings for a control SAM.
  }
}
