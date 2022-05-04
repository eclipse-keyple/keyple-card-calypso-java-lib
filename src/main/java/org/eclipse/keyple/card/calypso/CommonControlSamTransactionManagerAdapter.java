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
import org.calypsonet.terminal.reader.selection.spi.SmartCard;

/**
 * (package-private)<br>
 * Common Control SAM Transaction Manager.
 *
 * @since 2.2.0
 */
abstract class CommonControlSamTransactionManagerAdapter
    extends CommonSamTransactionManagerAdapter {

  /**
   * (package-private)<br>
   * Creates a new instance (to be used for instantiation of {@link
   * CommonControlSamTransactionManagerAdapter} only).
   *
   * @param targetSmartCard The target smartcard provided by the selection process.
   * @param securitySetting The card or SAM security settings.
   * @param defaultKeyDiversifier The full serial number of the target card or SAM to be used by
   *     default when diversifying keys.
   * @param transactionAuditData The original transaction data to fill.
   * @since 2.2.0
   */
  CommonControlSamTransactionManagerAdapter(
      SmartCard targetSmartCard,
      CommonSecuritySettingAdapter<?> securitySetting,
      byte[] defaultKeyDiversifier,
      List<byte[]> transactionAuditData) {
    super(targetSmartCard, securitySetting, defaultKeyDiversifier, transactionAuditData);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public final SamSecuritySetting getSecuritySetting() {
    return null; // No security settings for a control SAM.
  }
}
