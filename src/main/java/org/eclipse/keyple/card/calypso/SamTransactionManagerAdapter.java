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

import org.calypsonet.terminal.calypso.transaction.SamSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.SamTransactionManager;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * (package-private)<br>
 * Implementation of {@link SamTransactionManager}.
 *
 * @since 2.2.0
 */
final class SamTransactionManagerAdapter extends CommonSamTransactionManagerAdapter {

  private static final Logger logger = LoggerFactory.getLogger(SamTransactionManagerAdapter.class);

  /* Final fields */
  private final SamSecuritySettingAdapter securitySetting;
  private final ControlSamTransactionManagerAdapter controlSamTransactionManager;

  /**
   * (package-private)<br>
   * Creates a new instance.
   *
   * @param samReader The reader through which the SAM communicates.
   * @param sam The initial SAM data provided by the selection process.
   * @param securitySetting The security settings (optional).
   * @since 2.2.0
   */
  SamTransactionManagerAdapter(
      ProxyReaderApi samReader, CalypsoSamAdapter sam, SamSecuritySettingAdapter securitySetting) {
    super(samReader, sam, securitySetting);
    this.securitySetting = securitySetting;
    if (securitySetting != null && securitySetting.getControlSam() != null) {
      this.controlSamTransactionManager =
          new ControlSamTransactionManagerAdapter(
              sam, securitySetting, sam.getSerialNumber(), getTransactionAuditData());
    } else {
      this.controlSamTransactionManager = null;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.0
   */
  @Override
  public SamSecuritySetting getSecuritySetting() {
    return securitySetting;
  }
}
