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
import org.calypsonet.terminal.calypso.transaction.SamTransactionManager;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.eclipse.keyple.core.util.Assert;
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
  private final SamControlSamTransactionManagerAdapter controlSamTransactionManager;

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
          new SamControlSamTransactionManagerAdapter(
              sam, securitySetting, getTransactionAuditData());
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

  /**
   * (private)<br>
   * Overlapping interval test
   *
   * @param startA beginning of the A interval.
   * @param endA end of the A interval.
   * @param startB beginning of the B interval.
   * @param endB end of the B interval.
   * @return true if the intervals A and B overlap.
   */
  private boolean areIntervalsOverlapping(int startA, int endA, int startB, int endB) {
    return startA <= endB && endA >= startB;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  public SamTransactionManager prepareReadEventCounter(int eventCounterNumber) {
    Assert.getInstance()
        .isInRange(
            eventCounterNumber,
            CalypsoSamAdapter.MIN_EVENT_COUNTER_NUMBER,
            CalypsoSamAdapter.MAX_EVENT_COUNTER_NUMBER,
            "eventCounterNumber");
    getSamCommands()
        .add(
            new CmdSamReadEventCounter(
                getCalypsoSam().getProductType(),
                CmdSamReadEventCounter.CounterOperationType.READ_SINGLE_COUNTER,
                eventCounterNumber));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  public SamTransactionManager prepareReadEventCounters(
      int fromEventCounterNumber, int toEventCounterNumber) {
    Assert.getInstance()
        .isInRange(
            fromEventCounterNumber,
            CalypsoSamAdapter.MIN_EVENT_COUNTER_NUMBER,
            CalypsoSamAdapter.MAX_EVENT_COUNTER_NUMBER,
            "fromEventCounterNumber");
    Assert.getInstance()
        .isInRange(
            toEventCounterNumber,
            CalypsoSamAdapter.MIN_EVENT_COUNTER_NUMBER,
            CalypsoSamAdapter.MAX_EVENT_COUNTER_NUMBER,
            "toEventCounterNumber");
    Assert.getInstance()
        .greaterOrEqual(
            toEventCounterNumber,
            fromEventCounterNumber,
            "fromEventCounterNumber/toEventCounterNumber");
    if (areIntervalsOverlapping(0, 8, fromEventCounterNumber, toEventCounterNumber)) {
      getSamCommands()
          .add(
              new CmdSamReadEventCounter(
                  getCalypsoSam().getProductType(),
                  CmdSamReadEventCounter.CounterOperationType.READ_COUNTER_RECORD,
                  1));
    }
    if (areIntervalsOverlapping(9, 17, fromEventCounterNumber, toEventCounterNumber)) {
      getSamCommands()
          .add(
              new CmdSamReadEventCounter(
                  getCalypsoSam().getProductType(),
                  CmdSamReadEventCounter.CounterOperationType.READ_COUNTER_RECORD,
                  2));
    }
    if (areIntervalsOverlapping(18, 26, fromEventCounterNumber, toEventCounterNumber)) {
      getSamCommands()
          .add(
              new CmdSamReadEventCounter(
                  getCalypsoSam().getProductType(),
                  CmdSamReadEventCounter.CounterOperationType.READ_COUNTER_RECORD,
                  3));
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  public SamTransactionManager prepareReadEventCeiling(int eventCeilingNumber) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  public SamTransactionManager prepareReadEventCeilings(
      int fromEventCeilingNumber, int toEventCeilingNumber) {
    Assert.getInstance()
        .isInRange(
            fromEventCeilingNumber,
            CalypsoSamAdapter.MIN_EVENT_CEILING_NUMBER,
            CalypsoSamAdapter.MAX_EVENT_CEILING_NUMBER,
            "fromEventCeilingNumber");
    Assert.getInstance()
        .isInRange(
            toEventCeilingNumber,
            CalypsoSamAdapter.MIN_EVENT_CEILING_NUMBER,
            CalypsoSamAdapter.MAX_EVENT_CEILING_NUMBER,
            "toEventCeilingNumber");
    Assert.getInstance()
        .greaterOrEqual(
            toEventCeilingNumber,
            fromEventCeilingNumber,
            "fromEventCeilingNumber/toEventCeilingNumber");
    if (areIntervalsOverlapping(0, 8, fromEventCeilingNumber, toEventCeilingNumber)) {
      getSamCommands()
          .add(
              new CmdSamReadCeilings(
                  getCalypsoSam().getProductType(),
                  CmdSamReadCeilings.CeilingsOperationType.READ_CEILING_RECORD,
                  1));
    }
    if (areIntervalsOverlapping(9, 17, fromEventCeilingNumber, toEventCeilingNumber)) {
      getSamCommands()
          .add(
              new CmdSamReadCeilings(
                  getCalypsoSam().getProductType(),
                  CmdSamReadCeilings.CeilingsOperationType.READ_CEILING_RECORD,
                  2));
    }
    if (areIntervalsOverlapping(18, 26, fromEventCeilingNumber, toEventCeilingNumber)) {
      getSamCommands()
          .add(
              new CmdSamReadCeilings(
                  getCalypsoSam().getProductType(),
                  CmdSamReadCeilings.CeilingsOperationType.READ_CEILING_RECORD,
                  3));
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  public SamTransactionManager prepareWriteEventCeiling(int eventCeilingNumber, int newValue) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  public SamTransactionManager prepareWriteEventCeilings(
      int fromEventCeilingNumber, List<Integer> newValues) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.2.3
   */
  @Override
  public SamTransactionManager processCommands() {
    return super.processCommands();
  }
}
