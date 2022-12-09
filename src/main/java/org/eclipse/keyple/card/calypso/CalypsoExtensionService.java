/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;
import static org.eclipse.keyple.card.calypso.JsonAdapters.*;

import org.calypsonet.terminal.calypso.card.CalypsoCard;
import org.calypsonet.terminal.calypso.card.CalypsoCardSelection;
import org.calypsonet.terminal.calypso.card.DirectoryHeader;
import org.calypsonet.terminal.calypso.card.ElementaryFile;
import org.calypsonet.terminal.calypso.card.FileHeader;
import org.calypsonet.terminal.calypso.card.SvDebitLogRecord;
import org.calypsonet.terminal.calypso.card.SvLoadLogRecord;
import org.calypsonet.terminal.calypso.sam.CalypsoSam;
import org.calypsonet.terminal.calypso.sam.CalypsoSamSelection;
import org.calypsonet.terminal.calypso.transaction.BasicSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.BasicSignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.CardSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.CardTransactionManager;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.CommonSignatureVerificationData;
import org.calypsonet.terminal.calypso.transaction.SamSecuritySetting;
import org.calypsonet.terminal.calypso.transaction.SamTransactionManager;
import org.calypsonet.terminal.calypso.transaction.SearchCommandData;
import org.calypsonet.terminal.calypso.transaction.TraceableSignatureComputationData;
import org.calypsonet.terminal.calypso.transaction.TraceableSignatureVerificationData;
import org.calypsonet.terminal.card.CardApiProperties;
import org.calypsonet.terminal.card.ProxyReaderApi;
import org.calypsonet.terminal.reader.CardReader;
import org.calypsonet.terminal.reader.ReaderApiProperties;
import org.eclipse.keyple.core.common.CommonApiProperties;
import org.eclipse.keyple.core.common.KeypleCardExtension;
import org.eclipse.keyple.core.service.resource.spi.CardResourceProfileExtension;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.json.JsonUtil;

/**
 * Card extension dedicated to the management of Calypso cards.
 *
 * @since 2.0.0
 */
public final class CalypsoExtensionService implements KeypleCardExtension {

  /** singleton instance of CalypsoExtensionService */
  private static final CalypsoExtensionService INSTANCE = new CalypsoExtensionService();

  private final ContextSettingAdapter contextSetting;

  static {
    // Register additional JSON adapters.
    JsonUtil.registerTypeAdapter(DirectoryHeader.class, new DirectoryHeaderJsonAdapter(), false);
    JsonUtil.registerTypeAdapter(ElementaryFile.class, new ElementaryFileJsonAdapter(), false);
    JsonUtil.registerTypeAdapter(FileHeader.class, new FileHeaderJsonAdapter(), false);
    JsonUtil.registerTypeAdapter(SvLoadLogRecord.class, new SvLoadLogRecordJsonAdapter(), false);
    JsonUtil.registerTypeAdapter(SvDebitLogRecord.class, new SvDebitLogRecordJsonAdapter(), false);
    JsonUtil.registerTypeAdapter(CardCommand.class, new AbstractCardCommandJsonAdapter(), false);
  }

  /** Private constructor. */
  private CalypsoExtensionService() {
    contextSetting = new ContextSettingAdapter();
  }

  /**
   * Returns the service instance.
   *
   * @return A not null reference.
   * @since 2.0.0
   */
  public static CalypsoExtensionService getInstance() {
    return INSTANCE;
  }

  /**
   * Returns the context setting.
   *
   * @return A not null {@link ContextSetting}.
   * @since 2.3.0
   */
  public ContextSetting getContextSetting() {
    return contextSetting;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getReaderApiVersion() {
    return ReaderApiProperties.VERSION;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getCardApiVersion() {
    return CardApiProperties.VERSION;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getCommonApiVersion() {
    return CommonApiProperties.VERSION;
  }

  /**
   * Returns a new instance of {@link SearchCommandData} to use to define the parameters of the
   * {@link CardTransactionManager#prepareSearchRecords(SearchCommandData)} method.
   *
   * @return A not null reference.
   * @since 2.1.0
   */
  public SearchCommandData createSearchCommandData() {
    return new SearchCommandDataAdapter();
  }

  /**
   * Returns a new instance of {@link BasicSignatureComputationData} to use to define the parameters
   * of the {@link CardTransactionManager#prepareComputeSignature(CommonSignatureComputationData)}
   * and {@link SamTransactionManager#prepareComputeSignature(CommonSignatureComputationData)}
   * methods.
   *
   * @return A not null reference.
   * @since 2.2.0
   */
  public BasicSignatureComputationData createBasicSignatureComputationData() {
    return new BasicSignatureComputationDataAdapter();
  }

  /**
   * Returns a new instance of {@link TraceableSignatureComputationData} to use to define the
   * parameters of the {@link
   * CardTransactionManager#prepareComputeSignature(CommonSignatureComputationData)} and {@link
   * SamTransactionManager#prepareComputeSignature(CommonSignatureComputationData)} methods.
   *
   * @return A not null reference.
   * @since 2.2.0
   */
  public TraceableSignatureComputationData createTraceableSignatureComputationData() {
    return new TraceableSignatureComputationDataAdapter();
  }

  /**
   * Returns a new instance of {@link BasicSignatureVerificationData} to use to define the
   * parameters of the {@link
   * CardTransactionManager#prepareVerifySignature(CommonSignatureVerificationData)} and {@link
   * SamTransactionManager#prepareVerifySignature(CommonSignatureVerificationData)} methods.
   *
   * @return A not null reference.
   * @since 2.2.0
   */
  public BasicSignatureVerificationData createBasicSignatureVerificationData() {
    return new BasicSignatureVerificationDataAdapter();
  }

  /**
   * Returns a new instance of {@link TraceableSignatureVerificationData} to use to define the
   * parameters of the {@link
   * CardTransactionManager#prepareVerifySignature(CommonSignatureVerificationData)} and {@link
   * SamTransactionManager#prepareVerifySignature(CommonSignatureVerificationData)} methods.
   *
   * @return A not null reference.
   * @since 2.2.0
   */
  public TraceableSignatureVerificationData createTraceableSignatureVerificationData() {
    return new TraceableSignatureVerificationDataAdapter();
  }

  /**
   * Returns a new instance of {@link CalypsoCardSelection} to use when selecting a card.
   *
   * @return A not null reference.
   * @since 2.0.0
   */
  public CalypsoCardSelection createCardSelection() {
    return new CalypsoCardSelectionAdapter();
  }

  /**
   * Returns a new instance of {@link CalypsoSamSelection} to use when selecting a SAM.
   *
   * @return A not null reference.
   * @since 2.0.0
   */
  public CalypsoSamSelection createSamSelection() {
    return new CalypsoSamSelectionAdapter();
  }

  /**
   * Returns a new instance of {@link CardResourceProfileExtension} to provide to the {@link
   * org.eclipse.keyple.core.service.resource.CardResourceService} service.
   *
   * <p>The provided argument defines the selection rules to be applied to the SAM when detected by
   * the card resource service.
   *
   * @param calypsoSamSelection A not null {@link
   *     org.calypsonet.terminal.calypso.sam.CalypsoSamSelection}.
   * @return A not null reference.
   * @throws IllegalArgumentException If "calypsoSamSelection" is null.
   * @since 2.0.0
   */
  public CardResourceProfileExtension createSamResourceProfileExtension(
      CalypsoSamSelection calypsoSamSelection) {
    Assert.getInstance().notNull(calypsoSamSelection, "calypsoSamSelection");
    return new CalypsoSamResourceProfileExtensionAdapter(calypsoSamSelection);
  }

  /**
   * Returns a new instance of {@link CardSecuritySetting} to use for secure card operations.
   *
   * @return A not null reference.
   * @since 2.0.0
   */
  public CardSecuritySetting createCardSecuritySetting() {
    return new CardSecuritySettingAdapter();
  }

  /**
   * Return a new card transaction manager to handle operations secured with a control SAM.
   *
   * <p>The reader and the card's initial data are those from the selection.<br>
   * The provided {@link CardSecuritySetting} must match the specific needs of the card (SAM card
   * resource profile and other optional settings).
   *
   * @param cardReader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @param cardSecuritySetting The security settings.
   * @return A not null reference.
   * @throws IllegalArgumentException If one of the provided argument is null or if "calypsoCard"
   *     has a null or unknown product type.
   * @since 2.0.0
   */
  public CardTransactionManager createCardTransaction(
      CardReader cardReader, CalypsoCard calypsoCard, CardSecuritySetting cardSecuritySetting) {
    return createCardTransactionManagerAdapter(cardReader, calypsoCard, cardSecuritySetting, true);
  }

  /**
   * Returns a new card transaction manager to handle non-secured operations.
   *
   * @param cardReader The reader through which the card communicates.
   * @param calypsoCard The initial card data provided by the selection process.
   * @return A not null reference.
   * @throws IllegalArgumentException If one of the provided argument is null or if "calypsoCard"
   *     has a null or unknown product type.
   * @since 2.0.0
   */
  public CardTransactionManager createCardTransactionWithoutSecurity(
      CardReader cardReader, CalypsoCard calypsoCard) {
    return createCardTransactionManagerAdapter(cardReader, calypsoCard, null, false);
  }

  /**
   * Returns a new card transaction manager adapter.
   *
   * @param cardReader The reader.
   * @param calypsoCard The card.
   * @param cardSecuritySetting The security settings.
   * @param isSecureMode True if is secure mode requested.
   * @return A not null reference.
   * @throws IllegalArgumentException If one of the provided argument is null or if "calypsoCard"
   *     has a null or unknown product type.
   */
  private CardTransactionManagerAdapter createCardTransactionManagerAdapter(
      CardReader cardReader,
      CalypsoCard calypsoCard,
      CardSecuritySetting cardSecuritySetting,
      boolean isSecureMode) {

    Assert.getInstance()
        .notNull(cardReader, "card reader")
        .notNull(calypsoCard, "calypso card")
        .notNull(calypsoCard.getProductType(), "product type")
        .isTrue(
            calypsoCard.getProductType() != CalypsoCard.ProductType.UNKNOWN,
            "product type is known")
        .isTrue(!isSecureMode || cardSecuritySetting != null, "security setting is not null");

    if (!(cardReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
          "The provided 'cardReader' must implement 'ProxyReaderApi'");
    }
    if (!(calypsoCard instanceof CalypsoCardAdapter)) {
      throw new IllegalArgumentException(
          "The provided 'calypsoCard' must be an instance of 'CalypsoCardAdapter'");
    }
    if (isSecureMode && !(cardSecuritySetting instanceof CardSecuritySettingAdapter)) {
      throw new IllegalArgumentException(
          "The provided 'cardSecuritySetting' must be an instance of 'CardSecuritySettingAdapter'");
    }

    return new CardTransactionManagerAdapter(
        (ProxyReaderApi) cardReader,
        (CalypsoCardAdapter) calypsoCard,
        (CardSecuritySettingAdapter) cardSecuritySetting,
        contextSetting);
  }

  /**
   * Returns a new instance of {@link SamSecuritySetting} to use for secure SAM operations.
   *
   * @return A not null reference.
   * @since 2.2.0
   */
  public SamSecuritySetting createSamSecuritySetting() {
    return new SamSecuritySettingAdapter();
  }

  /**
   * Returns a new SAM transaction manager to handle operations secured with a control SAM.
   *
   * <p>The reader and the SAM's initial data are those from the selection.<br>
   * The provided {@link SamSecuritySetting} must match the specific needs of the SAM (SAM card
   * resource profile and other optional settings).
   *
   * @param samReader The reader through which the SAM communicates.
   * @param calypsoSam The initial SAM data provided by the selection process.
   * @param samSecuritySetting The security settings.
   * @return A not null reference.
   * @throws IllegalArgumentException If one of the provided argument is null or if "calypsoSam" has
   *     a null or unknown product type.
   * @since 2.2.0
   */
  public SamTransactionManager createSamTransaction(
      CardReader samReader, CalypsoSam calypsoSam, SamSecuritySetting samSecuritySetting) {
    return createSamTransactionManagerAdapter(samReader, calypsoSam, samSecuritySetting, true);
  }

  /**
   * Returns a new SAM transaction manager to handle non-secured operations.
   *
   * @param samReader The reader through which the SAM communicates.
   * @param calypsoSam The initial SAM data provided by the selection process.
   * @return A not null reference.
   * @throws IllegalArgumentException If one of the provided argument is null or if "calypsoSam" has
   *     a null or unknown product type.
   * @since 2.2.0
   */
  public SamTransactionManager createSamTransactionWithoutSecurity(
      CardReader samReader, CalypsoSam calypsoSam) {
    return createSamTransactionManagerAdapter(samReader, calypsoSam, null, false);
  }

  /**
   * Returns a new SAM transaction manager adapter.
   *
   * @param samReader The reader.
   * @param calypsoSam The SAM.
   * @param samSecuritySetting The security settings.
   * @param isSecureMode True if is secure mode requested.
   * @return A not null reference.
   * @throws IllegalArgumentException If one of the provided argument is null or if "calypsoSam" has
   *     a null or unknown product type.
   */
  private SamTransactionManagerAdapter createSamTransactionManagerAdapter(
      CardReader samReader,
      CalypsoSam calypsoSam,
      SamSecuritySetting samSecuritySetting,
      boolean isSecureMode) {

    Assert.getInstance()
        .notNull(samReader, "sam reader")
        .notNull(calypsoSam, "calypso SAM")
        .notNull(calypsoSam.getProductType(), "product type")
        .isTrue(
            calypsoSam.getProductType() != CalypsoSam.ProductType.UNKNOWN, "product type is known")
        .isTrue(!isSecureMode || samSecuritySetting != null, "security setting is not null");

    if (!(samReader instanceof ProxyReaderApi)) {
      throw new IllegalArgumentException(
          "The provided 'samReader' must implement 'ProxyReaderApi'");
    }
    if (!(calypsoSam instanceof CalypsoSamAdapter)) {
      throw new IllegalArgumentException(
          "The provided 'calypsoSam' must be an instance of 'CalypsoSamAdapter'");
    }
    if (isSecureMode && !(samSecuritySetting instanceof SamSecuritySettingAdapter)) {
      throw new IllegalArgumentException(
          "The provided 'samSecuritySetting' must be an instance of 'SamSecuritySettingAdapter'");
    }

    return new SamTransactionManagerAdapter(
        (ProxyReaderApi) samReader,
        (CalypsoSamAdapter) calypsoSam,
        (SamSecuritySettingAdapter) samSecuritySetting);
  }
}
