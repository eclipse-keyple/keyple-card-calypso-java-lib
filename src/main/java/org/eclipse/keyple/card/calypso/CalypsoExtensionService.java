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

import org.eclipse.keyple.core.common.CommonApiProperties;
import org.eclipse.keyple.core.common.KeypleCardExtension;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.eclipse.keypop.calypso.card.CalypsoCardApiFactory;
import org.eclipse.keypop.calypso.card.card.*;
import org.eclipse.keypop.card.CardApiProperties;
import org.eclipse.keypop.reader.ReaderApiProperties;

/**
 * Card extension dedicated to the management of Calypso cards.
 *
 * @since 2.0.0
 */
public final class CalypsoExtensionService implements KeypleCardExtension {

  /** singleton instance of CalypsoExtensionService */
  private static final CalypsoExtensionService INSTANCE = new CalypsoExtensionService();

  static {
    // Register additional JSON adapters.
    JsonUtil.registerTypeAdapter(DirectoryHeader.class, new DirectoryHeaderJsonAdapter(), false);
    JsonUtil.registerTypeAdapter(ElementaryFile.class, new ElementaryFileJsonAdapter(), false);
    JsonUtil.registerTypeAdapter(FileHeader.class, new FileHeaderJsonAdapter(), false);
    JsonUtil.registerTypeAdapter(SvLoadLogRecord.class, new SvLoadLogRecordJsonAdapter(), false);
    JsonUtil.registerTypeAdapter(SvDebitLogRecord.class, new SvDebitLogRecordJsonAdapter(), false);
    JsonUtil.registerTypeAdapter(CardCommand.class, new AbstractCardCommandJsonAdapter(), false);
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
   * Returns new instance of {@link CalypsoCardApiFactory}.
   *
   * @return A not null reference.
   * @since 3.0.0
   */
  CalypsoCardApiFactory getCalypsoCardApiFactory() {
    return new CalypsoCardApiFactoryAdapter();
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
}
