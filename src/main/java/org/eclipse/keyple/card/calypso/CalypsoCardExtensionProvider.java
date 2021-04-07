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
package org.eclipse.keyple.card.calypso;

/**
 * Provider of the {@link CalypsoCardExtension} service.
 *
 * @since 2.0
 */
public final class CalypsoCardExtensionProvider {

  /** (private) */
  private CalypsoCardExtensionProvider() {}

  /**
   * Create a {@link CalypsoCardExtension}.
   *
   * @return A not null reference.
   * @since 2.0
   */
  public static CalypsoCardExtension getService() {
    return CalypsoCardExtensionAdapter.getInstance();
  }
}
