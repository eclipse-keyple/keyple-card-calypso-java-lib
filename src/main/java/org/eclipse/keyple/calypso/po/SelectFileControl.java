/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.calypso.po;

/**
 * Definitions governing the expected behavior of the selection command (see the specifics of this
 * command in the ISO7816-4 standard and the Calypso specification)
 *
 * @since 2.0
 */
public enum SelectFileControl {
  /** The first EF of the current Calypso DF */
  FIRST_EF,
  /** The next EF of the current Calypso DF */
  NEXT_EF,
  /** The Calypso DF */
  CURRENT_DF
}
