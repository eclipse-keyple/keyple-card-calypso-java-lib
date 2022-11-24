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

/**
 * Contains the input/output data of the SV command operations (LOAD/DEBIT/UNDEBIT).
 *
 * @since x.y.z
 */
interface SvCommandSecurityData {

  /**
   * Sets the "SV Get" ingoing command data.
   *
   * @param svGetRequest A not empty byte array containing the "SV Get" apdu request data.
   * @return The object instance.
   * @since x.y.z
   */
  SvCommandSecurityData setSvGetRequest(byte[] svGetRequest);

  /**
   * Sets the "SV Get" outgoing command data.
   *
   * @param svGetResponse A not empty byte array containing the "SV Get" apdu response data.
   * @return The object instance.
   * @since x.y.z
   */
  SvCommandSecurityData setSvGetResponse(byte[] svGetResponse);

  /**
   * Sets the "SV Load/Debit/Undebit" outgoing command data.
   *
   * @param svCommandPartialRequest A not empty byte array containing the "SV Load/Debit/Undebit"
   *     apdu request data.
   * @return The object instance.
   * @since x.y.z
   */
  SvCommandSecurityData setSvCommandPartialRequest(byte[] svCommandPartialRequest);

  /**
   * Gets the serial number to be placed in the "SV Load/Debit/Undebit" command request.
   *
   * @return A not byte array containing the serial number.
   * @since x.y.z
   */
  byte[] getSerialNumber();

  /**
   * Gets the transaction number to be placed in the "SV Load/Debit/Undebit" command request.
   *
   * @return A not byte array containing the transaction number.
   * @since x.y.z
   */
  byte[] getTransactionNumber();

  /**
   * Gets the terminal challenge to be placed in the SV Load/Debit/Undebit command request.
   *
   * @return A not byte array containing the terminal challenge.
   * @since x.y.z
   */
  byte[] getTerminalChallenge();

  /**
   * Gets the terminal SV MAC to be placed in the "SV Load/Debit/Undebit" command request.
   *
   * @return A not byte array containing the terminal SV MAC.
   * @since x.y.z
   */
  byte[] getTerminalSvMac();
}
