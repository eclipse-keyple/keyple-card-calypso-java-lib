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
interface SvCommandSecurityDataApi {

  /**
   * Returns the "SV Get" ingoing command data.
   *
   * @return A not empty byte array containing the "SV Get" apdu request data.
   * @since x.y.z
   */
  byte[] getSvGetRequest();

  /**
   * Returns the "SV Get" outgoing command data.
   *
   * @return A not empty byte array containing the "SV Get" apdu response data.
   * @since x.y.z
   */
  byte[] getSvGetResponse();

  /**
   * Returns the "SV Load/Debit/Undebit" ingoing partial command data.
   *
   * @return A not empty byte array containing the "SV Load/Debit/Undebit" apdu request data.
   * @since x.y.z
   */
  byte[] getSvCommandPartialRequest();

  /**
   * Sets the serial number to be placed in the "SV Load/Debit/Undebit" command request.
   *
   * @return The current instance.
   * @since x.y.z
   */
  SvCommandSecurityDataApi setSerialNumber(byte[] serialNumber);

  /**
   * Sets the transaction number to be placed in the "SV Load/Debit/Undebit" command request.
   *
   * @return The current instance.
   * @since x.y.z
   */
  SvCommandSecurityDataApi setTransactionNumber(byte[] transactionNumber);

  /**
   * Sets the terminal challenge to be placed in the SV Load/Debit/Undebit command request.
   *
   * @return The current instance.
   * @since x.y.z
   */
  SvCommandSecurityDataApi setTerminalChallenge(byte[] terminalChallenge);

  /**
   * Sets the terminal SV MAC to be placed in the "SV Load/Debit/Undebit" command request.
   *
   * @return The current instance.
   * @since x.y.z
   */
  SvCommandSecurityDataApi setTerminalSvMac(byte[] terminalSvMac);
}
