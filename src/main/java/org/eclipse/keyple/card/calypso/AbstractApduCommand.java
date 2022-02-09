/* **************************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://calypsonet.org/
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

import java.util.HashMap;
import java.util.Map;
import org.calypsonet.terminal.card.ApduResponseApi;

/**
 * (package-private)<br>
 * Generic APDU command.
 *
 * <p>It provides the generic getters to retrieve:
 *
 * <ul>
 *   <li>the card command reference,
 *   <li>the name of the command,
 *   <li>the built {@link org.calypsonet.terminal.card.spi.ApduRequestSpi},
 *   <li>the parsed {@link org.calypsonet.terminal.card.ApduResponseApi}.
 * </ul>
 *
 * @since 2.0.1
 */
abstract class AbstractApduCommand {

  /**
   * (package-private)<br>
   * This Map stores expected status that could be by default initialized with sw1=90 and sw2=00
   * (Success)
   *
   * @since 2.0.1
   */
  static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    HashMap<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>();
    m.put(0x9000, new StatusProperties("Success"));
    STATUS_TABLE = m;
  }

  private final CardCommand commandRef;
  private final int le;
  private String name;
  private ApduRequestAdapter apduRequest;
  private ApduResponseApi apduResponse;

  /**
   * (package-private)<br>
   * Constructor
   *
   * @param commandRef The command reference.
   * @param le The value of the LE field.
   * @since 2.0.1
   */
  AbstractApduCommand(CardCommand commandRef, int le) {
    this.commandRef = commandRef;
    this.name = commandRef.getName();
    this.le = le;
  }

  /**
   * (package-private)<br>
   * Appends a string to the current name.
   *
   * <p>The sub name completes the name of the current command. This method must therefore only be
   * invoked conditionally (log level &gt;= debug).
   *
   * @param subName The string to append.
   * @throws NullPointerException If the request is not set.
   * @since 2.0.1
   */
  final void addSubName(String subName) {
    this.name = this.name + " - " + subName;
    this.apduRequest.setInfo(this.name);
  }

  /**
   * (package-private)<br>
   * Gets {@link CardCommand} the current command identification
   *
   * @return A not null reference.
   * @since 2.0.1
   */
  CardCommand getCommandRef() {
    return commandRef;
  }

  /**
   * (package-private)<br>
   * Gets the name of this APDU command.
   *
   * @return A not empty string.
   * @since 2.0.1
   */
  final String getName() {
    return this.name;
  }

  /**
   * (package-private)<br>
   * Sets the command {@link ApduRequestAdapter}.
   *
   * @param apduRequest The APDU request.
   * @since 2.0.1
   */
  final void setApduRequest(ApduRequestAdapter apduRequest) {
    this.apduRequest = apduRequest;
    this.apduRequest.setInfo(this.name);
  }

  /**
   * (package-private)<br>
   * Gets the {@link ApduRequestAdapter}.
   *
   * @return Null if the request is not set.
   * @since 2.0.1
   */
  final ApduRequestAdapter getApduRequest() {
    return apduRequest;
  }

  /**
   * (package-private)<br>
   * Sets the command {@link ApduResponseApi}.
   *
   * @param apduResponse The APDU response.
   * @return The current instance.
   * @since 2.0.1
   */
  AbstractApduCommand setApduResponse(ApduResponseApi apduResponse) {
    this.apduResponse = apduResponse;
    return this;
  }

  /**
   * (package-private)<br>
   * Gets {@link ApduResponseApi}
   *
   * @return Null if the response is not set.
   * @since 2.0.1
   */
  final ApduResponseApi getApduResponse() {
    return apduResponse;
  }

  /**
   * (package-private)<br>
   * Returns the internal status table
   *
   * @return A not null reference
   * @since 2.0.1
   */
  Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * (package-private)<br>
   * Builds a specific APDU command exception.
   *
   * @param exceptionClass the exception class.
   * @param message The message.
   * @return A not null reference.
   * @since 2.0.1
   */
  abstract CalypsoApduCommandException buildCommandException(
      Class<? extends CalypsoApduCommandException> exceptionClass, String message);

  /**
   * (package-private)<br>
   * Builds a specific APDU command exception for the case of an unexpected response length.
   *
   * @param message The message.
   * @return A not null reference.
   * @since 2.1.1
   */
  abstract CalypsoApduCommandException buildUnexpectedResponseLengthException(String message);

  /**
   * (private)<br>
   *
   * @return The properties of the result.
   * @throws NullPointerException If the response is not set.
   */
  private StatusProperties getStatusWordProperties() {
    return getStatusTable().get(apduResponse.getStatusWord());
  }

  /**
   * (package-private)<br>
   * Gets true if the status is successful from the statusTable according to the current status code
   * and if the length of the response is equal to the LE field in the request.
   *
   * @return A value
   * @since 2.0.1
   */
  final boolean isSuccessful() {
    StatusProperties props = getStatusWordProperties();
    return props != null
        && props.isSuccessful()
        && (le == 0 || apduResponse.getDataOut().length == le); // CL-CSS-RESPLE.1
  }

  /**
   * (package-private)<br>
   * This method check the status word and if the length of the response is equal to the LE field in
   * the request.<br>
   * If status word is not referenced, then status is considered unsuccessful.
   *
   * @throws CalypsoApduCommandException if status is not successful or if the length of the
   *     response is not equal to the LE field in the request.
   * @since 2.0.1
   */
  void checkStatus() throws CalypsoApduCommandException {

    StatusProperties props = getStatusWordProperties();
    if (props != null && props.isSuccessful()) {
      // SW is successful, then check the response length (CL-CSS-RESPLE.1)
      if (le != 0 && apduResponse.getDataOut().length != le) {
        throw buildUnexpectedResponseLengthException(
            String.format(
                "Incorrect APDU response length (expected: %d, actual: %d)",
                le, apduResponse.getDataOut().length));
      }
      // SW and response length are correct.
      return;
    }
    // status word is not referenced, or not successful.

    // exception class
    Class<? extends CalypsoApduCommandException> exceptionClass =
        props != null ? props.getExceptionClass() : null;

    // message
    String message = props != null ? props.getInformation() : "Unknown status";

    // Throw the exception
    throw buildCommandException(exceptionClass, message);
  }

  /**
   * (package-private)<br>
   * Gets the ASCII message from the statusTable for the current status word.
   *
   * @return A nullable value
   * @since 2.0.1
   */
  final String getStatusInformation() {
    StatusProperties props = getStatusWordProperties();
    return props != null ? props.getInformation() : null;
  }

  /**
   * (package-private)<br>
   * This internal class provides status word properties
   *
   * @since 2.0.1
   */
  static class StatusProperties {

    private final String information;

    private final boolean successful;

    private final Class<? extends CalypsoApduCommandException> exceptionClass;

    /**
     * (package-private)<br>
     * Creates a successful status.
     *
     * @param information the status information.
     * @since 2.0.1
     */
    StatusProperties(String information) {
      this.information = information;
      this.successful = true;
      this.exceptionClass = null;
    }

    /**
     * (package-private)<br>
     * Creates an error status.<br>
     * If {@code exceptionClass} is null, then a successful status is created.
     *
     * @param information the status information.
     * @param exceptionClass the associated exception class.
     * @since 2.0.1
     */
    StatusProperties(
        String information, Class<? extends CalypsoApduCommandException> exceptionClass) {
      this.information = information;
      this.successful = exceptionClass == null;
      this.exceptionClass = exceptionClass;
    }

    /**
     * (package-private)<br>
     * Gets information
     *
     * @return A nullable reference
     * @since 2.0.1
     */
    String getInformation() {
      return information;
    }

    /**
     * (package-private)<br>
     * Gets successful indicator
     *
     * @return The successful indicator
     * @since 2.0.1
     */
    boolean isSuccessful() {
      return successful;
    }

    /**
     * (package-private)<br>
     * Gets Exception Class
     *
     * @return A nullable reference
     * @since 2.0.1
     */
    Class<? extends CalypsoApduCommandException> getExceptionClass() {
      return exceptionClass;
    }
  }
}
