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
 * Superclass for all SAM command.
 *
 * @since 2.0.1
 */
abstract class AbstractSamCommand {


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
    m.put(
            0x6D00,
            new StatusProperties("Instruction unknown.", CalypsoSamIllegalParameterException.class));
    m.put(
            0x6E00,
            new StatusProperties("Class not supported.", CalypsoSamIllegalParameterException.class));
    m.put(0x9000, new StatusProperties("Success"));
    STATUS_TABLE = m;
  }

  private final CalypsoSamCommand commandRef;
  private final int le;
  private String name;
  private ApduRequestAdapter apduRequest;
  private ApduResponseApi apduResponse;
  private CalypsoSamAdapter calypsoSam;

  /**
   * (package-private)<br>
   * Constructor dedicated for the building of referenced Calypso commands
   *
   * @param commandRef A command reference from the Calypso command table.
   * @param le The value of the LE field.
   * @param calypsoSam The Calypso SAM (it may be null if the SAM selection has not yet been made).
   * @since 2.0.1
   */
  AbstractSamCommand(CalypsoSamCommand commandRef, int le, CalypsoSamAdapter calypsoSam) {
    this.commandRef = commandRef;
    this.name = commandRef.getName();
    this.le = le;
    this.calypsoSam = calypsoSam;
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
   * Returns the Calypso SAM.
   *
   * @return Null if the SAM selection has not yet been made.
   * @since 2.2.3
   */
  CalypsoSamAdapter getCalypsoSam() {
    return calypsoSam;
  }

  /**
   * (package-private)<br>
   * Parses the response {@link ApduResponseApi} and checks the status word.
   *
   * @param apduResponse The APDU response.
   * @throws CalypsoSamCommandException if status is not successful or if the length of the
   *     response is not equal to the LE field in the request.
   * @since 2.0.1
   */
  void parseApduResponse(ApduResponseApi apduResponse) throws CalypsoSamCommandException {
    this.apduResponse = apduResponse;
    checkStatus();
  }

  /**
   * (package-private)<br>
   * Sets the Calypso SAM and invoke the {@link #parseApduResponse(ApduResponseApi)} method.
   *
   * @since 2.2.3
   */
  void parseApduResponse(ApduResponseApi apduResponse, CalypsoSamAdapter calypsoSam)
          throws CalypsoSamCommandException {
    this.calypsoSam = calypsoSam;
    parseApduResponse(apduResponse);
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
  CalypsoSamCommandException buildCommandException(
          Class<? extends CalypsoSamCommandException> exceptionClass, String message) {

    CalypsoSamCommandException e;
    CalypsoSamCommand command = commandRef;
    Integer statusWord = getApduResponse().getStatusWord();
    if (exceptionClass == CalypsoSamAccessForbiddenException.class) {
      e = new CalypsoSamAccessForbiddenException(message, command, statusWord);
    } else if (exceptionClass == CalypsoSamCounterOverflowException.class) {
      e = new CalypsoSamCounterOverflowException(message, command, statusWord);
    } else if (exceptionClass == CalypsoSamDataAccessException.class) {
      e = new CalypsoSamDataAccessException(message, command, statusWord);
    } else if (exceptionClass == CalypsoSamIllegalArgumentException.class) {
      e = new CalypsoSamIllegalArgumentException(message, command);
    } else if (exceptionClass == CalypsoSamIllegalParameterException.class) {
      e = new CalypsoSamIllegalParameterException(message, command, statusWord);
    } else if (exceptionClass == CalypsoSamIncorrectInputDataException.class) {
      e = new CalypsoSamIncorrectInputDataException(message, command, statusWord);
    } else if (exceptionClass == CalypsoSamSecurityDataException.class) {
      e = new CalypsoSamSecurityDataException(message, command, statusWord);
    } else {
      e = new CalypsoSamUnknownStatusException(message, command, statusWord);
    }
    return e;
  }

  /**
   * (package-private)<br>
   * Builds a specific APDU command exception for the case of an unexpected response length.
   *
   * @param message The message.
   * @return A not null reference.
   * @since 2.1.1
   */
  CalypsoSamCommandException buildUnexpectedResponseLengthException(String message){
    return new CalypsoSamUnexpectedResponseLengthException(
            message, commandRef, getApduResponse().getStatusWord());
  }

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
   * (private)<br>
   * This method check the status word and if the length of the response is equal to the LE field in
   * the request.<br>
   * If status word is not referenced, then status is considered unsuccessful.
   *
   * @throws CalypsoSamCommandException if status is not successful or if the length of the
   *     response is not equal to the LE field in the request.
   */
  private void checkStatus() throws CalypsoSamCommandException {

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
    Class<? extends CalypsoSamCommandException> exceptionClass =
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

    private final Class<? extends CalypsoSamCommandException> exceptionClass;

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
            String information, Class<? extends CalypsoSamCommandException> exceptionClass) {
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
    Class<? extends CalypsoSamCommandException> getExceptionClass() {
      return exceptionClass;
    }
  }







}
