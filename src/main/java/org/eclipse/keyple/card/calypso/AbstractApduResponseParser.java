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
 * This abstract class defines the parser used to handle APDU's response.
 *
 * @since 2.0
 */
abstract class AbstractApduResponseParser {

  /**
   * This Map stores expected status that could be . By default inited with sw1=90 and sw2=00
   * (Success)
   *
   * @since 2.0
   */
  protected static final Map<Integer, StatusProperties> STATUS_TABLE;

  static {
    HashMap<Integer, StatusProperties> m = new HashMap<Integer, StatusProperties>();
    m.put(0x9000, new StatusProperties("Success"));
    STATUS_TABLE = m;
  }

  /**
   * the {@link ApduResponseApi} containing response.
   *
   * @since 2.0
   */
  protected final ApduResponseApi response;

  /**
   * Parsers are usually created by their associated builder. The CalypsoSam field maintains a link
   * between the builder and the parser in order to allow the parser to access the builder
   * parameters that were used to create the command (e.g. SFI, registration number, etc.).
   *
   * @since 2.0
   */
  protected final AbstractApduCommandBuilder builder;

  /**
   * (protected)<br>
   * The generic abstract constructor to build a parser of the APDU response.
   *
   * @param response {@link ApduResponseApi} response to parse (should not be null).
   * @param builder {@link AbstractApduCommandBuilder} the reference of the builder that created
   *     the. parser
   * @since 2.0
   */
  protected AbstractApduResponseParser(
      ApduResponseApi response, AbstractApduCommandBuilder builder) {
    this.response = response;
    this.builder = builder;
  }

  /**
   * Returns the internal status table
   *
   * @return A not null reference
   * @since 2.0
   */
  protected Map<Integer, StatusProperties> getStatusTable() {
    return STATUS_TABLE;
  }

  /**
   * Builds a command exception.
   *
   * <p>This method should be override in subclasses in order to create specific exceptions.
   *
   * @param exceptionClass the exception class.
   * @param message the message.
   * @param commandRef {@link CardCommand} the command reference.
   * @param statusWord the status word.
   * @return A not null value
   * @since 2.0
   */
  protected CalypsoApduCommandException buildCommandException(
      Class<? extends CalypsoApduCommandException> exceptionClass,
      String message,
      CardCommand commandRef,
      Integer statusWord) {
    return new CardCommandUnknownStatusException(message, commandRef, statusWord);
  }

  /**
   * Gets {@link ApduResponseApi}
   *
   * @return A not null reference
   * @since 2.0
   */
  public final ApduResponseApi getApduResponse() {
    return response;
  }

  /**
   * Gets {@link AbstractApduCommandBuilder}, the associated builder reference
   *
   * @return A nullable reference
   * @since 2.0
   */
  public AbstractApduCommandBuilder getBuilder() {
    return builder;
  }

  private StatusProperties getStatusWordProperties() {
    return getStatusTable().get(response.getStatusWord());
  }

  /**
   * Gets true if the status is successful from the statusTable according to the current status
   * code.
   *
   * @return A value
   * @since 2.0
   */
  public boolean isSuccessful() {
    StatusProperties props = getStatusWordProperties();
    return props != null && props.isSuccessful();
  }

  /**
   * This method check the status word.<br>
   * If status word is not referenced, then status is considered unsuccessful.
   *
   * @throws CalypsoApduCommandException if status is not successful.
   * @since 2.0
   */
  public void checkStatus() throws CalypsoApduCommandException {

    StatusProperties props = getStatusWordProperties();
    if (props != null && props.isSuccessful()) {
      return;
    }
    // status word is not referenced, or not successful.

    // exception class
    Class<? extends CalypsoApduCommandException> exceptionClass =
        props != null ? props.getExceptionClass() : null;

    // message
    String message = props != null ? props.getInformation() : "Unknown status";

    // command reference
    CardCommand commandRef = getCommandRef();

    // status word
    Integer statusWord = response.getStatusWord();

    // Throw the exception
    throw buildCommandException(exceptionClass, message, commandRef, statusWord);
  }

  /**
   * Gets the associated command reference.<br>
   * By default, the command reference is retrieved from the associated builder.
   *
   * @return A nullable command reference
   * @since 2.0
   */
  protected CardCommand getCommandRef() {
    return builder != null ? builder.getCommandRef() : null;
  }

  /**
   * Gets he ASCII message from the statusTable for the current status word.
   *
   * @return A nullable value
   * @since 2.0
   */
  public final String getStatusInformation() {
    StatusProperties props = getStatusWordProperties();
    return props != null ? props.getInformation() : null;
  }

  /**
   * This internal class provides status word properties
   *
   * @since 2.0
   */
  protected static class StatusProperties {

    private final String information;

    private final boolean successful;

    private final Class<? extends CalypsoApduCommandException> exceptionClass;

    /**
     * Creates a successful status.
     *
     * @param information the status information.
     * @since 2.0
     */
    public StatusProperties(String information) {
      this.information = information;
      this.successful = true;
      this.exceptionClass = null;
    }

    /**
     * Creates an error status.<br>
     * If {@code exceptionClass} is null, then a successful status is created.
     *
     * @param information the status information.
     * @param exceptionClass the associated exception class.
     * @since 2.0
     */
    public StatusProperties(
        String information, Class<? extends CalypsoApduCommandException> exceptionClass) {
      this.information = information;
      this.successful = exceptionClass == null;
      this.exceptionClass = exceptionClass;
    }

    /**
     * Gets information
     *
     * @return A nullable reference
     * @since 2.0
     */
    public String getInformation() {
      return information;
    }

    /**
     * Gets successful indicator
     *
     * @return The successful indicator
     * @since 2.0
     */
    public boolean isSuccessful() {
      return successful;
    }

    /**
     * Gets Exception Class
     *
     * @return A nullable reference
     * @since 2.0
     */
    public Class<? extends CalypsoApduCommandException> getExceptionClass() {
      return exceptionClass;
    }
  }
}
