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
package org.eclipse.keyple.calypso.po;

import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import org.eclipse.keyple.core.service.selection.spi.SmartCard;

/**
 * This POJO concentrates all the information we know about the PO being processed: from the
 * selection stage to the end of the transaction.
 *
 * <p>An instance of PoSmartCard is obtained by casting the AbstractSmartCard object from the
 * selection process (e.g. (PoSmartCard)(cardSelectionsResult.getActiveSmartCard()))
 *
 * <p>The various information contained in PoSmartCard is accessible by getters and includes:
 *
 * <ul>
 *   <li>The application identification fields (revision/version, class, DF name, serial number,
 *       ATR, issuer)
 *   <li>The indication of the presence of optional features (Stored Value, PIN, Rev3.2 mode,
 *       ratification management)
 *   <li>The management information of the modification buffer
 *   <li>The invalidation status
 *   <li>The files, counters, SV data read or modified during the execution of the processes defined
 *       by the PO transaction service.
 * </ul>
 *
 * @since 2.0
 */
public interface PoSmartCard extends SmartCard {
  /**
   * Gets the PO revision.
   *
   * <p>The PO revision indicates the generation of the product presented.
   *
   * <p>It will also have an impact on the internal construction of some commands to take into
   * account the specificities of the different POs.
   *
   * @return an enum giving the identified PO revision
   * @since 2.0
   */
  PoRevision getRevision();

  /**
   * Gets the DF name as an array of bytes.
   *
   * <p>The DF name is the name of the application DF as defined in ISO/IEC 7816-4.
   *
   * <p>It also corresponds to the complete representation of the target covered by the AID value
   * provided in the selection command.
   *
   * <p>The AID selects the application by specifying all or part of the targeted DF Name (5 bytes
   * minimum).
   *
   * @return a byte array containing the DF Name bytes (5 to 16 bytes)
   * @since 2.0
   */
  byte[] getDfNameBytes();

  /**
   * Gets the DF name as an HEX String.
   *
   * @return the DF name as an HEX string (see getDfNameBytes)
   * @since 2.0
   */
  String getDfName();

  /**
   * Gets the Calypso application serial number as an array of bytes.
   *
   * <p>The serial number for the application, is unique ID for the PO. <br>
   * The difference with getCalypsoSerialNumber is that the two possible bytes (MSB) of validity
   * date are here forced to zero.
   *
   * @return a byte array containing the Application Serial Number (8 bytes)
   * @since 2.0
   */
  byte[] getApplicationSerialNumberBytes();

  /**
   * Gets the Calypso application serial number as an HEX String.
   *
   * @return a String representing the Application Serial Number (8 bytes / 16 hex digits)
   * @since 2.0
   */
  String getApplicationSerialNumber();

  /**
   * Gets the Calypso startup information field as an HEX String
   *
   * @return the startup info field from the FCI as an HEX string
   * @since 2.0
   */
  String getStartupInfo();

  /**
   * Get the Answer To Reset as an HEX String.
   *
   * <p>The Answer To Reset is sent by the PO is ISO7816-3 mode and in contactless mode for PC/SC
   * readers.
   *
   * <p>When the ATR is obtained in contactless mode, it is in fact reconstructed by the reader from
   * information obtained from the lower communication layers.Therefore, it may differ from one
   * reader to another depending on the interpretation that has been made by the manufacturer of the
   * PC/SC standard.
   *
   * <p>This field is not interpreted in the Calypso module.
   *
   * @return an HEX chain representing the ATR
   * @throws IllegalStateException if the ATR is not available (see {@code hasAtr()} method)
   * @since 2.0
   */
  String getAtr();

  /**
   * The platform identification byte is the reference of the chip
   *
   * @return the platform identification byte
   * @since 2.0
   */
  byte getPlatform();

  /**
   * The Application Type byte determines the Calypso Revision and various options
   *
   * @return the Application Type byte
   * @since 2.0
   */
  byte getApplicationType();

  /**
   * Indicates whether the Confidential Session Mode is supported or not (since rev 3.2).
   *
   * <p>This boolean is interpreted from the Application Type byte
   *
   * @return true if the Confidential Session Mode is supported
   * @since 2.0
   */
  boolean isConfidentialSessionModeSupported();

  /**
   * Indicates if the ratification is done on deselect (ratification command not necessary)
   *
   * <p>This boolean is interpreted from the Application Type byte
   *
   * @return true if the ratification command is required
   * @since 2.0
   */
  boolean isDeselectRatificationSupported();

  /**
   * Indicates whether the PO has the Calypso Stored Value feature.
   *
   * <p>This boolean is interpreted from the Application Type byte
   *
   * @return true if the PO has the Stored Value feature
   * @since 2.0
   */
  boolean isSvFeatureAvailable();

  /**
   * Indicates whether the PO has the Calypso PIN feature.
   *
   * <p>This boolean is interpreted from the Application Type byte
   *
   * @return true if the PO has the PIN feature
   * @since 2.0
   */
  boolean isPinFeatureAvailable();

  /**
   * Indicates whether the Public Authentication is supported or not (since rev 3.3).
   *
   * <p>This boolean is interpreted from the Application Type byte
   *
   * @return true if the Public Authentication is supported
   * @since 2.0
   */
  boolean isPublicAuthenticationSupported();

  /**
   * The Application Subtype indicates to the terminal a reference to the file structure of the
   * Calypso DF.
   *
   * @return the Application Subtype byte
   * @since 2.0
   */
  byte getApplicationSubtype();

  /**
   * The Software Issuer byte indicates the entity responsible for the software of the selected
   * application.
   *
   * @return the Software Issuer byte
   * @since 2.0
   */
  byte getSoftwareIssuer();

  /**
   * The Software Version field may be set to any fixed value by the Software Issuer of the Calypso
   * application.
   *
   * @return the Software Version byte
   * @since 2.0
   */
  byte getSoftwareVersion();

  /**
   * The Software Revision field may be set to any fixed value by the Software Issuer of the Calypso
   * application.
   *
   * @return the Software Revision byte
   * @since 2.0
   */
  byte getSoftwareRevision();

  /**
   * Get the session modification byte from the startup info structure.
   *
   * <p>Depending on the type of PO, the session modification byte indicates the maximum number of
   * bytes that can be modified or the number of possible write commands in a session.
   *
   * @return the Session Modifications byte
   * @since 2.0
   */
  byte getSessionModification();

  /**
   * Tells if the PO has been invalidated or not.
   *
   * <p>An invalidated PO has 6283 as status word in response to the Select Application command.
   *
   * @return true if the PO has been invalidated.
   * @since 2.0
   */
  boolean isDfInvalidated();

  /**
   * Tells if the last session with this PO has been ratified or not.
   *
   * @return true if the PO has been ratified.
   * @throws IllegalStateException if these methods is invoked when no session has been opened
   * @since 2.0
   */
  boolean isDfRatified();

  /**
   * Gets the current SV balance value
   *
   * @return An int
   * @throws IllegalStateException if no SV Get command has been executed
   * @since 2.0
   */
  int getSvBalance();

  /**
   * Gets the last SV transaction number
   *
   * @return An int
   * @throws IllegalStateException if no SV Get command has been executed
   * @since 2.0
   */
  int getSvLastTNum();

  /**
   * Gets a reference to the last {@link SvLoadLogRecord}
   *
   * @return a last SV load log record object or null if not available
   * @throws NoSuchElementException if requested log is not found.
   * @since 2.0
   */
  SvLoadLogRecord getSvLoadLogRecord();

  /**
   * Gets a reference to the last {@link SvDebitLogRecord}
   *
   * @return a last SV debit log record object or null if not available
   * @throws NoSuchElementException if requested log is not found.
   * @since 2.0
   */
  SvDebitLogRecord getSvDebitLogLastRecord();

  /**
   * Gets list of references to the {@link SvDebitLogRecord} read from the PO.
   *
   * @return a list of SV debit log record objects or null if not available
   * @throws NoSuchElementException if requested log is not found.
   * @since 2.0
   */
  List<SvDebitLogRecord> getSvDebitLogAllRecords();

  /**
   * Gets the DF metadata.
   *
   * @return null if is not set.
   * @since 2.0
   */
  DirectoryHeader getDirectoryHeader();

  /**
   * Gets a reference to the {@link ElementaryFile} that has the provided SFI value.<br>
   * Note that if a secure session is actually running, then the object contains all session
   * modifications, which can be canceled if the secure session fails.
   *
   * @param sfi the SFI to search.
   * @return a not null reference.
   * @throws NoSuchElementException if requested EF is not found.
   * @since 2.0
   */
  ElementaryFile getFileBySfi(byte sfi);

  /**
   * Gets a reference to the {@link ElementaryFile} that has the provided LID value.<br>
   * Note that if a secure session is actually running, then the object contains all session
   * modifications, which can be canceled if the secure session fails.
   *
   * @param lid the LID to search.
   * @return a not null reference.
   * @throws NoSuchElementException if requested EF is not found.
   * @since 2.0
   */
  ElementaryFile getFileByLid(short lid);

  /**
   * Gets a reference to a map of all known Elementary Files by their associated SFI.<br>
   * Note that if a secure session is actually running, then the map contains all session
   * modifications, which can be canceled if the secure session fails.
   *
   * @return a not null reference (may be empty if no one EF is set).
   * @since 2.0
   */
  Map<Byte, ElementaryFile> getAllFiles();

  /**
   * Indicates if the PIN is blocked. The maximum number of incorrect PIN submissions has been
   * reached.
   *
   * @return true if the PIN status is blocked
   * @throws IllegalStateException if the PIN has not been checked
   * @since 2.0
   */
  boolean isPinBlocked();

  /**
   * Gives the number of erroneous PIN presentations remaining before blocking.
   *
   * @return the number of remaining attempts
   * @throws IllegalStateException if the PIN has not been checked
   * @since 2.0
   */
  int getPinAttemptRemaining();
}
