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
package org.eclipse.keyple.card.calypso.transaction;

import org.eclipse.keyple.card.calypso.po.CalypsoCard;
import org.eclipse.keyple.card.calypso.po.ElementaryFile;
import org.eclipse.keyple.card.calypso.po.FileData;
import org.eclipse.keyple.card.calypso.po.SelectFileControl;
import org.eclipse.keyple.core.card.CardRequest;

/**
 * Service providing the high-level API to manage transactions with a Calypso PO.
 *
 * <p>Depending on the type of operations required, the presence of a SAM may be necessary.
 *
 * <p>The {@link CalypsoCard} object provided to the build is kept and updated at each step of using
 * the service. It is the main container of the data handled during the transaction and acts as a
 * card image.
 *
 * <p>There are two main steps in using the methods of this service:
 *
 * <ul>
 *   <li>A command preparation step during which the application invokes prefixed "prepare" methods
 *       that will add to an internal list of commands to be executed by the PO. The incoming data
 *       to the PO are placed in {@link CalypsoCard}.
 *   <li>A processing step corresponding to the prefixed "process" methods, which will carry out the
 *       communications with the PO and if necessary the SAM. The outgoing data from the PO are
 *       placed in {@link CalypsoCard}.
 * </ul>
 *
 * <p>Technical or data errors, security conditions, etc. are reported as exceptions.
 *
 * @since 2.0
 */
public interface PoTransactionService {
  /**
   * Opens a Calypso Secure Session and then executes all previously prepared commands.
   *
   * <p>It is the starting point of the sequence:
   *
   * <ul>
   *   <li>{@link #processOpening(SessionAccessLevel)}
   *   <li>[{@link #processPoCommands()}]
   *   <li>[...]
   *   <li>[{@link #processPoCommands()}]
   *   <li>{@link #processClosing()}
   * </ul>
   *
   * <p>Each of the steps in this sequence may or may not be preceded by the preparation of one or
   * more commands and ends with an update of the {@link CalypsoCard} object provided when
   * PoTransactionService was created.
   *
   * <p>As a prerequisite for invoking this method, since the Calypso Secure Session involves the
   * use of a SAM, the PoTransactionService must have been built in secure mode, i.e. the
   * constructor used must be the one expecting a reference to a valid {@link PoSecuritySetting}
   * object, otherwise a {@link CalypsoPoTransactionIllegalStateException} is raised.
   *
   * <p>The secure session is opened with the {@link SessionAccessLevel} passed as an argument
   * depending on whether it is a personalization, reload or debit transaction profile..
   *
   * <p>The possible overflow of the internal session buffer of the PO is managed in two ways
   * depending on the setting chosen in {@link PoSecuritySetting}.
   *
   * <ul>
   *   <li>If the session was opened with the default atomic mode and the previously prepared
   *       commands will cause the buffer to be exceeded, then an {@link
   *       CalypsoAtomicTransactionException} is raised and no transmission to the PO is made. <br>
   *   <li>If the session was opened with the multiple session mode and the buffer is to be exceeded
   *       then a split into several secure sessions is performed automatically. However, regardless
   *       of the number of intermediate sessions performed, a secure session is opened at the end
   *       of the execution of this method.
   * </ul>
   *
   * <p>Be aware that in the "MULTIPLE" case we lose the benefit of the atomicity of the secure
   * session.
   *
   * <p><b>PO and SAM exchanges in detail</b>
   *
   * <p>When executing this method, communications with the PO and the SAM are (in that order) :
   *
   * <ul>
   *   <li>Sending the card diversifier (Calypso PO serial number) to the SAM and receiving the
   *       terminal challenge
   *   <li>Grouped sending to the PO (in a {@link CardRequest}) of
   *       <ul>
   *         <li>the open secure session command including the challenge terminal.
   *         <li>all previously prepared commands
   *       </ul>
   *   <li>Receiving grouped responses and updating {@link CalypsoCard} with the collected data.
   * </ul>
   *
   * For optimization purposes, if the first command prepared is the reading of a single record of a
   * PO file then this one is replaced by a setting of the session opening command allowing the
   * retrieval of this data in response to this command.
   *
   * <p><b>Other operations carried out</b>
   *
   * <ul>
   *   <li>The card KIF, KVC and card challenge received in response to the open secure session
   *       command are kept for a later initialization of the session's digest (see {@link
   *       #processClosing}).
   *   <li>All data received in response to the open secure session command and the responses to the
   *       prepared commands are also stored for later calculation of the digest.
   *   <li>If a list of authorized KVCs has been defined in {@link PoSecuritySetting} and the KVC of
   *       the card does not belong to this list then a {@link CalypsoUnauthorizedKvcException} is
   *       thrown.
   * </ul>
   *
   * <p>All unexpected results (communication errors, data or security errors, etc. are notified to
   * the calling application through dedicated exceptions.
   *
   * <p><i>Note: to understand in detail how the secure session works please refer to the PO
   * specification documents.</i>
   *
   * @param sessionAccessLevel An {@link SessionAccessLevel} enum entry.
   * @return The object instance.
   * @throws CalypsoPoTransactionIllegalStateException if no {@link PoSecuritySetting} is available
   * @throws CalypsoAtomicTransactionException if the PO session buffer were to overflow
   * @throws CalypsoUnauthorizedKvcException If the card KVC is not authorized
   * @throws CalypsoPoTransactionException If a functional error occurs (including PO and SAM IO
   *     errors)
   * @since 2.0
   */
  PoTransactionService processOpening(SessionAccessLevel sessionAccessLevel);

  /**
   * Process all previously prepared PO commands outside or inside a Secure Session.
   *
   * <ul>
   *   <li>All APDUs resulting from prepared commands are grouped in a {@link CardRequest} and sent
   *       to the PO.
   *   <li>The {@link CalypsoCard} object is updated with the result of the executed commands.
   *   <li>If a secure session is opened, except in the case where reloading or debit SV operations
   *       have been prepared, the invocation of this method does not generate communication with
   *       the SAM. The data necessary for the calculation of the terminal signature are kept to be
   *       sent to the SAM at the time of the invocation of {@link #processClosing()}.<br>
   *       The PO channel is kept open.
   *   <li>If no secure session is opened, the PO channel is closed depending on whether or not
   *       prepareReleasePoChannel has been called.
   *   <li>The PO session buffer overflows are managed in the same way as in {@link
   *       #processOpening(SessionAccessLevel)}. For example, when the multiple session mode is
   *       enabled, the commands are separated in as many sessions as necessary to respect the
   *       capacity of the PO buffer.
   * </ul>
   *
   * @return The object instance.
   * @throws CalypsoPoTransactionException If a functional error occurs (including PO and SAM IO
   *     errors)
   * @since 2.0
   */
  PoTransactionService processPoCommands();

  /**
   * Terminates the Secure Session sequence started with {@link
   * #processOpening(SessionAccessLevel)}.
   *
   * <p><b>Nominal case</b>
   *
   * <p>The previously prepared commands are integrated into the calculation of the session digest
   * by the SAM before execution by the PO by anticipating their responses.
   *
   * <p>Thus, the session closing command containing the terminal signature is integrated into the
   * same APDU group sent to the PO via a final {@link CardRequest}.
   *
   * <p>Upon reception of the {@link CardRequest} PO, the signature of the PO is verified with the
   * SAM.
   *
   * <p>If the method terminates normally, it means that the secure session closing and all related
   * security checks have been successful; conversely, if one of these operations fails, an
   * exception is raised.
   *
   * <p><b>Stored Value</b>
   *
   * <p>If the SV counter was debited or reloaded during the session, an additional verification
   * specific to the SV is performed by the SAM.
   *
   * <p><b>Ratification</b>
   *
   * <p>A ratification command is added after the close secure session command when the
   * communication is done in a contactless mode.
   *
   * <p>The logical channel is closed or left open depending on whether the {@link
   * #prepareReleasePoChannel()} method has been called before or not.
   *
   * <p><b>PO and SAM exchanges in detail</b>
   *
   * <ul>
   *   <li>All the data exchanged with the PO so far, to which are added the last prepared orders
   *       and their anticipated answers, are sent to the SAM for the calculation of the session
   *       digest. The terminal signature calculation request is also integrated in the same {@link
   *       CardRequest} SAM.
   *   <li>All previously prepared commands are sent to the PO along with the session closing
   *       command and possibly the ratification command within a single {@link CardRequest}.
   *   <li>The responses received from the PO are integrated into CalypsoCard. <br>
   *       Note: the reception of the answers of this final {@link CardRequest} PO is tolerant to
   *       the non-reception of the answer to the ratification order.
   *   <li>The data received from the PO in response to the logout (PO session signature and
   *       possibly SV signature) are sent to the SAM for verification.
   * </ul>
   *
   * @throws CalypsoPoTransactionException If a functional error occurs (including PO and SAM IO
   *     errors)
   * @since 2.0
   */
  void processClosing();

  /**
   * Aborts a Secure Session.
   *
   * <p>Send the appropriate command to the PO
   *
   * <p>Clean up internal data and status.
   *
   * @throws CalypsoPoTransactionException If a functional error occurs (including PO and SAM IO
   *     errors)
   * @since 2.0
   */
  void processCancel();

  /**
   * Performs a PIN verification, in order to authenticate the card holder and/or unlock access to
   * certain PO files.
   *
   * <p>This command can be performed both in and out of a secure session. The PIN code can be
   * transmitted in plain text or encrypted according to the parameter set in PoSecuritySetting (by
   * default the transmission is encrypted).
   *
   * <p>If the execution is done out of session but an encrypted transmission is requested, then
   * PoTransactionService must be constructed with {@link PoSecuritySetting}
   *
   * <p>If PoTransactionService is constructed without {@link PoSecuritySetting} the transmission in
   * done in plain.
   *
   * <p>The PO channel is closed if prepareReleasePoChannel is called before this command.
   *
   * @param pin The PIN code value (4-byte long byte array).
   * @return The object instance.
   * @throws CalypsoPoTransactionException If a functional error occurs (including PO and SAM IO
   *     errors)
   * @throws CalypsoPoTransactionIllegalStateException If the PIN feature is not available for this
   *     PO or if commands have been prepared before invoking this process method.
   * @since 2.0
   */
  PoTransactionService processVerifyPin(byte[] pin);

  /**
   * Invokes {@link #processVerifyPin(byte[])} with a string converted into an array of bytes as
   * argument.
   *
   * <p>The provided String is converted into an array of bytes and processed with {@link
   * #processVerifyPin(byte[])}.
   *
   * <p>E.g. "1234" will be transmitted as { 0x31,0x32,0x33,0x34 }
   *
   * @param pin An ASCII string (4-character long).
   * @return The object instance.
   * @see #processVerifyPin(byte[])
   * @since 2.0
   */
  PoTransactionService processVerifyPin(String pin);

  /**
   * Requests the closing of the PO channel.
   *
   * <p>If this command is called before a "process" command (except for processOpening) then the
   * last transmission to the PO will be associated with the indication CLOSE_AFTER in order to
   * close the PO channel.
   *
   * <p>Note: this command must imperatively be called at the end of any transaction, whether it
   * ended normally or not.
   *
   * <p>In case the transaction was interrupted (exception), an additional invocation of
   * processPoCommands must be made to effectively close the channel.
   *
   * @return The object instance.
   * @since 2.0
   */
  PoTransactionService prepareReleasePoChannel();

  /**
   * Schedules the execution of a <b>Select File</b> command based on the file's LID.
   *
   * <p>Once this command is processed, the result is available in {@link CalypsoCard} through the
   * {@link CalypsoCard#getFileBySfi(byte)} and {@link ElementaryFile#getHeader()} methods.
   *
   * @param lid The LID of the EF to select.
   * @return The object instance.
   * @since 2.0
   */
  PoTransactionService prepareSelectFile(byte[] lid);

  /**
   * Schedules the execution of a <b>Select File</b> command using a navigation control defined by
   * the ISO standard.
   *
   * <p>Once this command is processed, the result is available in {@link CalypsoCard} through the
   * {@link CalypsoCard#getFileBySfi(byte)} and {@link ElementaryFile#getHeader()} methods.
   *
   * @param control A {@link SelectFileControl} enum entry.
   * @return The object instance.
   * @since 2.0
   */
  PoTransactionService prepareSelectFile(SelectFileControl control);

  /**
   * Schedules the execution of a <b>Read Records</b> command to read a single record from the
   * indicated EF.
   *
   * <p>Once this command is processed, the result is available in {@link CalypsoCard}.
   *
   * <p>See the method {@link CalypsoCard#getFileBySfi(byte)}, the objects {@link ElementaryFile},
   * {@link FileData} and their specialized methods according to the type of expected data: e.g.
   * {@link FileData#getContent(int)}.
   *
   * @param sfi The SFI of the EF to read.
   * @param recordNumber The record number to read.
   * @return The object instance.
   * @throws IllegalArgumentException If one of the provided argument is out of range
   * @since 2.0
   */
  PoTransactionService prepareReadRecordFile(byte sfi, int recordNumber);

  /**
   * Schedules the execution of a <b>Read Records</b> command to read one or more records from the
   * indicated EF.
   *
   * <p>Once this command is processed, the result is available in {@link CalypsoCard}.
   *
   * <p>See the method {@link CalypsoCard#getFileBySfi(byte)}, the objects {@link ElementaryFile},
   * {@link FileData} and their specialized methods according to the type of expected data: e.g.
   * {@link FileData#getContent()}.
   *
   * @param sfi The SFI of the EF.
   * @param firstRecordNumber The record number to read (or first record to read in case of several.
   *     records)
   * @param numberOfRecords The number of records expected.
   * @param recordSize The record length.
   * @return The object instance.
   * @throws IllegalArgumentException If one of the provided argument is out of range
   * @since 2.0
   */
  PoTransactionService prepareReadRecordFile(
      byte sfi, int firstRecordNumber, int numberOfRecords, int recordSize);

  /**
   * Schedules the execution of a <b>Read Records</b> command to reads a record of the indicated EF,
   * which should be a counter file.
   *
   * <p>The record will be read up to the counter location indicated in parameter.<br>
   * Thus all previous counters will also be read.
   *
   * <p>Once this command is processed, the result is available in {@link CalypsoCard}.
   *
   * <p>See the method {@link CalypsoCard#getFileBySfi(byte)}, the objects {@link ElementaryFile},
   * {@link FileData} and their specialized methods according to the type of expected data: e.g.
   * {@link FileData#getAllCountersValue()} (int)}.
   *
   * @param sfi The SFI of the EF.
   * @param countersNumber The number of the last counter to be read.
   * @return The object instance.
   * @throws IllegalArgumentException If one of the provided argument is out of range
   * @since 2.0
   */
  PoTransactionService prepareReadCounterFile(byte sfi, int countersNumber);

  /**
   * Schedules the execution of a <b>Append Record</b> command to adds the data provided in the
   * indicated cyclic file.
   *
   * <p>A new record is added, the oldest record is deleted.
   *
   * <p>Note: {@link CalypsoCard} is filled with the provided input data.
   *
   * @param sfi The sfi to select.
   * @param recordData The new record data to write.
   * @return The object instance.
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.0
   */
  PoTransactionService prepareAppendRecord(byte sfi, byte[] recordData);

  /**
   * Schedules the execution of a <b>Update Record</b> command to overwrites the target file's
   * record contents with the provided data.
   *
   * <p>If the input data is shorter than the record size, only the first bytes will be overwritten.
   *
   * <p>Note: {@link CalypsoCard} is filled with the provided input data.
   *
   * @param sfi The sfi to select.
   * @param recordNumber The record number to update.
   * @param recordData The new record data. If length {@code <} RecSize, bytes beyond length are.
   *     left unchanged.
   * @return The object instance.
   * @throws IllegalArgumentException If record number is {@code <} 1
   * @throws IllegalArgumentException If the request is inconsistent
   * @since 2.0
   */
  PoTransactionService prepareUpdateRecord(byte sfi, int recordNumber, byte[] recordData);

  /**
   * Schedules the execution of a <b>Write Record</b> command to updates the target file's record
   * contents with the result of a binary OR between the existing data and the provided data.
   *
   * <p>If the input data is shorter than the record size, only the first bytes will be overwritten.
   *
   * <p>Note: {@link CalypsoCard} is filled with the provided input data.
   *
   * @param sfi The sfi to select.
   * @param recordNumber The record number to write.
   * @param recordData The data to overwrite in the record. If length {@code <} RecSize, bytes.
   *     beyond length are left unchanged.
   * @return The object instance.
   * @throws IllegalArgumentException If record number is {@code <} 1
   * @throws IllegalArgumentException If the request is inconsistent
   * @since 2.0
   */
  PoTransactionService prepareWriteRecord(byte sfi, int recordNumber, byte[] recordData);

  /**
   * Schedules the execution of a <b>Increase command</b> command to increase the target counter.
   *
   * <p>Note: {@link CalypsoCard} is filled with the provided input data.
   *
   * @param counterNumber {@code >=} 01h: Counters file, number of the counter. 00h: Simulated.
   *     Counter file.
   * @param sfi SFI of the file to select or 00h for current EF.
   * @param incValue Value to add to the counter (defined as a positive int {@code <=} 16777215
   *     [FFFFFFh])
   * @return The object instance.
   * @throws IllegalArgumentException If the decrement value is out of range
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.0
   */
  PoTransactionService prepareIncreaseCounter(byte sfi, int counterNumber, int incValue);

  /**
   * Schedules the execution of a <b>Decrease command</b> command to decrease the target counter.
   *
   * <p>Note: {@link CalypsoCard} is filled with the provided input data.
   *
   * @param counterNumber {@code >=} 01h: Counters file, number of the counter. 00h: Simulated.
   *     Counter file.
   * @param sfi SFI of the file to select or 00h for current EF.
   * @param decValue Value to subtract to the counter (defined as a positive int {@code <=} 16777215
   *     [FFFFFFh])
   * @return The object instance.
   * @throws IllegalArgumentException If the decrement value is out of range
   * @throws IllegalArgumentException If the command is inconsistent
   * @since 2.0
   */
  PoTransactionService prepareDecreaseCounter(byte sfi, int counterNumber, int decValue);

  /**
   * Schedules the execution of a command to set the value of the target counter.
   *
   * <p>It builds an Increase or Decrease command and add it to the list of commands to be sent with
   * the next <b>process</b> command in order to set the target counter to the specified value.<br>
   * The operation (Increase or Decrease) is selected according to whether the difference between
   * the current value and the desired value is negative (Increase) or positive (Decrease).
   *
   * <p>Note: it is assumed here that:<br>
   *
   * <ul>
   *   <li>the counter value has been read before,
   *   <li>the type of session (and associated access rights) is consistent with the requested
   *       operation: reload session if the counter is to be incremented, debit if it is to be
   *       decremented.<br>
   *       No control is performed on this point by this method; the closing of the session will
   *       determine the success of the operation..
   * </ul>
   *
   * @param counterNumber {@code >=} 01h: Counters file, number of the counter. 00h: Simulated.
   *     Counter file.
   * @param sfi SFI of the file to select or 00h for current EF.
   * @param newValue The desired value for the counter (defined as a positive int {@code <=}
   *     16777215 [FFFFFFh])
   * @return The object instance.
   * @throws IllegalArgumentException If the desired value is out of range or if the command is
   *     inconsistent
   * @throws CalypsoPoTransactionIllegalStateException If the current counter value is unknown.
   * @since 2.0
   */
  PoTransactionService prepareSetCounter(byte sfi, int counterNumber, int newValue);

  /**
   * Schedules the execution of a <b>Verify Pin</b> command without PIN presentation in order to get
   * the attempt counter.
   *
   * <p>The PIN status will made available in CalypsoCard after the execution of process command.
   * <br>
   * Adds it to the list of commands to be sent with the next process command.
   *
   * <p>See {@link CalypsoCard#isPinBlocked} and {@link CalypsoCard#getPinAttemptRemaining} methods.
   *
   * @return The object instance.
   * @throws CalypsoPoTransactionIllegalStateException If the PIN feature is not available for this
   *     PO.
   * @since 2.0
   */
  PoTransactionService prepareCheckPinStatus();

  /**
   * Schedules the execution of a <b>SV Get</b> command to prepare an SV operation or simply
   * retrieves the current SV status.
   *
   * <p>Once this command is processed, the result is available in {@link CalypsoCard}.
   *
   * <p>See the methods {@link CalypsoCard#getSvBalance()}, {@link CalypsoCard#getSvLoadLogRecord()}
   * ()}, {@link CalypsoCard#getSvDebitLogLastRecord()}, {@link
   * CalypsoCard#getSvDebitLogAllRecords()}.
   *
   * @param svOperation Informs about the nature of the intended operation: debit or reload.
   * @param svAction The type of action: DO a debit or a positive reload, UNDO an undebit or a.
   *     negative reload
   * @return The object instance.
   * @throws CalypsoPoTransactionIllegalStateException If the SV feature is not available for this
   *     PO.
   * @since 2.0
   */
  PoTransactionService prepareSvGet(SvSettings.Operation svOperation, SvSettings.Action svAction);

  /**
   * Schedules the execution of a <b>SV Reload</b> command to increase the current SV balance and
   * using the provided additional data.
   *
   * <p>Note #1: a communication with the SAM is done here.
   *
   * <p>Note #2: the key used is the reload key.
   *
   * @param amount The value to be reloaded, positive or negative integer in the range.
   *     -8388608..8388607
   * @param date 2-byte free value.
   * @param time 2-byte free value.
   * @param free 2-byte free value.
   * @return The object instance.
   * @throws CalypsoPoTransactionIllegalStateException If the SV feature is not available for this
   *     PO.
   * @throws CalypsoPoTransactionException If a functional error occurs (including PO and SAM IO
   *     errors)
   * @since 2.0
   */
  PoTransactionService prepareSvReload(int amount, byte[] date, byte[] time, byte[] free)
      throws CalypsoPoTransactionException;

  /**
   * Schedules the execution of a <b>SV Reload</b> command to increase the current SV balance.
   *
   * <p>Note #1: the optional SV additional data are set to zero.
   *
   * <p>Note #2: a communication with the SAM is done here.
   *
   * <p>Note #3: the key used is the reload key.
   *
   * @param amount The value to be reloaded, positive integer in the range 0..8388607 for a DO.
   *     action, in the range 0..8388608 for an UNDO action.
   * @return The object instance.
   * @throws CalypsoPoTransactionIllegalStateException If the SV feature is not available for this
   *     PO.
   * @throws CalypsoPoTransactionException If a functional error occurs (including PO and SAM IO
   *     errors)
   * @since 2.0
   */
  PoTransactionService prepareSvReload(int amount) throws CalypsoPoTransactionException;

  /**
   * Schedules the execution of a <b>SV Debit</b> or <b>SV Undebit</b> command to increase the
   * current SV balance or to partially or totally cancels the last SV debit command and using the
   * provided additional data.
   *
   * <p>It consists in decreasing the current balance of the SV by a certain amount or canceling a
   * previous debit according to the type operation chosen in when invoking the previous SV Get
   * command.
   *
   * <p>Note #1: a communication with the SAM is done here.
   *
   * <p>Note #2: the key used is the reload key.
   *
   * @param amount The amount to be subtracted or added, positive integer in the range 0..32767 when
   *     subtracted and 0..32768 when added.
   * @param date 2-byte free value.
   * @param time 2-byte free value.
   * @return The object instance.
   * @since 2.0
   */
  PoTransactionService prepareSvDebit(int amount, byte[] date, byte[] time);

  /**
   * Schedules the execution of a <b>SV Debit</b> or <b>SV Undebit</b> command to increase the
   * current SV balance or to partially or totally cancels the last SV debit command.
   *
   * <p>It consists in decreasing the current balance of the SV by a certain amount or canceling a
   * previous debit.
   *
   * <p>Note #1: the optional SV additional data are set to zero.
   *
   * <p>Note #2: a communication with the SAM is done here.
   *
   * <p>Note #3: the key used is the reload key.The information fields such as date and time are set
   * to 0. The extraInfo field propagated in Logs are automatically generated with the type of
   * transaction and amount.
   *
   * <p>Note #4: operations that would result in a negative balance are forbidden (SV Exception
   * raised).
   *
   * <p>Note #5: the key used is the debit key
   *
   * @param amount The amount to be subtracted or added, positive integer in the range 0..32767 when
   *     subtracted and 0..32768 when added.
   * @return The Object instance.
   * @since 2.0
   */
  PoTransactionService prepareSvDebit(int amount);

  /**
   * Schedules the execution of <b>Read Records</b> commands to read all SV logs.
   *
   * <p>The SV transaction logs are contained in two files with fixed identifiers:
   *
   * <ul>
   *   <li>The file whose SFI is 0x14 contains 1 record containing the unique reload log.
   *   <li>The file whose SFI is 0x15 contains 3 records containing the last three debit logs.
   * </ul>
   *
   * <p>At the end of this reading operation, the data will be accessible in CalypsoCard in raw
   * format via the standard commands for accessing read files or in the form of dedicated objects
   * (see {@link CalypsoCard#getSvLoadLogRecord()} and {@link
   * CalypsoCard#getSvDebitLogAllRecords()})
   *
   * <p>Once this command is processed, the result is available in {@link CalypsoCard}.
   *
   * <p>See the methods {@link CalypsoCard#getSvBalance()}, {@link CalypsoCard#getSvLoadLogRecord()}
   * ()}, {@link CalypsoCard#getSvDebitLogLastRecord()}, {@link
   * CalypsoCard#getSvDebitLogAllRecords()}. *
   *
   * @return The Object instance.
   * @since 2.0
   */
  PoTransactionService prepareSvReadAllLogs();

  /**
   * Schedules the execution of a <b>Invalidate</b> command.
   *
   * <p>This command is usually executed within a secure session with the SESSION_LVL_DEBIT key
   * (depends on the access rights given to this command in the file structure of the PO).
   *
   * @throws CalypsoPoTransactionIllegalStateException If the PO is already invalidated.
   * @return The Object instance.
   * @since 2.0
   */
  PoTransactionService prepareInvalidate();

  /**
   * Schedules the execution of a <b>Rehabilitate</b> command.
   *
   * <p>This command is usually executed within a secure session with the SESSION_LVL_PERSO key
   * (depends on the access rights given to this command in the file structure of the PO).
   *
   * @return The Object instance.
   * @throws CalypsoPoTransactionIllegalStateException If the PO is not invalidated.
   * @since 2.0
   */
  PoTransactionService prepareRehabilitate();

  /**
   * The PO Transaction Access Level: personalization, loading or debiting.
   *
   * @since 2.0
   */
  public enum SessionAccessLevel {

    /** Session Access Level used for personalization purposes. */
    SESSION_LVL_PERSO("perso", (byte) 0x01),
    /** Session Access Level used for reloading purposes. */
    SESSION_LVL_LOAD("load", (byte) 0x02),
    /** Session Access Level used for validating and debiting purposes. */
    SESSION_LVL_DEBIT("debit", (byte) 0x03);

    private final String name;
    private final byte sessionKey;

    SessionAccessLevel(String name, byte sessionKey) {
      this.name = name;
      this.sessionKey = sessionKey;
    }

    public String getName() {
      return name;
    }

    public byte getSessionKey() {
      return sessionKey;
    }
  }

  /**
   * Defines the Stored Value transactions parameters.
   *
   * @since 2.0
   */
  class SvSettings {
    /**
     * Defines the type of Stored Value operation to be performed.
     *
     * @since 2.0
     */
    public enum Operation {
      /** Increase the balance of the stored value */
      RELOAD,
      /** Decrease the balance of the stored value */
      DEBIT
    }

    /**
     * Defines the type Stored Value of action.
     *
     * @since 2.0
     */
    public enum Action {
      /**
       * In the case of a {@link Operation#RELOAD}, loads a positive amount; in the case of a {@link
       * Operation#DEBIT}, debits a positive amount
       */
      DO,
      /**
       * In the case of a {@link Operation#RELOAD}, loads a negative amount; in the case of a {@link
       * Operation#DEBIT}, cancels, totally or partially, a previous debit.
       */
      UNDO
    }
  }
}
