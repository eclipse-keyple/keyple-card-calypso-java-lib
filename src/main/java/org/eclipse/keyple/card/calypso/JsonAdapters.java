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

import static org.eclipse.keyple.card.calypso.DtoAdapters.*;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import java.lang.reflect.Type;
import org.eclipse.keypop.calypso.card.card.*;

/**
 * Contains all JSON adapters used for serialization and deserialization processes.<br>
 * These adapters are required for interfaces and abstract classes.
 *
 * @since 2.2.3
 */
final class JsonAdapters {

  private static final String TYPE = "type";
  private static final String DATA = "data";
  private static final String UNKNOWN_TYPE_TEMPLATE = "Unknown type: %s";

  private JsonAdapters() {}

  /**
   * JSON serializer/deserializer of a {@link DirectoryHeader}.
   *
   * @since 2.0.0
   */
  static final class DirectoryHeaderJsonAdapter
      implements JsonSerializer<DirectoryHeaderAdapter>, JsonDeserializer<DirectoryHeaderAdapter> {

    /**
     * {@inheritDoc}
     *
     * @since 2.1.1
     */
    @Override
    public JsonElement serialize(
        DirectoryHeaderAdapter src, Type typeOfSrc, JsonSerializationContext context) {
      return context.serialize(src);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public DirectoryHeaderAdapter deserialize(
        JsonElement json, Type typeOfT, JsonDeserializationContext context)
        throws JsonParseException {
      return context.deserialize(json, DirectoryHeaderAdapter.class);
    }
  }

  /**
   * JSON serializer/deserializer of a {@link ElementaryFile}.
   *
   * @since 2.0.0
   */
  static final class ElementaryFileJsonAdapter
      implements JsonSerializer<ElementaryFileAdapter>, JsonDeserializer<ElementaryFileAdapter> {

    /**
     * {@inheritDoc}
     *
     * @since 2.1.1
     */
    @Override
    public JsonElement serialize(
        ElementaryFileAdapter src, Type typeOfSrc, JsonSerializationContext context) {
      return context.serialize(src);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public ElementaryFileAdapter deserialize(
        JsonElement json, Type typeOfT, JsonDeserializationContext context)
        throws JsonParseException {
      return context.deserialize(json, ElementaryFileAdapter.class);
    }
  }

  /**
   * JSON serializer/deserializer of a {@link FileHeader}.
   *
   * @since 2.0.0
   */
  static final class FileHeaderJsonAdapter
      implements JsonSerializer<FileHeaderAdapter>, JsonDeserializer<FileHeaderAdapter> {

    /**
     * {@inheritDoc}
     *
     * @since 2.1.1
     */
    @Override
    public JsonElement serialize(
        FileHeaderAdapter src, Type typeOfSrc, JsonSerializationContext context) {
      return context.serialize(src);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public FileHeaderAdapter deserialize(
        JsonElement json, Type typeOfT, JsonDeserializationContext context)
        throws JsonParseException {
      return context.deserialize(json, FileHeaderAdapter.class);
    }
  }

  /**
   * JSON serializer/deserializer of a {@link SvLoadLogRecord}.
   *
   * @since 2.0.0
   */
  static final class SvLoadLogRecordJsonAdapter
      implements JsonSerializer<SvLoadLogRecordAdapter>, JsonDeserializer<SvLoadLogRecordAdapter> {

    /**
     * {@inheritDoc}
     *
     * @since 2.1.1
     */
    @Override
    public JsonElement serialize(
        SvLoadLogRecordAdapter src, Type typeOfSrc, JsonSerializationContext context) {
      return context.serialize(src);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public SvLoadLogRecordAdapter deserialize(
        JsonElement json, Type typeOfT, JsonDeserializationContext context)
        throws JsonParseException {
      return context.deserialize(json, SvLoadLogRecordAdapter.class);
    }
  }

  /**
   * JSON serializer/deserializer of a {@link SvDebitLogRecord}.
   *
   * @since 2.0.0
   */
  static final class SvDebitLogRecordJsonAdapter
      implements JsonSerializer<SvDebitLogRecordAdapter>,
          JsonDeserializer<SvDebitLogRecordAdapter> {

    /**
     * {@inheritDoc}
     *
     * @since 2.1.1
     */
    @Override
    public JsonElement serialize(
        SvDebitLogRecordAdapter src, Type typeOfSrc, JsonSerializationContext context) {
      return context.serialize(src);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    @Override
    public SvDebitLogRecordAdapter deserialize(
        JsonElement json, Type typeOfT, JsonDeserializationContext context)
        throws JsonParseException {
      return context.deserialize(json, SvDebitLogRecordAdapter.class);
    }
  }

  /**
   * JSON serializer/deserializer of a {@link Command}.
   *
   * @since 2.2.3
   */
  static final class AbstractCardCommandJsonAdapter
      implements JsonSerializer<Command>, JsonDeserializer<Command> {

    /**
     * {@inheritDoc}
     *
     * @since 2.2.3
     */
    @Override
    public JsonElement serialize(Command src, Type typeOfSrc, JsonSerializationContext context) {
      JsonObject jsonObject = new JsonObject();
      jsonObject.addProperty(TYPE, src.getClass().getName());
      jsonObject.add(DATA, context.serialize(src));
      return jsonObject;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.3
     */
    @Override
    public Command deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
        throws JsonParseException {
      JsonObject jsonObject = json.getAsJsonObject();
      String type = jsonObject.get(TYPE).getAsString();
      JsonObject data = jsonObject.get(DATA).getAsJsonObject();
      Command command;
      try {
        Class<?> classOfData = Class.forName(type);
        command = context.deserialize(data, classOfData);
      } catch (ClassNotFoundException e) {
        throw new JsonParseException(String.format(UNKNOWN_TYPE_TEMPLATE, type));
      }
      return command;
    }
  }
}
