/**
 * Copyright: DAASI International GmbH 2020-2020. All rights reserved.
 *
 * This is Open Source Software
 * License: Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 *
 * Author: DAASI International GmbH, www.daasi.de
 * For questions please mail to info@daasi.de
 */
package com.example.midpoint.service;

import java.util.*;
import javax.xml.namespace.QName;

import com.example.midpoint.service.exception.Scim2WebServiceBadRequestException;
import com.example.midpoint.service.exception.Scim2WebServiceInternalErrorException;
import com.example.midpoint.service.model.ExtendedQName;
import com.example.midpoint.service.utils.ExtendedUserResource;
import org.apache.commons.configuration2.Configuration;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import com.evolveum.midpoint.common.configuration.api.MidpointConfiguration;
import com.evolveum.midpoint.prism.Definition;
import com.evolveum.midpoint.prism.ItemDefinition;
import com.evolveum.midpoint.prism.PrismContext;
import com.evolveum.midpoint.prism.impl.ComplexTypeDefinitionImpl;
import com.evolveum.midpoint.prism.schema.PrismSchema;
import com.evolveum.midpoint.schema.SchemaConstantsGenerated;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;

class Scim2WebServiceConfig {

    private static final Trace LOGGER = TraceManager.getTrace(Scim2WebServiceConfig.class);

    private Integer maxResultSize;

    private Integer defaultResultSize;

    private List<String> nameSpaces;

    private Map<ExtendedQName, ExtendedQName> fromScimAttributesMapping;

    private Map<ExtendedQName, ExtendedQName> toScimAttributesMapping;

    private ExtendedQName additionalEMailAttribute;

    private Map<QName, ItemDefinition<?>> extendedAttributes;

    private ExtendedQName identifierQName;

    private String identifierRegExp;

    private String baseUri;

    private Boolean enableAuditLogin;

    private transient MidpointConfiguration configuration;

    private transient PrismContext prismContext;

    Scim2WebServiceConfig( MidpointConfiguration configuration, PrismContext prismContext ) {
        this.configuration = configuration;
        this.prismContext = prismContext;
    }

    String getBaseUri() {
        return baseUri;
    }

    void setBaseUri(String baseUri) {
        if (this.baseUri == null) {
            this.baseUri = getConfiguredBaseUri(baseUri);
        }
    }

    private boolean readBooleanParameterOrDefault( String parameterName, boolean defaultValue ) {
        if (configuration != null) {
            Configuration config = configuration.getConfiguration( "midpoint.scim2Service" );
            if (config == null) {
                LOGGER.warn("No configuration available. Set {} to {}", parameterName, defaultValue);
            } else {
                boolean value = config.getBoolean(parameterName, defaultValue);
                LOGGER.info("Set {} to {}", parameterName, value);
                return value;
            }
        }
        return defaultValue;
    }

    private String readStringParameterOrDefault( String parameterName, String defaultValue ) {
        if (configuration != null) {
            Configuration config = configuration.getConfiguration( "midpoint.scim2Service" );
            if (config == null) {
                LOGGER.warn("No configuration available. Set {} to {}", parameterName, defaultValue);
            } else {
                String value = config.getString(parameterName, defaultValue);
                LOGGER.info("Set {} to {}", parameterName, value);
                return value;
            }
        }
        return defaultValue;
    }

    private int readIntParameterOrDefault( String parameterName, int defaultValue ) {
        if (configuration != null) {
            Configuration config = configuration.getConfiguration( "midpoint.scim2Service" );
            if (config == null) {
                LOGGER.warn("No configuration available. Set {} to {}", parameterName, defaultValue);
            } else {
                int value = config.getInt(parameterName, defaultValue);
                LOGGER.info("Set {} to {}", parameterName, value);
                return value;
            }
        }
        return defaultValue;
    }

    boolean isEnableAuditLogin() {
        if( null == enableAuditLogin ) {
            enableAuditLogin = readBooleanParameterOrDefault( "enableAuditLogin", true );
        }
        return enableAuditLogin;
    }

    /**
     * Returns the configured max size or the default value.
     *
     * @return
     */
    int getMaxResultSize() {
        if (maxResultSize == null) {
            maxResultSize = readIntParameterOrDefault( "maxResultSize", 1000 );
        }
        return maxResultSize;
    }

    /**
     * Returns the configured default size or the default value.
     *
     * @return
     */
    int getDefaultResultSize() {
        if (defaultResultSize == null) {
            defaultResultSize = readIntParameterOrDefault( "defaultResultSize", getMaxResultSize() );
        }
        return defaultResultSize;
    }

    ExtendedQName getIdentifierQName() {
        return this.identifierQName;
    }

    /**
     * Returns the configured regular expression.
     *
     * @return
     */
    String getIdentifierRegExp() {
        if (identifierRegExp == null) {
            identifierRegExp = readStringParameterOrDefault( "identifierRegExp", "" );
        }
        return identifierRegExp;
    }

    /**
     * Returns the configured base uri.
     *
     * @param baseUri default value
     * @return
     */
    String getConfiguredBaseUri(String baseUri) {
        if (this.baseUri == null) {
            this.baseUri = readStringParameterOrDefault( "baseUri", baseUri );
        }
        return this.baseUri;
    }

    /**
     * Retruns the configured additional mails attribute
     * @return configured mails attribute or null of not configured
     */
    QName getConfiguredAdditionalEMailAttribute() {
        if (this.additionalEMailAttribute == null) {
            String confUrn = readStringParameterOrDefault( "additionalEMailAttribute", "" );
            additionalEMailAttribute = buildMapping(confUrn, "");
            LOGGER.info("Set additionalEMailAttribute to {}", additionalEMailAttribute);
        }
        return this.additionalEMailAttribute;
    }

    /**
     * Returns the configured name space.
     *
     * @return
     */
    List<String> getNameSpaces() {
        if (nameSpaces == null) {
            nameSpaces = new ArrayList<>();
            nameSpaces.add("http://example.com/xml/ns/mySchema");
            if (configuration != null) {
                Configuration config = configuration.getConfiguration("midpoint.scim2Service");
                if (config != null) {
                    List<String> defaultNameSpaces = new ArrayList<>();
                    defaultNameSpaces.add("http://example.com/xml/ns/mySchema");
                    List<Object> nameSpacesObjList = config.getList("nameSpace", defaultNameSpaces);
                    nameSpaces.clear();
                    for (Object nameSpacesObj : nameSpacesObjList) {
                        nameSpaces.add(Objects.toString(nameSpacesObj));
                    }
                    ExtendedUserResource.SCIM_SCHEMA_EXTENDED = config.getString("scimNameSpace",
                                                                                 ExtendedUserResource.SCIM_SCHEMA_EXTENDED);
                }
            }
            LOGGER.info("Set nameSpaces to {}", nameSpaces);
            LOGGER.info("Set scimNameSpaces to {}", ExtendedUserResource.SCIM_SCHEMA_EXTENDED);
        }
        return nameSpaces;
    }

    /**
     * Returns the configured SCIM to midPoint attributes mapping.
     *
     * @return
     */
    Map<ExtendedQName, ExtendedQName> getFromScimAttributesMapping() throws Scim2WebServiceException {
        if (fromScimAttributesMapping == null) {
            if (configuration != null) {
                Configuration config = configuration.getConfiguration("midpoint.scim2Service.attributeMapping.map");
                if (config != null) {
                    Map<String, List<String>> mappings = getMappings(config);
                    fromScimAttributesMapping = new HashMap<ExtendedQName, ExtendedQName>();
                    toScimAttributesMapping = new HashMap<ExtendedQName, ExtendedQName>();
                    if (mappings.isEmpty()) {
                        LOGGER.warn("No attribute mapping found.");
                    } else {
                        List<String> scimList = mappings.get(ExtendedUserResource.CONF_MAP_SCIM);
                        List<String> midpointList = mappings.get(ExtendedUserResource.CONF_MAP_MIDPOINT);
                        List<String> identifierList = mappings.get(ExtendedUserResource.CONF_MAP_IDENTIFIER);
                        List<String> uniqueList = mappings.get(ExtendedUserResource.CONF_MAP_UNIQUE);

                        for (int i = 0; i < scimList.size(); i++) {
                            boolean isIdentifier = false;
                            boolean isUnique = false;
                            if (identifierList != null) {
                                isIdentifier = Boolean.parseBoolean(identifierList.get(i));
                            }
                            if (uniqueList != null) {
                                isUnique = Boolean.parseBoolean(uniqueList.get(i));
                            }
                            ExtendedQName toScimMapping = buildMapping(midpointList.get(i),
                                                                       ExtendedUserResource.SCIM_SCHEMA_CORE_USER);
                            toScimMapping.setUnique(isUnique);
                            ExtendedQName fromScimMapping = buildMapping(scimList.get(i),
                                                                         SchemaConstantsGenerated.NS_COMMON);
                            fromScimMapping.setUnique(isUnique);

                            if (isIdentifier) {
                                identifierQName = new ExtendedQName(toScimMapping.getNamespaceURI(),
                                                                    toScimMapping.getLocalPart());
                            }

                            toScimAttributesMapping.put(new ExtendedQName(toScimMapping.getNamespaceURI(),
                                                                          toScimMapping.getLocalPart(), isUnique), fromScimMapping);
                            fromScimAttributesMapping.put(new ExtendedQName(fromScimMapping.getNamespaceURI(),
                                                                            fromScimMapping.getLocalPart(), isUnique), toScimMapping);
                        }
                    }
                }
            }
            LOGGER.info("Set SCIM to midPoint attributes mapping to {}", fromScimAttributesMapping);
        }
        return fromScimAttributesMapping;
    }


    ExtendedQName buildMapping(String value, String nameSpace) {
        if (value.indexOf(":") >= 0) {
            nameSpace = StringUtils.substringBeforeLast(value, ":");
            value = StringUtils.substringAfterLast(value, ":");
        }
        return new ExtendedQName(nameSpace, value);
    }

    Map<String, List<String>> getMappings(Configuration config) throws Scim2WebServiceException {
        Iterator<?> iterator = config.getKeys();
        Map<String, List<String>> mappings = new HashMap<String, List<String>>();
        int lastSize = -1;
        while (iterator.hasNext()) {
            String key = iterator.next().toString();
            key = key.substring(key.lastIndexOf(":") + 1);
            if (key != null && !key.isEmpty() && !key.startsWith("midpoint.")) {
                List<String> values = new ArrayList<>();
                for (Object valObj : config.getList(key)) {
                    values.add(Objects.toString(valObj));
                }

                if (values != null && !values.isEmpty()) {
                    if (lastSize == -1 || lastSize == values.size()) {
                        mappings.put(key, values);
                        lastSize = values.size();
                    } else {
                        mappings.clear();
                        throw new Scim2WebServiceInternalErrorException(
                            "Bad configuration: all mappings must have the same nodes but '" + key + "' doesn't."
                                + " No attribute mapping will be available.",
                            "fatal");
                    }
                }
            }
        }
        if (!mappings.isEmpty() && (!mappings.containsKey(ExtendedUserResource.CONF_MAP_SCIM)
            || !mappings.containsKey(ExtendedUserResource.CONF_MAP_MIDPOINT))) {
            mappings.clear();
            throw new Scim2WebServiceInternalErrorException(
                "Bad configuration: either scim or midpoint mapping is missing.", "fatal");
        } else if (mappings.containsKey(ExtendedUserResource.CONF_MAP_IDENTIFIER)) {
            boolean found = false;
            for (String value : mappings.get(ExtendedUserResource.CONF_MAP_IDENTIFIER)) {
                if (Boolean.parseBoolean(value)) {
                    if (found) {
                        mappings.clear();
                        throw new Scim2WebServiceInternalErrorException("More than one identifier specified.", "fatal");
                    } else {
                        found = true;
                    }
                }
            }
        }
        return mappings;
    }

    /**
     * Returns the configured midPoint to SCIM attributes mapping.
     *
     * @return
     */
    Map<ExtendedQName, ExtendedQName> getToScimAttributesMapping() throws Scim2WebServiceException {
        if (toScimAttributesMapping == null) {
            getFromScimAttributesMapping();
            LOGGER.info("Set midPoint to SCIM attributes mapping to {}", toScimAttributesMapping);
        }
        return toScimAttributesMapping;
    }

    Map<QName, ItemDefinition<?>> getExtendedAttributes() {
        if (extendedAttributes == null) {
            extendedAttributes = buildExtendedAttributes();
        }
        return extendedAttributes;
    }

    protected Map<QName, ItemDefinition<?>> buildExtendedAttributes() {
        Map<QName, ItemDefinition<?>> attrs = new HashMap<QName, ItemDefinition<?>>();
        if (prismContext != null) {
            for (String nameSpace : getNameSpaces()) {
                PrismSchema schema = prismContext.getSchemaRegistry().getPrismSchema(nameSpace);
                if (schema != null && schema.getDefinitions() != null) {
                    Iterator<Definition> iterator = schema.getDefinitions().iterator();
                    while (iterator.hasNext()) {
                        Object typeDefinition = iterator.next();
                        if (typeDefinition instanceof ComplexTypeDefinitionImpl) {
                            List<? extends ItemDefinition> definitions = ((ComplexTypeDefinitionImpl) typeDefinition)
                                .getDefinitions();
                            for (ItemDefinition<?> definition : definitions) {
                                QName qName = definition.getItemName();
                                attrs.put(qName, definition);
                            }
                        }
                    }
                } else {
                    LOGGER.warn("No schema registration or no definitions found for name space '{}'", nameSpace);
                }
            }
        }
        return attrs;
    }

    /**
     * Maps midPoint attribute name to SCIM attribute name.
     *
     * @param midpointAttr
     * @return
     */
    protected String mapAttrToScim(QName midpointAttr) throws Scim2WebServiceException {
        String scimAttr = midpointAttr.getLocalPart();
        if (getToScimAttributesMapping().containsKey(midpointAttr)) {
            QName mapping = getToScimAttributesMapping().get(midpointAttr);
            scimAttr = toPropertyName(mapping);
        }
        return scimAttr;
    }

    /**
     * Maps midPoint attribute name to SCIM attribute name.
     * @param scimAttr
     * @return
     */
    protected String mapAttrFromScim(String scimAttr) throws Scim2WebServiceException {
        //		scimAttr = filterOutNameSpace(scimAttr);
        Pair<String, String> nameSpaceAttrName = buildNameSpaceAttrNamePair(scimAttr);
        String midpointAttr = nameSpaceAttrName.getRight();
        QName qName = new QName(nameSpaceAttrName.getLeft(), nameSpaceAttrName.getRight());
        if (getFromScimAttributesMapping().containsKey(qName)) {
            QName mapping = getFromScimAttributesMapping().get(qName);
            midpointAttr = toPropertyName(mapping);
        } else {
            throw new Scim2WebServiceBadRequestException("No mapping found for property " + toPropertyName(qName),
                                                         "configuration");
        }
        return midpointAttr;
    }

    private Pair<String, String> buildNameSpaceAttrNamePair(String scimAttr) {
        String nameSpace = ExtendedUserResource.SCIM_SCHEMA_CORE_USER;
        if (scimAttr.indexOf(":") >= 0) {
            nameSpace = StringUtils.substringBeforeLast(scimAttr, ":");
            scimAttr = StringUtils.substringAfterLast(scimAttr, ":");
        }

        return new ImmutablePair<String, String>(nameSpace, scimAttr);
    }

    /**
     * Filters out the schema name from the attribute name.
     *
     * @param scimAttr
     * @return
     */
    protected String filterOutNameSpace(String scimAttr) throws Scim2WebServiceException {
        for (QName mapping : getToScimAttributesMapping().values()) {
            String nameSpace = mapping.getNamespaceURI();
            String attrName = mapping.getLocalPart();
            if (scimAttr.endsWith(attrName) && scimAttr.startsWith(nameSpace)) {
                scimAttr = scimAttr.substring(nameSpace.length() + 1);
                break;
            }
        }
        return scimAttr;
    }

    static String toPropertyName(QName qName) {
        String result = "";
        if (qName != null) {
            result = qName.getNamespaceURI() + ":" + qName.getLocalPart();
        }
        return result;
    }

}
