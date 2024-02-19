/**
 * Copyright: DAASI International GmbH 2020-2020. All rights reserved.
 *
 * This is Open Source Software
 * License: Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 *
 * Author: Tamim Ziai DAASI International GmbH, www.daasi.de
 * For questions please mail to info@daasi.de
 */
package com.example.midpoint.service.utils;

import com.evolveum.midpoint.schema.SchemaConstantsGenerated;

import com.fasterxml.jackson.databind.JsonNode;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.types.UserResource;
import com.unboundid.scim2.common.utils.JsonUtils;
import org.apache.commons.lang3.StringUtils;

import javax.xml.namespace.QName;
import java.util.List;

public class ExtendedUserResource {

	public static String SCIM_SCHEMA_CORE_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
	public static String SCIM_SCHEMA_EXTENDED = "urn:ietf:params:scim:schemas:extension:2.0:User";
	public static final QName F_OID = new QName(SchemaConstantsGenerated.NS_COMMON, "oid");
	public static final QName F_ACTIVATION = new QName(SchemaConstantsGenerated.NS_COMMON, "activation");
	public static final QName F_EFFECTIVE_STATUS = new QName(SchemaConstantsGenerated.NS_COMMON, "effectiveStatus");

	public static final String CONF_MAP_SCIM = "scim";
	public static final String CONF_MAP_MIDPOINT = "midpoint";
	public static final String CONF_MAP_IDENTIFIER = "asIdentifier";
	public static final String CONF_MAP_UNIQUE = "isUnique";

	public static void addExtensionValueToUserRessource(UserResource resource, String path, Object value) throws ScimException {
		String nameSpace = SCIM_SCHEMA_EXTENDED;

		if (path != null) {
			if (path.indexOf(":") > 0) {
				nameSpace = StringUtils.substringBeforeLast(path, ":");
				if (SCIM_SCHEMA_CORE_USER.equals(nameSpace)) {
					path = StringUtils.substringAfterLast(path, ":");
				}
			} else if (!path.startsWith(nameSpace)) {
				path = nameSpace + ":" + path;
			}
		}
		resource.replaceExtensionValue(path, JsonUtils.valueToNode(value));
		resource.getSchemaUrns().add(nameSpace);
	}

	public static List<JsonNode> getExtensionValueFromUserRessource(UserResource resource, String path) throws ScimException {
		String nameSpace = SCIM_SCHEMA_EXTENDED;
		if (path != null) {
			if (path.indexOf(":") > 0) {
				nameSpace = StringUtils.substringBeforeLast(path, ":");
			}

			if (!path.startsWith(nameSpace)) {
				path = nameSpace + ":" + path;
			}
		}
		return resource.getExtensionValues(path);
	}

}
