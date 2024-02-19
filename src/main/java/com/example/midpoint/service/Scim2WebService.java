/**
 * Copyright: DAASI International GmbH 2020-2020. All rights reserved.
 *
 * This is Open Source Software
 * License: Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 *
 * Author: Tamim Ziai DAASI International GmbH, www.daasi.de
 * For questions please mail to info@daasi.de
 */
package com.example.midpoint.service;

import static com.unboundid.scim2.common.utils.ApiConstants.MEDIA_TYPE_SCIM;

import java.beans.IntrospectionException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.*;
import java.util.Map.Entry;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;

import com.example.midpoint.service.exception.*;
import com.example.midpoint.service.model.ExtendedQName;
import com.example.midpoint.service.utils.ExtendedUserResource;
import com.example.midpoint.service.utils.XMLGregorianCalendarMatchingRule;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.filters.Filter;
import com.unboundid.scim2.common.filters.FilterType;
import com.unboundid.scim2.common.messages.*;
import com.unboundid.scim2.common.types.*;
import com.unboundid.scim2.common.types.AttributeDefinition.Builder;
import com.unboundid.scim2.common.types.AttributeDefinition.Type;
import com.unboundid.scim2.common.types.AttributeDefinition.Uniqueness;
import com.unboundid.scim2.common.utils.JsonUtils;
import com.unboundid.scim2.common.utils.Parser;
import com.unboundid.scim2.common.utils.SchemaUtils;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.Response.StatusType;
import jakarta.ws.rs.core.UriInfo;
import org.apache.commons.configuration2.Configuration;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.apache.commons.lang3.time.StopWatch;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.evolveum.midpoint.audit.api.AuditService;
import com.evolveum.midpoint.common.configuration.api.MidpointConfiguration;
import com.evolveum.midpoint.model.api.ModelService;
import com.evolveum.midpoint.model.impl.security.SecurityHelper;
import com.evolveum.midpoint.prism.*;
import com.evolveum.midpoint.prism.delta.DeltaFactory;
import com.evolveum.midpoint.prism.delta.ItemDelta;
import com.evolveum.midpoint.prism.delta.ObjectDelta;
import com.evolveum.midpoint.prism.delta.PropertyDelta;
import com.evolveum.midpoint.prism.impl.query.SubstringFilterImpl;
import com.evolveum.midpoint.prism.impl.xjc.JaxbTypeConverter;
import com.evolveum.midpoint.prism.match.MatchingRuleRegistry;
import com.evolveum.midpoint.prism.path.ItemPath;
import com.evolveum.midpoint.prism.polystring.PolyString;
import com.evolveum.midpoint.prism.query.ObjectFilter;
import com.evolveum.midpoint.prism.query.ObjectPaging;
import com.evolveum.midpoint.prism.query.ObjectQuery;
import com.evolveum.midpoint.prism.query.OrderDirection;
import com.evolveum.midpoint.rest.impl.AbstractRestController;
import com.evolveum.midpoint.schema.*;
import com.evolveum.midpoint.schema.constants.SchemaConstants;
import com.evolveum.midpoint.schema.result.OperationResult;
import com.evolveum.midpoint.schema.util.MiscSchemaUtil;
import com.evolveum.midpoint.security.api.SecurityContextManager;
import com.evolveum.midpoint.security.api.SecurityUtil;
import com.evolveum.midpoint.task.api.Task;
import com.evolveum.midpoint.task.api.TaskManager;
import com.evolveum.midpoint.util.DOMUtil;
import com.evolveum.midpoint.util.exception.*;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;
import com.evolveum.midpoint.xml.ns._public.common.common_3.*;
import com.evolveum.prism.xml.ns._public.types_3.PolyStringType;
import com.unboundid.scim2.server.annotations.ResourceType;


/**
 * A per resource life cycle Resource Endpoint implementation.
 */
@RequestMapping("/ws/services/scim2")
@ResourceType(description = "User Account", name = "User", schema = UserResource.class)
@Service
@RestController
public class Scim2WebService extends AbstractRestController {

	private static final Trace LOGGER = TraceManager.getTrace(Scim2WebService.class);

	private PrismObjectDefinition<? extends UserType> userDefinition;

	private ComplexTypeDefinition metadataDefinition;

	private ComplexTypeDefinition activationDefinition;

	private String scimSchemas;

	@Autowired(required = true)
	protected transient MidpointConfiguration configuration;

	@Autowired(required = true)
	protected ModelService modelService;

	@Autowired(required = true)
	protected PrismContext prismContext;

	@Autowired(required = true)
	protected MatchingRuleRegistry matchingRuleRegistry;

	@Autowired
	protected AuditService auditService;

    @Autowired
	protected SecurityContextManager securityContextManager;

	@Autowired
	protected SecurityHelper securityHelper;

	@Autowired
	protected TaskManager taskManager;

	protected Scim2WebServiceConfig config;

	protected void init(UriInfo ui) {
		try {
			this.config = new Scim2WebServiceConfig( configuration, prismContext );
			config.setBaseUri(ui.getBaseUri().toString());
			config.getExtendedAttributes();
			config.getFromScimAttributesMapping();
		} catch (Scim2WebServiceException se) {
			throw new RuntimeException(se);
		}
	}


	/**
	 * Retrieves a user object by it's name.
	 *
	 * @param id The oid of the resource to retrieve.
	 * @param attributes requested attributes
	 * @param excludedAttributes excluded attributes
	 * @param ui User info
	 * @return The result as SimpleSearchResults<UserResource>
	 * @throws ScimException
	 */
	@Path("/Users/{id}")
	@GET
	@Produces({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	public Response getUser(@PathParam("id") final String id,
							@QueryParam("attributes") final String attributes,
							@QueryParam("excludedAttributes") final String excludedAttributes,
							@Context UriInfo ui) {

		Validate.notEmpty(id, "No id in person");
		init(ui);

		Response response;
		Task task = initRequest();
		//Task task = createTaskInstance(Scim2WebService.class.getName() + OPERATION_NAME);
		//auditLogin(task);
		OperationResult result = task.getResult();
		try {
			Map<ExtendedQName, ExtendedQName> mappingSubSet = buildAttributeMappingSubset(attributes, excludedAttributes);

			PrismObject<UserType> userType = getUser(id, task, result);

			if (userType != null) {
				UserResource resource = mapToUserResource(userType, mappingSubSet );

				LOGGER.debug("returning:\n{}", resource);
				response = Response.status(Status.OK).header("Location", getUserLocationUri(userType.getOid()))
						.entity(resource.toString()).build();
			} else {
				LOGGER.info("No resource found with ID " + id);
				response = buildScimError(Status.NOT_FOUND, "No resource found with ID " + id, null);
			}

		} catch (Scim2WebServiceException se) {
			LOGGER.warn(se.getMessage(), se);
			response = buildScimError(se.getStatus(), se.getMessage(), se.getScimDetail());
		} catch (ObjectNotFoundException e) {
			LOGGER.warn(e.getMessage(), e);
			response = buildScimError(Status.NOT_FOUND, "No resource found with ID " + id, null);
		} catch (Exception e) {
			LOGGER.error("Internal error", e);
			response = buildScimError(Status.INTERNAL_SERVER_ERROR, e.getMessage(), null);
		}
		result.computeStatus();
		//RestServiceUtil.finishRequest(task, securityHelper);

		return response;
	}

	/**
	 * Retrieves self.
	 *
	 * @param id The oid of the resource to retrieve.
	 * @param attributes requested attributes
	 * @param excludedAttributes excluded attributes
	 * @param ui User info
	 * @return The result as SimpleSearchResults<UserResource>
	 * @throws ScimException
	 */

	@Path("/Me")
	@GET
	@Produces({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	public Response getMe(
			@QueryParam("attributes") final String attributes,
			@QueryParam("excludedAttributes") final String excludedAttributes,
			@Context UriInfo ui) {

		Response response;

		try {
			FocusType loggedInUser;
			loggedInUser = SecurityUtil.getPrincipal().getFocus();
			response = getUser(loggedInUser.getOid(), attributes, excludedAttributes, ui);
		} catch (SecurityViolationException e) {
			response = buildScimError(Status.UNAUTHORIZED, e.getMessage(), null);
		}

		return response;
	}

	/**
	 * Builds a copy of the ToScimAttributesMapping Map with the specified Attributes.
	 * If both given attributes are null or empty null is returned. If both are not empty an exception is thrown.
	 * @param attributes A coma separated list in a string containing the wanted attributes
	 * @param excludedAttributes A coma separated list in a string containing the attributes to be excluded
	 */
	private Map<ExtendedQName, ExtendedQName> buildAttributeMappingSubset(String attributes, String excludedAttributes) throws Scim2WebServiceException {

		if( StringUtils.isBlank( attributes ) && StringUtils.isBlank( excludedAttributes ) ) {
			return null;
		}

		if (StringUtils.isNotBlank( attributes ) && StringUtils.isNotBlank( excludedAttributes )) {
			throw new Scim2WebServiceBadRequestException( "Parameters attributes and excludedAttributes are mutually exclusive", null);
		}

		if (StringUtils.isNotBlank( attributes )) {
			return buildAttributeMappingSubsetFromAttributes(attributes, false);
		} else {
			return buildAttributeMappingSubsetFromAttributes(excludedAttributes, true);
		}
	}

	/**
	 * Helper for  buildAttributeMappingSubset
	 * @param attributes either excludedAttributes- or attributes-String depending on boolean exclude
	 * @param exclude tells if attributes should be excluded (true) or added (false) to the returned mapping
	 * @return
	 * @throws Scim2WebServiceException
	 */
	private Map<ExtendedQName, ExtendedQName> buildAttributeMappingSubsetFromAttributes(String attributes, boolean exclude) throws Scim2WebServiceException {
		try {
			if (attributes.contains("emails")) {
				attributes = attributes + "," + config.getToScimAttributesMapping().get(
					config.getConfiguredAdditionalEMailAttribute()
				).getLocalPart();
			}
			String[] trimmedAttributes = attributes.replace("\"", "").replaceAll("\\s", "").split(",");

			Map<ExtendedQName, ExtendedQName> mapping = new HashMap<>();
			if(exclude) {
				mapping.putAll( config.getToScimAttributesMapping() );
			}
			for (String trimmedAttribute : trimmedAttributes) {
				boolean found = false;
				for (ExtendedQName key : config.getFromScimAttributesMapping().keySet() ) {
					if( LOGGER.isDebugEnabled() ) {
						LOGGER.debug( "Checking local name {} against attribute {}", key.getLocalPart(), trimmedAttribute );
					}
					if (key.getLocalPart().equalsIgnoreCase(trimmedAttribute)) {
						if(exclude) {
							mapping.remove( config.getFromScimAttributesMapping().get(key) );
						}
						else {
							mapping.put( config.getFromScimAttributesMapping().get(key), key);
						}
						found = true;
						break;
					}
				}
				if( !found ) {
					throw new Scim2WebServiceBadRequestException( "Attribute " + trimmedAttribute + " is unknown", "invalidAttribute" );
				}
			}

			return mapping;
		} catch (Scim2WebServiceBadRequestException e ) {
			throw e;
		} catch (Scim2WebServiceException e) {
			//This was swallowed previously. why?
			throw e;
		}
	}


	/**
	 * Searches user objects according to the filter in the payload.
	 *
	 * @param payload The scim json of the search.
	 * @param ui      User info
	 * @return The result as SimpleSearchResults<UserResource>
	 * @throws ScimException
	 */
	@Path("/Users/.search")
	@POST
	@Consumes({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	@Produces({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	public Response searchUser(final String payload, @Context UriInfo ui) throws ScimException {
		try {
			Validate.notEmpty(payload, "No payload");
		} catch (NullPointerException | IllegalArgumentException e) {
			LOGGER.warn(e.getMessage(), e);
			return buildScimError(Status.BAD_REQUEST, e.getMessage(), null);
		}

		Response response;
		SearchRequest resource;
		try {
			resource = JsonUtils.getObjectReader().forType(SearchRequest.class).readValue(payload);
			LOGGER.debug("search resource: {}", resource);
			String attributes = ( resource.getAttributes() == null || resource.getAttributes().isEmpty() ) ? null : StringUtils.join( resource.getAttributes(), ',' );
			String excludedAttributes = ( resource.getExcludedAttributes() == null || resource.getExcludedAttributes().isEmpty() ) ? null : StringUtils.join( resource.getExcludedAttributes(), ',' );
			response = searchUser(resource.getFilter(), resource.getStartIndex(), resource.getCount(),
					resource.getSortBy(), resource.getSortBy(),
					attributes, excludedAttributes, ui);
		} catch (JsonProcessingException e) {
			LOGGER.warn(e.getMessage(), e);
			response = buildScimError(Status.BAD_REQUEST, e.getMessage(), null);
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
			response = buildScimError(Status.INTERNAL_SERVER_ERROR, e.getMessage(), null);
		}

		return response;
	}

	/**
	 * Searches user objects according to the filter.
	 *
	 * @param filter     The search filter.
	 * @param startIndex The index of the first resource
	 * @param count      the page size
	 * @param sortBy     Sort attribute
	 * @param sortOrder  Sort order
	 * @param attributes requested attributes
	 * @param excludedAttributes excluded attributes
	 * @param ui         User info
	 * @return The result as SimpleSearchResults<UserResource>
	 * @throws ScimException
	 */
	@Path("/Users")
	@GET
	@Produces({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	public Response searchUser(@QueryParam("filter") final String filter,
			@QueryParam("startIndex") final Integer startIndex,
			@QueryParam("count") final Integer count,
			@QueryParam("sortBy") final String sortBy,
			@QueryParam("sortOrder") final String sortOrder,
			@QueryParam("attributes") final String attributes,
			@QueryParam("excludedAttributes") final String excludedAttributes,
			@Context UriInfo ui) throws ScimException {
		StopWatch sw = StopWatch.createStarted();
		init(ui);
		LOGGER.debug("STOPWATCH init {}", sw.getTime());
		Response response = Response.status(Status.OK).build();
		Task task = initRequest();
		//Task task = createTaskInstance(Scim2WebService.class.getName() + OPERATION_NAME);
		//auditLogin(task);
		//LOGGER.debug("STOPWATCH auditLogin {}", sw.getTime());
		OperationResult result = task.getResult();

		Filter scimFilter = null;

		/*
		 * Must not be > maxResultSize
		 */
		if (count != null && count > config.getMaxResultSize()) {
			response = buildScimError(Status.BAD_REQUEST, "Count must not exceed " + config.getMaxResultSize(), null);
		}
		if (response.getStatus() == Status.OK.getStatusCode() && filter != null) {
			try {
				scimFilter = Parser.parseFilter(filter);
			} catch (BadRequestException e) {
				response = buildScimError(Status.BAD_REQUEST, e.getMessage(), "invalidFilter");
			}
			LOGGER.debug("STOPWATCH parseFilter {}", sw.getTime());
		}
		if (response.getStatus() == Status.OK.getStatusCode() && sortOrder != null && !sortOrder.equals("ascending")
				&& !sortOrder.equals("descending")) {
			response = buildScimError(Status.BAD_REQUEST, "Sort order must be either 'ascending' or 'descending'",
					null);
		}
		Map<ExtendedQName, ExtendedQName> mappingSubSet = null;
		if( response.getStatus() == Status.OK.getStatusCode() ) {
			try {
				mappingSubSet = buildAttributeMappingSubset(attributes, excludedAttributes);
			} catch ( Scim2WebServiceException se ) {
				LOGGER.warn(se.getMessage(), se);
				response = buildScimError(se.getStatus(), se.getMessage(), se.getScimDetail());
			}
		}

		if (response.getStatus() == Status.OK.getStatusCode()) {
			LOGGER.debug("Filter = {}", scimFilter);
			response.close();
			try {
				String body = buildSearchResult(startIndex, count, sortBy, sortOrder, scimFilter, mappingSubSet, task, result);
				response = Response.status(Status.OK).entity(body).build();
			} catch (Scim2WebServiceException se) {
				LOGGER.warn(se.getMessage(), se);
				response.close();
				response = buildScimError(se.getStatus(), se.getMessage(), se.getScimDetail());
			} catch (Exception e) {
				LOGGER.error(e.getMessage(), e);
				response.close();
				response = buildScimError(Status.INTERNAL_SERVER_ERROR, e.getMessage(), null);
			}

			result.computeStatus();
			//RestServiceUtil.finishRequest(task, securityHelper);
		}
		LOGGER.debug("STOPWATCH search {}", sw.getTime());
		return response;
	}


	/**
	 * ResouceType User Endpoint
	 *
	 * @param ui UriInfo
	 * @throws ScimException Exception
	 */
	@Path("/ResourceTypes/{id}")
	@GET
	@Produces({MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON})
	public Response getResourceType(@PathParam("id") final String id, @Context UriInfo ui) throws ScimException {
		init(ui);
		Response response;
		if (!id.equals("User")) {
			response = buildScimError(Status.NOT_FOUND, "No resourceType found with ID " + id, null);
		} else {

			try {
				response = Response.status(Status.OK).entity(buildUserResourceType().toString()).build();
			} catch (Exception e) {
				response = buildScimError(Status.INTERNAL_SERVER_ERROR, e.getMessage(), null);
			}
		}

		return response;
	}

	/**
	 * Endpoint of ResourceTypes
	 *
	 * @param ui UriInfo
	 * @param filter filter Query Parameter
	 * @throws ScimException Exception
	 */
	@Path("/ResourceTypes")
	@GET
	@Produces({MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON})
	public Response getAllResourceTypes(@QueryParam("filter") final String filter, @Context UriInfo ui) throws ScimException {
		init(ui);
		Response response = null;
		if (filter != null) {
			return buildScimError(Status.FORBIDDEN, "clients could incorrectly assume\n" +
					"   that any matching conditions specified in a filter are true.", null);
		}
		try {
			response = Response.status(Status.OK).entity(CollectResourceTypes()).build();
		} catch (Exception e) {
			response = buildScimError(Status.INTERNAL_SERVER_ERROR, e.getMessage(), null);
		}

		return response;
	}


	/**
	 * Collects all ResourceType Endpoints
	 *
	 * @return Return the finished String with all ResourceTypes
	 * @throws URISyntaxException Exception
	 */
	protected String CollectResourceTypes() throws URISyntaxException {
		Collection<ResourceTypeResource> schemas = new ArrayList<>();
		schemas.add(buildUserResourceType());
		ListResponse<ResourceTypeResource> schemasResponse = new ListResponse<>(schemas);
		return schemasResponse.toString();
	}


	/**
	 * Builds the User ResouceType
	 *
	 * @return The ResourceType of the User
	 * @throws URISyntaxException Exception
	 */
	protected ResourceTypeResource buildUserResourceType() throws URISyntaxException {
		Collection<ResourceTypeResource.SchemaExtension> schemaExtensions = new ArrayList<>();
		ResourceTypeResource.SchemaExtension s = new ResourceTypeResource.SchemaExtension(new URI(ExtendedUserResource.SCIM_SCHEMA_EXTENDED), true);
		schemaExtensions.add(s);
		ResourceTypeResource userSchema = new ResourceTypeResource("User", "User",
				"User Account", new URI("/Users"), new URI(ExtendedUserResource.SCIM_SCHEMA_CORE_USER), schemaExtensions);
		Meta m = new Meta();
		m.setLocation(new URI(config.getBaseUri() + "/ResourceTypes/User"));
		m.setResourceType("ResourceType");
		userSchema.setMeta(m);

		return userSchema;
	}

	@Path("/Schemas")
	@GET
	@Produces({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	public Response getSchemas(@Context UriInfo ui) throws ScimException {
		init(ui);
		Response response = null;
		try {
			response = Response.status(Status.OK).entity(getScimSchemas()).build();
		} catch (Scim2WebServiceException e) {
			response = buildScimError(e.getStatus(), e.getMessage(), e.getScimDetail());
		} catch (Exception e) {
			response = buildScimError(Status.INTERNAL_SERVER_ERROR, e.getMessage(), null);
		}

		return response;
	}

	protected String getScimSchemas() throws IntrospectionException, Scim2WebServiceException {
		if (scimSchemas == null) {
			Collection<SchemaResource> schemas = new ArrayList<SchemaResource>();

			SchemaResource schema = SchemaUtils.getSchema(UserResource.class);
			Collection<AttributeDefinition> attributes = new ArrayList<AttributeDefinition>(schema.getAttributes());

			// Remove not supported attributes
			attributes = removeUnmappedAttributes(schema.getAttributes(), attributes, "");

			schema = new SchemaResource(schema.getId(), schema.getName(), schema.getDescription(), attributes);

			schemas.add(schema);

			// Add extended attributes
			attributes = buildExtendedSchemaAttributes();

			LOGGER.debug("Found {} attributes in schema: {}", attributes.size(), attributes);

			schema = new SchemaResource(ExtendedUserResource.SCIM_SCHEMA_EXTENDED, "User extensions",
					"User account extensions", attributes);

			schemas.add(schema);

			ListResponse<SchemaResource> schemasResponse = new ListResponse<SchemaResource>(schemas);
			scimSchemas = schemasResponse.toString();
		}
		return scimSchemas;
	}

	/**
	 * Adds the extended attributes.
	 *
	 * @return
	 * @throws Scim2WebServiceException
	 */
	protected Collection<AttributeDefinition> buildExtendedSchemaAttributes() throws Scim2WebServiceException {
		Collection<AttributeDefinition> attributes = new ArrayList<AttributeDefinition>();

		for (ExtendedQName qName : config.getFromScimAttributesMapping().keySet()) {
			if (ExtendedUserResource.SCIM_SCHEMA_EXTENDED.equals(qName.getNamespaceURI())) {
				String name = qName.getLocalPart();
				qName = config.getFromScimAttributesMapping().get(qName);
				if (config.getExtendedAttributes().containsKey(qName)) {
					ItemDefinition<?> def = config.getExtendedAttributes().get(qName);
					attributes.add(buildAttributeDef(qName, name, def));
				} else {
					PrismPropertyDefinition<Object> def = getUserDefinition().findPropertyDefinition(ItemPath.create(qName));
					if (def != null) {
						attributes.add(buildAttributeDef(qName, name, def));
					}
				}
			}
		}
		return attributes;
	}

	protected AttributeDefinition buildAttributeDef(ExtendedQName qName, String name, ItemDefinition<?> def) {
		Builder builder = new Builder();
		builder.setName(name);
		builder.setDescription(def.getDisplayName());
		builder.setMultiValued(def.getMaxOccurs() == -1 || def.getMaxOccurs() > 1);
		if (qName.isUnique()) {
			builder.setUniqueness(Uniqueness.SERVER);
		}

		String type = def.getTypeName().getLocalPart();
		try {
			builder.setType(Type.fromName(type));
		} catch (Exception e) {
			builder.setType(Type.STRING);
		}
		return builder.build();
	}

	/**
	 * Removes unmapped attributes from the schema resource.
	 *
	 * @param attributes
	 * @param newAttributes
	 * @param prefix
	 * @return
	 * @throws Scim2WebServiceException
	 */
	protected Collection<AttributeDefinition> removeUnmappedAttributes(Collection<AttributeDefinition> attributes,
			Collection<AttributeDefinition> newAttributes, String prefix) throws Scim2WebServiceException {
		for (AttributeDefinition attrDef : attributes) {
			AttributeDefinition attrD = checkAttributeDefinition(attrDef, "");
			newAttributes.remove(attrDef);
			if (attrD != null) {
				newAttributes.add(attrD);
			}
		}
		return newAttributes;
	}

	private AttributeDefinition checkAttributeDefinition(AttributeDefinition attrDef, String prefix)
			throws Scim2WebServiceException {
		AttributeDefinition attributeDefinition = attrDef;
		QName qN = new QName(ExtendedUserResource.SCIM_SCHEMA_CORE_USER, prefix + attrDef.getName());
		boolean isMappred = false;
		if (config.getFromScimAttributesMapping().containsKey(qN)) {
			isMappred = true;
		} else {
			attributeDefinition = null;
		}
		if (attrDef.getSubAttributes() != null) {
			ArrayList<AttributeDefinition> attributes = new ArrayList<>(attrDef.getSubAttributes());
			for (AttributeDefinition attrD : attrDef.getSubAttributes()) {
				attributeDefinition = checkAttributeDefinition(attrD, attrDef.getName() + ".");
				if (attributeDefinition == null) {
					attributes.remove(attrD);
				} else {
					isMappred = true;
				}
			}
			if (isMappred) {
				Builder builder = new Builder();
				builder.setCaseExact(attrDef.isCaseExact());
				builder.setDescription(attrDef.getDescription());
				builder.setMultiValued(attrDef.isMultiValued());
				builder.setMutability(attrDef.getMutability());
				builder.setName(attrDef.getName());
				builder.setRequired(attrDef.isRequired());
				builder.setReturned(attrDef.getReturned());
				builder.setType(attrDef.getType());
				builder.setUniqueness(attrDef.getUniqueness());
				builder.addSubAttributes(attributes.toArray(new AttributeDefinition[attributes.size()]));
				attributeDefinition = builder.build();
			}
		}
		return attributeDefinition;
	}

	/**
	 * Builds SCIM search result.
	 *
	 * @param startIndex   Index of the first object
	 * @param itemsPerPage number of entries per page
	 * @param sortBy       attribute to sort by
	 * @param sortOrder    sort order
	 * @param scimFilter   The SCIM filter to search for
	 * @param mappingSubSet an eventually computed subset of the complete mapping. may be null
	 * @param task         task instance
	 * @param result       operation result
	 * @return The result as SCIM2 search result
	 * @throws ScimException
	 * @throws CommonException
	 * @throws Scim2WebServiceException
	 */
	protected String buildSearchResult(Integer startIndex, Integer itemsPerPage, String sortBy, String sortOrder,
			Filter scimFilter, Map<ExtendedQName, ExtendedQName> mappingSubSet, Task task, OperationResult result)
			throws ScimException, CommonException, Scim2WebServiceException {
		StopWatch sw = StopWatch.createStarted();

		if (startIndex == null || startIndex < 1) {
			startIndex = 1;
		}

		if (itemsPerPage == null) {
			itemsPerPage = config.getDefaultResultSize();
		}

		/*
		 * RFC 7644: A negative value SHALL be interpreted as "0"
		 */
		if (itemsPerPage < 0) {
			itemsPerPage = 0;
		}

		if (sortOrder == null) {
			sortOrder = "ascending";
		}

		List<PrismObject<UserType>> users = findUsers(scimFilter, startIndex - 1, itemsPerPage, sortBy, sortOrder, task,
				result);

		/*
		 * Adjust to the current value
		 */
		int size = users.size();
		if (itemsPerPage > size) {
			itemsPerPage = size;
		}

		List<UserResource> resources = new ArrayList<UserResource>();
		if (itemsPerPage > 0) {
			for (PrismObject<UserType> user : users) {
				UserResource resource = mapToUserResource(user, mappingSubSet );
				resources.add(resource);
			}
		}
		ListResponse<UserResource> response = new ListResponse<UserResource>(users.size(), resources, startIndex,
				itemsPerPage);

		String body = response.toString();

		LOGGER.debug("STOPWATCH buildSearchResult {}", sw.getTime());
		// LOGGER.debug("returning:\n{}", body);

		return body;
	}

	/**
	 * Deletes a user object.
	 *
	 * @param id The oid of the resource to delete.
	 * @param ui User info
	 * @return The result as SimpleSearchResults<UserResource>
	 * @throws ScimException
	 */
	@Path("/Users/{id}")
	@DELETE
	@Produces({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	public Response deleteUser(@PathParam("id") final String id, @Context UriInfo ui) throws ScimException {
		StopWatch sw = StopWatch.createStarted();
		Validate.notEmpty(id, "No oid");
		init(ui);

		Response response;
		Task task = initRequest();
		//Task task = createTaskInstance(Scim2WebService.class.getName() + OPERATION_NAME);
		//auditLogin(task);
		OperationResult result = task.getResult();

		try {
			PrismObject<UserType> userType = getUser(id, task, result);
			if (userType != null) {
				ObjectDelta<UserType> userDeleteDelta = prismContext.deltaFactory().object().createDeleteDelta(UserType.class, userType.getOid());
				Collection<ObjectDelta<? extends ObjectType>> deltas = MiscSchemaUtil.createCollection(userDeleteDelta);
				modelService.executeChanges(deltas, null, task, result);
				response = Response.status(Status.NO_CONTENT).build();
			} else {
				LOGGER.info("No resource found with ID " + id);
				response = buildScimError(Status.NOT_FOUND, "No resource found with ID " + id, null);
			}

		} catch (Scim2WebServiceException se) {
			LOGGER.warn(se.getMessage(), se);
			response = buildScimError(se.getStatus(), se.getMessage(), se.getScimDetail());
		} catch (ObjectNotFoundException e) {
			LOGGER.warn(e.getMessage(), e);
			response = buildScimError(Status.NOT_FOUND, "No resource found with ID " + id, null);
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
			response = buildScimError(Status.INTERNAL_SERVER_ERROR, e.getMessage(), null);
		}
		result.computeStatus();
		//RestServiceUtil.finishRequest(task, securityHelper);

		LOGGER.debug("STOPWATCH delete {}", sw.getTime());
		return response;
	}

	/**
	 * Creates a user object by it's name.
	 *
	 * @param payload The scim json of the user to be added.
	 * @param ui      User info
	 * @return The result as SimpleSearchResults<UserResource>
	 * @throws ScimException
	 */
	@Path("/Users")
	@POST
	@Consumes({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	@Produces({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	public Response createUser(final String payload, @Context UriInfo ui) throws ScimException {
		StopWatch sw = StopWatch.createStarted();
		try {
			Validate.notEmpty(payload, "No payload");
		} catch (NullPointerException | IllegalArgumentException e) {
			LOGGER.warn(e.getMessage(), e);
			return buildScimError(Status.BAD_REQUEST, e.getMessage(), null);
		}
		init(ui);

		Response response;
		Task task = initRequest();
		//Task task = createTaskInstance(Scim2WebService.class.getName() + OPERATION_NAME);
		//auditLogin(task);
		OperationResult result = task.getResult();

		UserResource resource;
		try {
			resource = JsonUtils.getObjectReader().forType(UserResource.class).readValue(payload);
			// Ignore meta data
			resource.setMeta(null);
			LOGGER.debug("create resource: {}", resource);

			UserType userType = new UserType(prismContext);
			try {
				LOGGER.debug("create user type: {}", userType);
				ObjectMapper mapper = new ObjectMapper();
				@SuppressWarnings("unchecked")
                Map<String, Object> attributesMap = mapper.readValue(payload, Map.class);
				userType = mapToUserType(userType, resource, attributesMap);
				ObjectDelta<UserType> userAddDelta = DeltaFactory.Object.createAddDelta(userType.asPrismObject());
				try {
					LOGGER.debug("create objectdelta: {}", userAddDelta.debugDump());
				} catch (Throwable t) {
					// ignore
				}
				Collection<ObjectDelta<? extends ObjectType>> deltas = MiscSchemaUtil.createCollection(userAddDelta);
				LOGGER.debug("create object deltas: {}", deltas);
				Collection<ObjectDeltaOperation<? extends ObjectType>> results = modelService.executeChanges(deltas,
						null, task, result);
				@SuppressWarnings("unchecked")
				PrismObject<UserType> createdUserType = (PrismObject<UserType>) results.iterator().next()
						.getObjectDelta().getObjectToAdd();

				// Return the created object
				resource = mapToUserResource(createdUserType, null);

				LOGGER.debug("returning:\n{}", resource);
				response = Response.status(Status.CREATED).header("Location", getUserLocationUri(createdUserType.getOid()))
						.entity(resource.toString()).build();
			} catch (ObjectAlreadyExistsException e) {
				LOGGER.warn(e.getMessage(), e);
				response = buildScimError(Status.CONFLICT,
						"A user with user name " + userType.getName() + " already exists", "uniqueness");
			}
		} catch (Scim2WebServiceException se) {
			LOGGER.warn(se.getMessage(), se);
			response = buildScimError(se.getStatus(), se.getMessage(), se.getScimDetail());
		} catch (JsonProcessingException | NoFocusNameSchemaException | DatatypeConfigurationException e) {
			LOGGER.warn(e.getMessage(), e);
			response = buildScimError(Status.BAD_REQUEST, e.getMessage(), null);
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
			response = buildScimError(Status.INTERNAL_SERVER_ERROR, e.getMessage(), null);
		}
		result.computeStatus();
		//RestServiceUtil.finishRequest(task, securityHelper);
		LOGGER.debug("STOPWATCH create {}", sw.getTime());

		return response;
	}

	/**
	 * Builds a SCIM error resource.
	 *
	 * @param status
	 * @param detail
	 * @param type
	 * @return
	 */
	protected Response buildScimError(StatusType status, String detail, String type) {
		Response response;
		ErrorResponse scimErrorResponse = new ErrorResponse(status.getStatusCode());
		scimErrorResponse.setDetail(detail);
		scimErrorResponse.setScimType(type);
		response = Response.status(status).entity(scimErrorResponse.toString()).build();
		return response;
	}

	/**
	 * Modifies a user object.
	 *
	 * @param id      The id of the resource to be modified
	 * @param payload The scim json of the user to be modified
	 * @param ui      User info
	 * @return The result as SimpleSearchResults<UserResource>
	 * @throws ScimException
	 */
	@Path("/Users/{id}")
	@PUT
	@Consumes({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	@Produces({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	public Response modifyUser(@PathParam("id") final String id, final String payload, @Context UriInfo ui)
			throws ScimException {
		StopWatch sw = StopWatch.createStarted();
		try {
			Validate.notEmpty(payload, "No payload");
		} catch (NullPointerException | IllegalArgumentException e) {
			LOGGER.warn(e.getMessage(), e);
			return buildScimError(Status.BAD_REQUEST, e.getMessage(), null);
		}
		init(ui);

		Response response;
		Task task = initRequest();
		//Task task = createTaskInstance(Scim2WebService.class.getName() + OPERATION_NAME);
		//auditLogin(task);
		OperationResult result = task.getResult();

		LOGGER.debug("Payload:\n{}", payload);
		UserResource resource;
		try {
			resource = JsonUtils.getObjectReader().forType(UserResource.class).readValue(payload);
			ObjectMapper mapper = new ObjectMapper();
			@SuppressWarnings("unchecked")
            Map<String, Object> attributesMap = mapper.readValue(payload, Map.class);
			PrismObject<UserType> userType = getUser(id, task, result);
			if (userType != null) {
				UserType userTypeMod = mapToUserType(userType.clone().asObjectable(), resource, attributesMap);
				Collection<ItemDelta<?, ?>> modifications = getModifications(userType.asObjectable(), userTypeMod);
				if (!modifications.isEmpty()) {
					ObjectDelta<UserType> userModifyDeltaReplace = prismContext.deltaFactory().object().createModifyDelta(userType.getOid(),
							modifications, UserType.class);
					Collection<ObjectDelta<? extends ObjectType>> deltas = MiscSchemaUtil
							.createCollection(userModifyDeltaReplace);
					modelService.executeChanges(deltas, null, task, result);
					userType = getUser(userType.getOid(), task, result);
				}
				// Return the modified object
				resource = mapToUserResource(userType, null);

				LOGGER.debug("returning:\n{}", resource);
				response = Response.status(Status.OK).header("Location", getUserLocationUri(userType.getOid()))
						.entity(resource.toString()).build();
			} else {
				LOGGER.info("No resource found with ID " + id);
				response = buildScimError(Status.NOT_FOUND, "No resource found with ID " + id, null);
			}
		} catch (Scim2WebServiceException se) {
			LOGGER.warn(se.getMessage(), se);
			response = buildScimError(se.getStatus(), se.getMessage(), se.getScimDetail());
		} catch (JsonProcessingException | NoFocusNameSchemaException | DatatypeConfigurationException e) {
			LOGGER.warn(e.getMessage(), e);
			response = buildScimError(Status.BAD_REQUEST, e.getMessage(), null);
		} catch (ObjectNotFoundException e) {
			LOGGER.warn(e.getMessage(), e);
			response = buildScimError(Status.NOT_FOUND, "No resource found with ID " + id, null);
		} catch (Exception e) {
			LOGGER.error("Internal error", e);
			response = buildScimError(Status.INTERNAL_SERVER_ERROR, e.getMessage(), null);
		}
		result.computeStatus();
		//RestServiceUtil.finishRequest(task, securityHelper);

		LOGGER.debug("STOPWATCH modify {}", sw.getTime());

		return response;
	}

	/**
	 * Patches a user object.
	 *
	 * @param id      The id of the resource to be patched
	 * @param payload The scim json of the user to be patched
	 * @param ui      User info
	 * @return The result as SimpleSearchResults<UserResource>
	 * @throws ScimException
	 */
	@Path("/Users/{id}")
	@PATCH
	@Consumes({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	@Produces({ MEDIA_TYPE_SCIM, MediaType.APPLICATION_JSON })
	public Response patchUser(@PathParam("id") final String id, final String payload, @Context UriInfo ui)
			throws ScimException {
		StopWatch sw = StopWatch.createStarted();
		try {
			Validate.notEmpty(payload, "No payload");
		} catch (NullPointerException | IllegalArgumentException e) {
			LOGGER.warn(e.getMessage(), e);
			return buildScimError(Status.BAD_REQUEST, e.getMessage(), null);
		}
		init(ui);

		Response response;
		Task task = initRequest();
		//Task task = createTaskInstance(Scim2WebService.class.getName() + OPERATION_NAME);
		//auditLogin(task);
		OperationResult result = task.getResult();

		LOGGER.debug("Payload:\n{}", payload);
		try {
			PrismObject<UserType> userType = getUser(id, task, result);
			if (userType != null) {
				PatchRequest patchRequest = JsonUtils.getObjectReader().forType(PatchRequest.class).readValue(payload);

				Collection<ObjectDelta<? extends ObjectType>> deltas = buildDeltas(userType, patchRequest);
				if (deltas != null) {
					modelService.executeChanges(deltas, null, task, result);
					PrismObject<UserType> modifiedUserType = getUser(userType.getOid(), task, result);

					// Return the modified object
					UserResource resource = mapToUserResource(modifiedUserType, null);
					LOGGER.debug("returning:\n{}", resource);

					response = Response.status(Status.OK).header("Location", getUserLocationUri(userType.getOid()))
							.entity(resource.toString()).build();
				} else {
					response = Response.status(Status.NO_CONTENT).header("Location", getUserLocationUri(userType.getOid()))
							.build();
				}
			} else {
				LOGGER.info("No resource found with ID " + id);
				response = buildScimError(Status.NOT_FOUND, "No resource found with ID " + id, null);
			}

		} catch (Scim2WebServiceException se) {
			LOGGER.warn(se.getMessage(), se);
			response = buildScimError(se.getStatus(), se.getMessage(), se.getScimDetail());
		} catch (ObjectNotFoundException e) {
			LOGGER.warn(e.getMessage(), e);
			response = buildScimError(Status.NOT_FOUND, "No resource found with ID " + id, null);
		} catch (JsonProcessingException | NoFocusNameSchemaException | DatatypeConfigurationException e) {
			LOGGER.warn(e.getMessage(), e);
			response = buildScimError(Status.BAD_REQUEST, e.getMessage(), null);
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
			response = buildScimError(Status.INTERNAL_SERVER_ERROR, e.getMessage(), null);
		}
		result.computeStatus();
		//RestServiceUtil.finishRequest(task, securityHelper);

		LOGGER.debug("STOPWATCH patch {}", sw.getTime());
		return response;
	}

	/**
	 * Builds deltas from the patch request.
	 *
	 * @param userType          Object oid
	 * @param patchRequest SCIM patch request
	 * @return
	 * @throws ScimException
	 * @throws Scim2WebServiceException
	 * @throws JsonProcessingException
	 * @throws DatatypeConfigurationException
	 */
	private Collection<ObjectDelta<? extends ObjectType>> buildDeltas(PrismObject<UserType> userType, PatchRequest patchRequest)
			throws ScimException, Scim2WebServiceException, JsonProcessingException, DatatypeConfigurationException {
		Collection<ObjectDelta<? extends ObjectType>> deltas = null;
		ObjectDelta<UserType> userModifyDeltaAdd = null;
		for (PatchOperation patchOperation : patchRequest.getOperations()) {
			String path = patchOperation.getPath().toString();
			PatchOpType opType = patchOperation.getOpType();
			if (path.equals("emails")) {
				List<Object> primaryValues = getEmailValues(patchOperation.getJsonNode(), true);
				List<Object> nonPrimaryValues = getEmailValues(patchOperation.getJsonNode(), false);
				if (primaryValues.isEmpty() && !nonPrimaryValues.isEmpty()) {
					// if there is no primary mail found, treat the first mail in the list as
					// primary mail
					primaryValues.add(nonPrimaryValues.remove(0));
				} else if (primaryValues.size() > 1) {
					throw new Scim2WebServiceUnprocessableEntryException(
							"Can't process multiple primary mails!", "fatal");
				}

				Pair<QName, List<Object>> primaryPair = null;
				Pair<QName, List<Object>> nonPrimaryPair = null;

				if (!primaryValues.isEmpty()) {
					primaryPair = new ImmutablePair<QName, List<Object>>(UserType.F_EMAIL_ADDRESS,
							primaryValues);
					userModifyDeltaAdd = addModifyDelta(userType.getOid(), userModifyDeltaAdd, opType,
							primaryPair, false);
				}
				if (!nonPrimaryValues.isEmpty()) {
					nonPrimaryPair = new ImmutablePair<QName, List<Object>>(
						config.getConfiguredAdditionalEMailAttribute(), nonPrimaryValues);
					userModifyDeltaAdd = addModifyDelta(userType.getOid(), userModifyDeltaAdd, opType,
							nonPrimaryPair, true);
				}
			} else if (path.equals("phoneNumbers")) {
				List<Object> primaryValues = getEmailValues(patchOperation.getJsonNode(), true);
				List<Object> nonPrimaryValues = getEmailValues(patchOperation.getJsonNode(), false);
				if (primaryValues.isEmpty() && !nonPrimaryValues.isEmpty()) {
					// if there is no primary mail found, treat the first number in the list as
					// primary number
					primaryValues.add(nonPrimaryValues.remove(0));
				} else if (primaryValues.size() > 1) {
					throw new Scim2WebServiceUnprocessableEntryException(
							"Can't process multiple primary phone numbers!", "fatal");
				}

				Pair<QName, List<Object>> primaryPair = null;

				if (!primaryValues.isEmpty()) {
					primaryPair = new ImmutablePair<QName, List<Object>>(UserType.F_TELEPHONE_NUMBER,
							primaryValues);
					userModifyDeltaAdd = addModifyDelta(userType.getOid(), userModifyDeltaAdd, opType,
							primaryPair, false);
				}
			} else {
				Pair<QName, List<Object>> pair = convertPatchOperationToMidpoint(userType, patchOperation);
				if (pair != null) {
					boolean isExtended = config.getExtendedAttributes().containsKey(pair.getLeft());
					userModifyDeltaAdd = addModifyDelta(userType.getOid(), userModifyDeltaAdd, opType, pair,
							isExtended);
				} else {
					throw ScimException.createException(Status.BAD_REQUEST.getStatusCode(),
							"Bad patch operation: " + patchOperation);
				}
			}
		}
		deltas = add2Deltas(deltas, userModifyDeltaAdd);
		return deltas;
	}

	/**
	 * Adds a modify delta to provided ObjectDelta depending on oid, opType, QName and values
	 *
	 * @param oid oid of modified entry
	 * @param userModifyDelta ObjectDelta the modification will be added to
	 * @param opType operation Type of delta
	 * @param pair qname and values of updated attribute
	 * @param extendedAttr if set, will add 'extention' as parent to imtempath
	 * @return
	 */
	private ObjectDelta<UserType> addModifyDelta(String oid, ObjectDelta<UserType> userModifyDelta,
			PatchOpType opType, Pair<QName, List<Object>> pair, boolean extendedAttr) {
		LOGGER.debug("Modification with operation '{}', qName '{}' and value '{}'", opType,
				pair.getLeft().getLocalPart(), pair.getRight());
		ItemPath itemPath;
		if (extendedAttr) {
			itemPath = ItemPath.create(ItemPath.create("extension"), ItemPath.create(pair.getLeft()));
		} else {
			itemPath = ItemPath.create(pair.getLeft());
		}
		switch (opType) {
		case ADD:
			if (userModifyDelta == null) {
				userModifyDelta = createModificationAddProperty(oid, itemPath, pair.getRight());
			} else {
				userModifyDelta.addModificationAddProperty(itemPath, pair.getRight().toArray());
			}
			break;
		case REPLACE:
			if (userModifyDelta == null) {
				userModifyDelta = createModificationReplaceProperty(oid, itemPath, pair.getRight());
			} else {
				userModifyDelta.addModificationReplaceProperty(itemPath, pair.getRight().toArray());
			}
			break;
		case REMOVE:
			if (userModifyDelta == null) {
				userModifyDelta = createModificationDeleteProperty(oid, itemPath, pair.getRight());
			} else {
				userModifyDelta.addModificationDeleteProperty(itemPath, pair.getRight().toArray());
			}
			break;
		default:
			break;
		}
		return userModifyDelta;
	}

	protected ObjectDelta<UserType> createModificationAddProperty(String oid, ItemPath path, List<Object> values) {
		return prismContext.deltaFactory().object().createModificationAddProperty(UserType.class, oid, path,
				values.toArray());
	}

	protected ObjectDelta<UserType> createModificationReplaceProperty(String oid, ItemPath path,
			List<Object> values) {
		return prismContext.deltaFactory().object().createModificationReplaceProperty(UserType.class, oid, path,
				values.toArray());
	}

	protected ObjectDelta<UserType> createModificationDeleteProperty(String oid, ItemPath path,
			List<Object> values) {
		return prismContext.deltaFactory().object().createModificationDeleteProperty(UserType.class, oid, path,
				values.toArray());
	}

	/**
	 * Returns the location URI as string.
	 *
	 * @param oid Object oid
	 * @return location
	 */
	protected String getUserLocationUri(final String oid) {
		return config.getBaseUri() + "/Users/" + oid;
	}

	/**
	 * Compares the original and the current objects and returns the deltas.
	 *
	 * @param orig Original object
	 * @param curr Current object
	 * @return Collection of item deltas
	 * @throws SchemaException
	 */
	private Collection<ItemDelta<?, ?>> getModifications(final UserType orig, final UserType curr)
			throws SchemaException {
		List<ItemDelta<?, ?>> modifications = new ArrayList<>();

		if (curr.getName() == null) {
			addDelta(modifications, UserType.F_NAME, null);
		} else if (!StringUtils.equals((orig.getName() == null ? null : orig.getName().getOrig()),
				curr.getName().getOrig())) {
			addDelta(modifications, UserType.F_NAME, new PolyString(curr.getName().getOrig()));
		}

		if (curr.getAdditionalName() == null) {
			addDelta(modifications, UserType.F_ADDITIONAL_NAME, null);
		} else if (!StringUtils.equals((orig.getAdditionalName() == null ? null : orig.getAdditionalName().getOrig()),
				curr.getAdditionalName().getOrig())) {
			addDelta(modifications, UserType.F_ADDITIONAL_NAME, new PolyString(curr.getAdditionalName().getOrig()));
		}

		if (curr.getEmailAddress() == null) {
			addDelta(modifications, UserType.F_EMAIL_ADDRESS, null);
		} else if (!StringUtils.equals(orig.getEmailAddress(), curr.getEmailAddress())) {
			addDelta(modifications, UserType.F_EMAIL_ADDRESS, curr.getEmailAddress());
		}

		if (curr.getEmployeeNumber() == null) {
			addDelta(modifications, UserType.F_EMPLOYEE_NUMBER, null);
		} else if (curr.getEmployeeNumber() != null
				&& !StringUtils.equals(orig.getEmployeeNumber(), curr.getEmployeeNumber())) {
			addDelta(modifications, UserType.F_EMPLOYEE_NUMBER, curr.getEmployeeNumber());
		}

		//employee type deprecated
		//if (curr.getEmployeeType() == null) {
		//	addDelta(modifications, UserType.F_EMPLOYEE_TYPE, null);
		//} else if (!curr.getEmployeeType().equals(orig.getEmployeeType())) {
		//	addDelta(modifications, UserType.F_EMPLOYEE_TYPE, curr.getEmployeeType());
		//}

		if (curr.getFamilyName() == null) {
			addDelta(modifications, UserType.F_FAMILY_NAME, null);
		} else if (!StringUtils.equals((orig.getFamilyName() == null ? null : orig.getFamilyName().getOrig()),
				curr.getFamilyName().getOrig())) {
			addDelta(modifications, UserType.F_FAMILY_NAME, new PolyString(curr.getFamilyName().getOrig()));
		}

		if (curr.getFullName() == null) {
			addDelta(modifications, UserType.F_FULL_NAME, null);
		} else if (!StringUtils.equals((orig.getFullName() == null ? null : orig.getFullName().getOrig()),
				curr.getFullName().getOrig())) {
			addDelta(modifications, UserType.F_FULL_NAME, new PolyString(curr.getFullName().getOrig()));
		}

		if (curr.getGivenName() == null) {
			addDelta(modifications, UserType.F_GIVEN_NAME, null);
		} else if (!StringUtils.equals((orig.getGivenName() == null ? null : orig.getGivenName().getOrig()),
				curr.getGivenName().getOrig())) {
			addDelta(modifications, UserType.F_GIVEN_NAME, new PolyString(curr.getGivenName().getOrig()));
		}

		if (curr.getHonorificPrefix() == null) {
			addDelta(modifications, UserType.F_HONORIFIC_PREFIX, null);
		} else if (!StringUtils.equals((orig.getHonorificPrefix() == null ? null : orig.getHonorificPrefix().getOrig()),
				curr.getHonorificPrefix().getOrig())) {
			addDelta(modifications, UserType.F_HONORIFIC_PREFIX, new PolyString(curr.getHonorificPrefix().getOrig()));
		}

		if (curr.getHonorificSuffix() == null) {
			addDelta(modifications, UserType.F_HONORIFIC_SUFFIX, null);
		} else if (!StringUtils.equals((orig.getHonorificSuffix() == null ? null : orig.getHonorificSuffix().getOrig()),
				curr.getHonorificSuffix().getOrig())) {
			addDelta(modifications, UserType.F_HONORIFIC_SUFFIX, new PolyString(curr.getHonorificSuffix().getOrig()));
		}

		if (curr.getLocale() == null) {
			addDelta(modifications, UserType.F_LOCALE, null);
		} else if (!StringUtils.equals(orig.getLocale(), curr.getLocale())) {
			addDelta(modifications, UserType.F_LOCALE, curr.getLocale());
		}

		if (curr.getPreferredLanguage() == null) {
			addDelta(modifications, UserType.F_PREFERRED_LANGUAGE, null);
		} else if (!StringUtils.equals(orig.getPreferredLanguage(), curr.getPreferredLanguage())) {
			addDelta(modifications, UserType.F_PREFERRED_LANGUAGE, curr.getPreferredLanguage());
		}

		if (curr.getTelephoneNumber() == null) {
			addDelta(modifications, UserType.F_TELEPHONE_NUMBER, null);
		} else if (!StringUtils.equals(orig.getTelephoneNumber(), curr.getTelephoneNumber())) {
			addDelta(modifications, UserType.F_TELEPHONE_NUMBER, curr.getTelephoneNumber());
		}

		if (curr.getLocality() == null) {
			addDelta(modifications, UserType.F_LOCALITY, null);
		} else if (!StringUtils.equals((orig.getLocality() == null ? null : orig.getLocality().getOrig()),
				curr.getLocality().getOrig())) {
			addDelta(modifications, UserType.F_LOCALITY, new PolyString(curr.getLocality().getOrig()));
		}

		if (curr.getNickName() == null) {
			addDelta(modifications, UserType.F_NICK_NAME, null);
		} else if (!StringUtils.equals((orig.getNickName() == null ? null : orig.getNickName().getOrig()),
				curr.getNickName().getOrig())) {
			addDelta(modifications, UserType.F_NICK_NAME, new PolyString(curr.getNickName().getOrig()));
		}

		if (curr.getTitle() == null) {
			addDelta(modifications, UserType.F_TITLE, null);
		} else if (!StringUtils.equals((orig.getTitle() == null ? null : orig.getTitle().getOrig()),
				curr.getTitle().getOrig())) {
			addDelta(modifications, UserType.F_TITLE, new PolyString(curr.getTitle().getOrig()));
		}

		if (curr.getActivation() != null && (curr.getActivation().getAdministrativeStatus() == null || !curr
				.getActivation().getAdministrativeStatus().equals(orig.getActivation().getAdministrativeStatus()))) {
			addActivationModification(modifications, curr.getActivation());
		}

		if (curr.getExtension() != null) {
			addExtensionModifications(orig, curr, modifications);
		}

		return modifications;
	}

	/**
	 * Adds the activation modification.
	 *
	 * @param modifications list to add modifications to
	 * @param activation    the activation object
	 * @throws SchemaException
	 */
	protected void addActivationModification(List<ItemDelta<?, ?>> modifications, ActivationType activation)
			throws SchemaException {
		PropertyDelta<?> delta = createDelta(activation.getAdministrativeStatus(), false, getUserDefinition()
				.findPropertyDefinition(ItemPath.create(new QName("activation"), "administrativeStatus")));
		delta.setParentPath(ItemPath.create(SchemaConstants.C_ACTIVATION));
		modifications.add(delta);
	}

	/**
	 * Adds extension modifications.
	 *
	 * @param orig          origin object
	 * @param curr          current object
	 * @param modifications list to add modifications to
	 * @throws SchemaException
	 */
	private void addExtensionModifications(UserType orig, UserType curr, List<ItemDelta<?, ?>> modifications)
			throws SchemaException {
		PrismContainerValue<Containerable> containerValue = prismContext.itemFactory().createContainerValue();
		if (orig.getExtension() == null) {
			PrismContainerValue<?> asPrismContainerValue = curr.getExtension().asPrismContainerValue();
			if (asPrismContainerValue != null && asPrismContainerValue.getItems() != null) {
				for (Item<?, ?> item : asPrismContainerValue.getItems()) {
					addToExtension(containerValue, item);
				}
			}
		} else {
			PrismContainerValue<?> currPrismContainerValue = curr.getExtension().asPrismContainerValue();

			// Add new attribute values
			if (currPrismContainerValue != null && currPrismContainerValue.getItems() != null) {
				for (Item<?, ?> currItem : currPrismContainerValue.getItems()) {
					addToExtension(containerValue, currItem);
				}
			}
		}

		if (containerValue.getItems() != null && !containerValue.getItems().isEmpty()) {
			addExtensionDelta(modifications, containerValue);
		}
	}

	private void addToExtension(PrismContainerValue<Containerable> containerValue, Item<?, ?> item)
			throws SchemaException {
		QName qName = null;
		if (config.getExtendedAttributes().containsKey(item.getElementName())) {
			qName = item.getElementName();
		}
		if (qName != null) {
			for (Object value : item.getRealValues()) {
				addPropertyValue(containerValue, qName, value, true);
			}
		} else {
			throw new SchemaException("Unknown property: " + Scim2WebServiceConfig.toPropertyName(item.getElementName()));
		}
	}

	/**
	 * Adds extension deltas.
	 *
	 * @param deltas         delta list to add to
	 * @param containerValue the container that contains the items
	 * @throws SchemaException
	 */
	private void addExtensionDelta(List<ItemDelta<?, ?>> deltas, PrismContainerValue<Containerable> containerValue)
			throws SchemaException {
		for (Item<?, ?> item : containerValue.getItems()) {
			List<Object> values = new ArrayList<Object>();

			for (PrismValue value : item.getValues()) {
				if (value.getRealValue() != null) {
					values.add(value.getRealValue().toString());
				}
			}

			if (values.isEmpty()) {
				values = null;
			}

			PropertyDelta<?> delta = createDelta(values, false,
					getUserDefinition().getExtensionDefinition().findPropertyDefinition(item.getElementName()));
			delta.setParentPath(ItemPath.create((SchemaConstantsGenerated.C_EXTENSION)));
			deltas.add(delta);
		}
	}

	/**
	 * Adds a new delta to the delta list.
	 *
	 * @param deltas        delta list
	 * @param itemName      item name
	 * @param itemRealValue item value
	 * @param add
	 * @throws SchemaException
	 */
	protected void addDelta(List<ItemDelta<?, ?>> deltas, QName itemName, Object itemRealValue, boolean add)
			throws SchemaException {

		deltas.add(createDelta(itemRealValue, add, getUserDefinition().findPropertyDefinition(ItemPath.create(itemName))));
	}

	protected void addDelta(List<ItemDelta<?, ?>> deltas, QName itemName, Object itemRealValue) throws SchemaException {
		addDelta(deltas, itemName, itemRealValue, false);
	}

	/**
	 * Creates a modification delta.
	 *
	 * @param itemRealValue the value to add/replace
	 * @param add           whether it is an add
	 * @param definition    property definition
	 * @return delta
	 * @throws SchemaException
	 */
	protected PropertyDelta<?> createDelta(Object itemRealValue, boolean add, PrismPropertyDefinition<?> definition)
			throws SchemaException {
		PropertyDelta<?> delta = prismContext.deltaFactory().property().create(definition);
		PrismPropertyValue property = null;

		if (itemRealValue instanceof Collection) {
			Collection<?> values = (Collection<?>) itemRealValue;
			for (Object value : values) {
				property = prismContext.itemFactory().createPropertyValue(value);

				if (add) {
					delta.addValueToAdd(property);
				} else {
					delta.addValueToReplace(property);
				}

				if (definition.getMaxOccurs() == 1) {
					break;
				}
			}

		} else {
			if (itemRealValue != null) {
				property = prismContext.itemFactory().createPropertyValue(itemRealValue);
			}
			if (add) {
				delta.addValueToAdd(property);
			} else {
				delta.addValueToReplace(property);
			}
		}

		return delta;
	}

	/**
	 * Adds a delta to the delta list.
	 *
	 * @param deltas          delta list
	 * @param userModifyDelta delta to add
	 * @return
	 */
	private Collection<ObjectDelta<? extends ObjectType>> add2Deltas(
			Collection<ObjectDelta<? extends ObjectType>> deltas, ObjectDelta<UserType> userModifyDelta) {
		if (userModifyDelta != null) {
			LOGGER.debug("Adding delta: {}", userModifyDelta.debugDump());
			if (deltas == null) {
				deltas = MiscSchemaUtil.createCollection(userModifyDelta);
			} else {
				deltas.add(userModifyDelta);
			}
		}
		return deltas;
	}

	/**
	 * Extracts data from a patch operation
	 *
	 * @param userType
	 * @param patchOperation
	 * @return a pair of ItemPath and string values
	 * @throws Scim2WebServiceException
	 * @throws JsonProcessingException
	 * @throws DatatypeConfigurationException
	 */
	protected Pair<QName, List<Object>> convertPatchOperationToMidpoint(PrismObject<UserType> user, PatchOperation patchOperation)
			throws Scim2WebServiceException, JsonProcessingException, DatatypeConfigurationException {
		Pair<QName, List<Object>> pair = null;
		String path = patchOperation.getPath().toString();
		QName qName = getQName(path);
    		if (qName != null) {
    			List<Object> values = extractValues(user, patchOperation.getJsonNode(), qName);
    			pair = new ImmutablePair<QName, List<Object>>(qName, values);
    		}
		return pair;
	}

	/**
	 * Extracts the email or phone number values from a scim json node. Depending on
	 * primary will only return the (non-)primary mail-values. Note that type and
	 * display-name are ignored here
	 *
	 * @param node    scim json node
	 * @param primary tells if only primary or only non primary mails should be
	 *                returned
	 * @return (empty) list with all (non-) primary email values
	 */
	private List<Object> getEmailValues(JsonNode node, boolean primary) {
		List<Object> result = new ArrayList<Object>();
		if (node != null) {

			if (node != null && node.isArray()) {
				for (JsonNode nextEmail : node) {
					JsonNode primaryNode = nextEmail.get("primary");

					boolean primaryNodeVal = primaryNode != null && primaryNode.asBoolean();
					if (primaryNodeVal == primary) {
						String value = nextEmail.get("value").asText();
						result.add(value);
						if (primary) {
							// only 1 primary mail can be handled by midpoint. all other
							// primary values are ignored here
							break;
						}
					}
				}
			}
		}
		return result;
	}

	/**
	 * Extracts values from a json node and converts them to midPoint internal type.
	 *
	 * @param user
	 * @param node   the json node
	 * @param qName  the property
	 * @param values initial list of values
	 * @return values list
	 * @throws JsonProcessingException
	 * @throws DatatypeConfigurationException
	 */
	private List<Object> extractValues(PrismObject<UserType> user, JsonNode node, QName qName) throws JsonProcessingException, DatatypeConfigurationException {
        List<Object> values = JsonUtils.nodeToValue(node, List.class);

        if (values == null) {
            values = new ArrayList<Object>();
        } else {
            List<Object> convertedValues = new ArrayList<Object>(values.size());
            for (Object value : values) {
                Object convertedValue = value;
                if (config.getExtendedAttributes().containsKey(qName)) {
                    // Init extension
                    ItemDefinition<?> definition = user.getExtension().getDefinition().findItemDefinition(ItemPath.create(qName));
                    convertedValue = convertToMidpoint(value, qName, (PrismPropertyDefinition) definition);
                } else {
                    ItemDefinition<?> definition = user.getDefinition().findItemDefinition(ItemPath.create(qName));
                    convertedValue = convertToMidpoint(value, qName, (PrismPropertyDefinition) definition);
                }

                convertedValues.add(convertedValue);
            }
            values = convertedValues;
        }

        return values;
	}

	/**
	 * Returns a property according to the urn.
	 *
	 * @param urn the urn
	 * @return property
	 * @throws Scim2WebServiceException
	 */
	protected ExtendedQName getQName(String urn) throws Scim2WebServiceException {
		ExtendedQName qName = null;
		if (urn != null) {
			LOGGER.debug("Schema urn '{}'", urn);

			String nameSpace = ExtendedUserResource.SCIM_SCHEMA_CORE_USER;
			if (urn.indexOf(":") >= 0) {
				nameSpace = StringUtils.substringBeforeLast(urn, ":");
				urn = StringUtils.substringAfterLast(urn, ":");
			}
			QName qN = new QName(nameSpace, urn);
			if (config.getFromScimAttributesMapping().containsKey(qN)) {
				qName = config.getFromScimAttributesMapping().get(qN);
			}
			if (qName == null) {
				// attribute was not found in core user schema -> search in extended schema
				String nameSpaceExtended = ExtendedUserResource.SCIM_SCHEMA_EXTENDED;
				QName extendedQN = new QName(nameSpaceExtended, urn);
				if (config.getFromScimAttributesMapping().containsKey(extendedQN)) {
					qName = config.getFromScimAttributesMapping().get(extendedQN);
				}
			}
		}

		return qName;
	}

	/**
	 * Converts PrismObject<UserType> to UserResource
	 *
	 * @param user user object of type PrismObject<UserType>
	 * @param mappingSubSet an eventually computed subset of the complete mapping. may be null
	 * @return UserResource
	 * @throws ScimException
	 * @throws Scim2WebServiceException
	 */
	/**
	 * Converts PrismObject<UserType> to UserResource
	 *
	 * @param user user object of type PrismObject<UserType>
	 * @param mappingSubSet an eventually computed subset of the complete mapping. may be null
	 * @return UserResource
	 * @throws ScimException
	 * @throws Scim2WebServiceException
	 */
	protected UserResource mapToUserResource(PrismObject<UserType> user, Map<ExtendedQName, ExtendedQName> mappingSubSet)
			throws ScimException, Scim2WebServiceException {
		UserType userType = user.asObjectable();
		UserResource resource = new UserResource();
		PrismProperty<String> oid = prismContext.itemFactory().createProperty(ExtendedUserResource.F_OID);
		oid.setValue(prismContext.itemFactory().createPropertyValue(userType.getOid()));
		List<Item<?, ?>> items = new ArrayList<Item<?, ?>> (user.getValue().getItems());
		items.add(oid);
		for (Item<?, ?> item : items) {
			QName qName = item.getElementName();
			if (mappingSubSet == null || mappingSubSet.containsKey(qName)) {
				if (qName.equals(UserType.F_EMAIL_ADDRESS)) {
					addMailToResource(resource, item, true);
				} else if (item.getElementName().equals(config.getConfiguredAdditionalEMailAttribute())) {
					addMailToResource(resource, item, false);
				} else if (qName.equals(UserType.F_TELEPHONE_NUMBER)) {
					addPhoneNumberToResource(resource, item, true);
				} else if (config.getToScimAttributesMapping().containsKey(qName)) {
					updateResource(resource, item, userType);
				}
			}
		}

		if (userType.getExtension() != null) {
			PrismContainerValue<?> asPrismContainerValue = userType.getExtension().asPrismContainerValue();
			if (asPrismContainerValue != null && asPrismContainerValue.getItems() != null) {
				for (Item<?, ?> item : asPrismContainerValue.getItems()) {
					if (asPrismContainerValue.contains(item)) {
						if (mappingSubSet == null || mappingSubSet.containsKey(item.getElementName())){
							if (item.getElementName()
									.equals(config.getConfiguredAdditionalEMailAttribute())) {
								addMailToResource(resource, item, false);
							}
							// TODO should be considered to map additional mails also in custom
							// attribute?
							else {
								updateResource(resource, item, userType);
							}
						}
					}
				}
			}
		}

		Meta meta = buildMetaData(userType);

		resource.setMeta(meta);
		return resource;
	}

	/**
	 * adds emails value to provided UserResource
	 *
	 * @param resource  UserResource the email should be added to
	 * @param emailItem email values
	 * @param primary   tells if added mails are primary or not. Note that if primary
	 *                  is set only one value will be expected and added to the
	 *                  resource
	 */
	private void addMailToResource(UserResource resource, Item<?, ?> emailItem, boolean primary) {
		List<Email> mails = resource.getEmails();
		if (mails == null) {
			mails = new ArrayList<Email>();
		}
		if (primary) {
			String value = emailItem.getRealValue().toString();
			Email email = new Email();
			email.setValue(value);
			email.setPrimary(true);
			mails.add(email);
		} else {
			for (Object nextEmailValue : emailItem.getRealValues()) {
				Email email = new Email();
				email.setValue(nextEmailValue.toString());
				email.setPrimary(false);
				mails.add(email);
			}
		}
		resource.setEmails(mails);
	}

	/**
	 * adds phone numbers value to provided UserResource
	 *
	 * @param resource  UserResource the phone number should be added to
	 * @param phoneNumberItem phone number values
	 * @param primary   tells if added phone numbers are primary or not. Note that if primary
	 *                  is set only one value will be expected and added to the
	 *                  resource
	 */
	private void addPhoneNumberToResource(UserResource resource, Item<?, ?> phoneNumberItem, boolean primary) {
		List<PhoneNumber> phoneNumbers = resource.getPhoneNumbers();
		if (phoneNumbers == null) {
			phoneNumbers = new ArrayList<PhoneNumber>();
		}
		if (primary) {
			String value = phoneNumberItem.getRealValue().toString();
			PhoneNumber phoneNumber = new PhoneNumber();
			phoneNumber.setValue(value);
			phoneNumber.setPrimary(true);
			phoneNumbers.add(phoneNumber);
		} else {
			for (Object nextPhoneNumberValue : phoneNumberItem.getRealValues()) {
				PhoneNumber phoneNumber = new PhoneNumber();
				phoneNumber.setValue(nextPhoneNumberValue.toString());
				phoneNumber.setPrimary(false);
				phoneNumbers.add(phoneNumber);
			}
		}
		resource.setPhoneNumbers(phoneNumbers);
	}

	protected void updateResource(UserResource resource, Item<?, ?> item, UserType userType)
			throws ScimException, Scim2WebServiceException {
		List<Object> values = new ArrayList<Object>();
		if (UserType.F_ACTIVATION.equals(item.getElementName())) {
			values.add(ActivationStatusType.ENABLED.equals(userType.getActivation().getEffectiveStatus()));
		} else {
			for (PrismValue value : item.getValues()) {
				values.add(value.getRealValue().toString());
			}
		}
		setExtendedResourceValue(resource, item.getElementName(), values);
	}

	/**
	 * Extracts extended attribute from midPoint.
	 *
	 * @param resource SCIM resource
	 * @param qName    The qName to get the local part name from
	 * @param values   The value to set
	 * @throws ScimException
	 * @throws Scim2WebServiceException
	 */
	private void setExtendedResourceValue(UserResource resource, QName qName, List<Object> values)
			throws ScimException, Scim2WebServiceException {
		Object value = null;
		if (values != null && !values.isEmpty()) {
			value = values.get(0);
		}

		String scimAttr = config.mapAttrToScim(qName);
		Map<QName, ItemDefinition<?>> extendedAttributes = config.getExtendedAttributes();
		if (extendedAttributes.containsKey(qName) && isMultiValue(extendedAttributes.get(qName))) {
			ExtendedUserResource.addExtensionValueToUserRessource(resource, scimAttr, values);
		} else if (scimAttr.startsWith(ExtendedUserResource.SCIM_SCHEMA_CORE_USER + ":emails")) {
			// emails must be multivalue and in scim2 format, therefore they are treated
			// separately here
			List<Email> emails = new ArrayList<Email>();
			Email email = new Email();
			email.setValue((String) value);
			emails.add(email);
			resource.setEmails(emails);
        } else if (scimAttr.startsWith(ExtendedUserResource.SCIM_SCHEMA_CORE_USER + ":addresses")) {
            // same for addresses
            // note that this only supports one address for now
            List<Address> addresses;
            Address address;
            if (resource.getAddresses() != null && !resource.getAddresses().isEmpty()
                    && resource.getAddresses().get(0) != null) {
                addresses = resource.getAddresses();
                address = resource.getAddresses().get(0);
            } else {
                addresses = new ArrayList<Address>();
                address = new Address();
                addresses.add(address);
                resource.setAddresses(addresses);
            }
            String addressPart = scimAttr.subSequence(scimAttr.lastIndexOf(".")+1, scimAttr.length()).toString();
            switch (addressPart) {
            case "country":
                address.setCountry((String) value);
                break;
            case "formatted":
                address.setFormatted((String) value);
                break;
            case "locality":
                address.setLocality((String) value);
                break;
            case "postalCode":
                address.setPostalCode((String) value);
                break;
            case "region":
                address.setRegion((String) value);
                break;
            case "streetAddress":
                address.setStreetAddress((String) value);
                break;
            case "type":
                address.setType((String) value);
                break;
            case "primary":
                address.setPrimary(Boolean.valueOf((String) value));
                break;

            }
        }
		else {
			ExtendedUserResource.addExtensionValueToUserRessource(resource, scimAttr, value);
		}
	}

	private boolean isMultiValue(ItemDefinition<?> itemDefinition) {
		return (itemDefinition.getMaxOccurs() == -1 || itemDefinition.getMaxOccurs() > 1);
	}

	/**
	 * Builds the meta data from the midPoint user.
	 *
	 * @param userType midPoint user
	 * @return meta data
	 */
	private Meta buildMetaData(UserType userType) {
		Meta meta = new Meta();
		if (userType.getMetadata() != null) {
			if (userType.getMetadata().getCreateTimestamp() != null) {
				meta.setCreated(userType.getMetadata().getCreateTimestamp().normalize().toGregorianCalendar());
			}
			if (userType.getMetadata().getModifyTimestamp() != null) {
				meta.setLastModified(userType.getMetadata().getModifyTimestamp().normalize().toGregorianCalendar());
			} else {
				meta.setLastModified(meta.getCreated());
			}
		}
		meta.setVersion(userType.getVersion());
		meta.setResourceType("User");
		try {
			meta.setLocation(new URI(getUserLocationUri(userType.getOid())));
		} catch (URISyntaxException e) {
			LOGGER.error("Could not create location", e);
		}
		return meta;
	}

	/**
	 * Converts UserResource to UserType
	 *
	 * @param userType      the actual user
	 * @param resource      the user resource to convert
	 * @param attributesMap
	 * @return UserType
	 * @throws SchemaException
	 * @throws IOException
	 * @throws JsonMappingException
	 * @throws JsonParseException
	 * @throws Scim2WebServiceException
	 * @throws DatatypeConfigurationException
	 */
    protected UserType mapToUserType(UserType userType, UserResource resource, Map<String, Object> attributesMap)
            throws SchemaException, JsonParseException, JsonMappingException, IOException, Scim2WebServiceException,
            DatatypeConfigurationException {
		if (userType == null) {
			userType = new UserType(prismContext);
		}

		PrismObject<UserType> user = userType.asPrismObject();

		if (user.getExtensionContainerValue() != null) {
			user.getExtensionContainerValue().clear();
		}

		Set<String> attributes = attributesMap.keySet();
		if (attributes.contains("emails")) {
			if (resource.getEmails() == null || resource.getEmails().isEmpty()) {
				addItemToUser(user, getQName("emails"), null);
			} else {
				int primaryMailsCount = getPrimaryMailsCount(resource.getEmails());
				if (primaryMailsCount > 1) {
					throw new Scim2WebServiceUnprocessableEntryException(
							"Can't process multiple primary mails!", "fatal");
				}
				if (primaryMailsCount == 0) {
					// if there is no primary mail, first mail in the list is treated as primary
					resource.getEmails().get(0).setPrimary(true);
				}
				for (Email nextEmail : resource.getEmails()) {
					if (nextEmail != null && nextEmail.getPrimary() != null
							&& nextEmail.getPrimary()) {
						addItemToUser(user, getQName("emails"), nextEmail.getValue());
					} else {
						addItemToUser(user, config.getConfiguredAdditionalEMailAttribute(),
								nextEmail.getValue());
					}
				}
			}
		}
		if (attributes.contains("phoneNumbers")) {
			if (resource.getPhoneNumbers() == null || resource.getPhoneNumbers().isEmpty()) {
				addItemToUser(user, getQName("phoneNumbers"), null);
			} else {
				int primaryPhoneNumber = getPrimaryPhoneNumbersCount(resource.getPhoneNumbers());
				if (primaryPhoneNumber > 1) {
					throw new Scim2WebServiceUnprocessableEntryException(
							"Can't process multiple primary phone numbers!", "fatal");
				}
				if (primaryPhoneNumber == 0) {
					// if there is no primary phone number, first phone number in the list is treated as primary
					resource.getPhoneNumbers().get(0).setPrimary(true);
				}
				for (PhoneNumber phoneNumber : resource.getPhoneNumbers()) {
					if (phoneNumber != null && phoneNumber.getPrimary() != null
							&& phoneNumber.getPrimary()) {
						addItemToUser(user, getQName("phoneNumbers"), phoneNumber.getValue());
					}
				}
			}
		}
		if (attributes.contains("userName")) {
			addItemToUser(user, getQName("userName"), resource.getUserName());
		}
		if (attributes.contains("displayName")) {
			addItemToUser(user, getQName("displayName"), resource.getDisplayName());
		}
		if (attributes.contains("nickName")) {
			addItemToUser(user, getQName("nickName"), resource.getNickName());
		}
		if (attributes.contains("phoneNumbers")) {
			if (resource.getPhoneNumbers() == null || resource.getPhoneNumbers().isEmpty()) {
				addItemToUser(user, getQName("phoneNumbers"), null);
			} else {
				addItemToUser(user, getQName("phoneNumbers"), resource.getPhoneNumbers().get(0).getValue());
			}
		}
		if (attributes.contains("title")) {
			addItemToUser(user, getQName("title"), resource.getTitle());
		}
		if (attributes.contains("userType")) {
			addItemToUser(user, getQName("userType"), resource.getUserType());
		}
		if (attributes.contains("locale")) {
			addItemToUser(user, getQName("locale"), resource.getLocale());
		}

		if (attributes.contains("name")) {
			Name name = resource.getName();

			if (name == null) {
				addItemToUser(user, getQName("name.familyName"), null);
				addItemToUser(user, getQName("name.middleName"), null);
				addItemToUser(user, getQName("name.formatted"), null);
				addItemToUser(user, getQName("name.givenName"), null);
				addItemToUser(user, getQName("name.honorificPrefix"), null);
				addItemToUser(user, getQName("name.honorificSuffix"), null);
			} else {
				Set<String> nameAttributes = ((Map<String, Object>) attributesMap.get("name")).keySet();
				if (nameAttributes.contains("familyName")) {
					addItemToUser(user, getQName("name.familyName"), name.getFamilyName());
				}
				if (nameAttributes.contains("middleName")) {
					addItemToUser(user, getQName("name.middleName"), name.getMiddleName());
				}
				if (nameAttributes.contains("formatted")) {
					addItemToUser(user, getQName("name.formatted"), name.getFormatted());
				}
				if (nameAttributes.contains("givenName")) {
					addItemToUser(user, getQName("name.givenName"), name.getGivenName());
				}
				if (nameAttributes.contains("honorificPrefix")) {
					addItemToUser(user, getQName("name.honorificPrefix"), name.getHonorificPrefix());
				}
				if (nameAttributes.contains("honorificSuffix")) {
					addItemToUser(user, getQName("name.honorificSuffix"), name.getHonorificSuffix());
				}
			}
		}

		if (attributes.contains("addresses")) {
			if (resource.getAddresses() == null || resource.getAddresses().isEmpty()) {
				addItemToUser(user, getQName("addresses.country"), null);
				addItemToUser(user, getQName("addresses.formatted"), null);
				addItemToUser(user, getQName("addresses.locality"), null);
				addItemToUser(user, getQName("addresses.postalCode"), null);
				addItemToUser(user, getQName("addresses.region"), null);
				addItemToUser(user, getQName("addresses.streetAddress"), null);
				addItemToUser(user, getQName("addresses.type"), null);
				addItemToUser(user, getQName("addresses.primary"), null);
			} else {
			    if (resource.getAddresses().size() > 1) {
			        throw new Scim2WebServiceBadRequestException("At most one address is supported", "request");
			    }
				Address address = resource.getAddresses().get(0);
				if (address.getCountry() != null) {
					addItemToUser(user, getQName("addresses.country"), address.getCountry());
				}
				if (address.getFormatted() != null) {
					addItemToUser(user, getQName("addresses.formatted"), address.getFormatted());
				}
				if (address.getLocality() != null) {
					addItemToUser(user, getQName("addresses.locality"), address.getLocality());
				}
				if (address.getPostalCode() != null) {
					addItemToUser(user, getQName("addresses.postalCode"), address.getPostalCode());
				}
				if (address.getRegion() != null) {
					addItemToUser(user, getQName("addresses.region"), address.getRegion());
				}
				if (address.getStreetAddress() != null) {
					addItemToUser(user, getQName("addresses.streetAddress"), address.getStreetAddress());
				}
				if (address.getType() != null) {
					addItemToUser(user, getQName("addresses.type"), address.getType());
				}
				if (address.getPrimary() != null) {
					addItemToUser(user, getQName("addresses.primary"), address.getPrimary());
				}
			}
		}
		if (attributes.contains("active")) {
			userType = setActivation(resource, userType);
		}

		user = mapExtensionsToUserType(resource, user);

		return user.asObjectable();
	}

	/**
	 * Returns count of primary emails
	 * @param emails list of emails
	 * @return count of Emails with falg primary = true
	 */
	private int getPrimaryMailsCount(List<Email> emails) {
		int result = 0;
		for (Email next : emails) {
			if (next.getPrimary() != null && next.getPrimary()) {
				result++;
			}
		}
		return result;
	}

	/**
	 * Returns count of primary phone numbers
	 * @param phoneNumbers list of phone numbers
	 * @return count of phoneNumbers with falg primary = true
	 */
	private int getPrimaryPhoneNumbersCount(List<PhoneNumber> emails) {
		int result = 0;
		for (PhoneNumber next : emails) {
			if (next.getPrimary() != null && next.getPrimary()) {
				result++;
			}
		}
		return result;
	}

	protected PrismObject<UserType> mapExtensionsToUserType(UserResource resource, PrismObject<UserType> user)
			throws Scim2WebServiceException, Scim2WebServiceBadRequestException, SchemaException, IOException,
			JsonParseException, JsonMappingException, DatatypeConfigurationException {
		ObjectNode extensionNode = resource.getExtensionObjectNode();
		if (extensionNode != null) {
			Iterator<Entry<String, JsonNode>> extensionEntries = extensionNode.fields();
			while (extensionEntries.hasNext()) {
				Entry<String, JsonNode> extensionEntry = extensionEntries.next();
				Iterator<Entry<String, JsonNode>> fields = extensionEntry.getValue().fields();
				while (fields.hasNext()) {
					Entry<String, JsonNode> entry = fields.next();
					processField(user, extensionEntry, entry, "");
				}
			}
		}
		return user;
	}

    protected void processField(PrismObject<UserType> user, Entry<String, JsonNode> extensionEntry,
            Entry<String, JsonNode> entry, String prefix)
            throws Scim2WebServiceException, Scim2WebServiceBadRequestException, SchemaException, IOException,
            JsonParseException, JsonMappingException, DatatypeConfigurationException {
		if (entry.getValue().getNodeType().equals(JsonNodeType.OBJECT)) {
			Iterator<Entry<String, JsonNode>> fields = entry.getValue().fields();
			while (fields.hasNext()) {
				processField(user, extensionEntry, fields.next(), entry.getKey() + ".");
			}

		} else {
			QName qName = new QName(extensionEntry.getKey(), prefix + entry.getKey());
			QName key = getQName(Scim2WebServiceConfig.toPropertyName(qName));

			if (key == null) {
				throw new Scim2WebServiceBadRequestException("No mapping found for property " + Scim2WebServiceConfig.toPropertyName(qName),
						"configuration");
			}

			if (entry.getValue() instanceof ArrayNode) {
				ArrayNode arrayNode = (ArrayNode) entry.getValue();
				Iterator<JsonNode> arrayNodeElements = arrayNode.elements();
				if (arrayNodeElements.hasNext()) {
					while (arrayNodeElements.hasNext()) {
						JsonNode node2 = arrayNodeElements.next();
						addItemToUser(user, key, node2.asText(), true);
					}
				} else {
					addItemToUser(user, key, null, false);
				}
			} else {
				Object value = JsonUtils.nodeToValue(entry.getValue(), String.class);
				addItemToUser(user, key, value, false);
			}
		}
	}

    private void addItemToUser(PrismObject<UserType> user, QName qName, Object value)
            throws SchemaException, DatatypeConfigurationException {
		addItemToUser(user, qName, value, false);
	}

	private void addItemToUser(PrismObject<UserType> user, QName qName, Object value, boolean multiple)
			throws SchemaException, DatatypeConfigurationException {
		if (qName != null) {
			UserType userType = user.asObjectable();

			if (!qName.equals(ExtendedUserResource.F_ACTIVATION)) {
			    Object convertedValue = value;
				if (config.getExtendedAttributes().containsKey(qName)) {
				    // Init extension
				    getExtension(userType);
	                ItemDefinition<?> definition = user.getExtension().getDefinition().findItemDefinition(ItemPath.create(qName));
	                convertedValue = convertToMidpoint(value, qName, (PrismPropertyDefinition) definition);
					addPropertyValue(getExtension(userType).asPrismContainerValue(), qName, convertedValue,
							multiple);
				} else {
				    ItemDefinition<?> definition = user.getDefinition().findItemDefinition(ItemPath.create(qName));
				    convertedValue = convertToMidpoint(value, qName, (PrismPropertyDefinition) definition);
					addPropertyValue(userType.asPrismContainerValue(), qName, convertedValue, multiple);
				}
			}
		} else {
			throw new SchemaException("No mapping found for property " + Scim2WebServiceConfig.toPropertyName(qName));
		}
	}

    private Object convertToMidpoint(Object value, QName qName, PrismPropertyDefinition<?> definition)
            throws DatatypeConfigurationException {
        Object convertedValue = value;

        if (definition instanceof PrismPropertyDefinition) {
            QName type = definition.getTypeName();

            if (PolyStringType.COMPLEX_TYPE.equals(type)) {
                convertedValue = new PolyString(value.toString());
            } else if (DOMUtil.XSD_DATETIME.equals(type)) {
                convertedValue = DatatypeFactory.newInstance().newXMLGregorianCalendar(value.toString());
            } else if (DOMUtil.XSD_BOOLEAN.equals(type)) {
                convertedValue = Boolean.valueOf(value.toString());
            } else if (DOMUtil.XSD_INTEGER.equals(type) || DOMUtil.XSD_INT.equals(type)) {
                convertedValue = Integer.valueOf(value.toString());
            }
        }

        return convertedValue;
    }

    /**
	 * Sets the activation.
	 *
	 * @param resource
	 * @param userType
	 * @return Updated userType
	 */
	protected UserType setActivation(UserResource resource, UserType userType) {
		ActivationStatusType statusType;
		if (resource.getActive() == null) {
			statusType = null;
		} else if (resource.getActive()) {
			statusType = ActivationStatusType.ENABLED;
		} else {
			statusType = ActivationStatusType.DISABLED;
		}

		ActivationType activation = new ActivationType(prismContext);
		activation.setAdministrativeStatus(statusType);
		userType.setActivation(activation);

		return userType;
	}

	/**
	 * Adds a property value to {@code container}.
	 *
	 * @param container the container to add the property to
	 * @param name      the property name
	 * @param value     the property value
	 */
	private <T> void addPropertyValue(PrismContainerValue<?> container, QName name, T value, boolean add) {
		Validate.notNull(container, "Container must not be null.");
		Validate.notNull(name, "QName must not be null.");

		PrismProperty<Object> property;
		try {
			property = container.findOrCreateProperty(ItemPath.create(name));
		} catch (SchemaException e) {
			// This should not happen. Code generator and compiler should take care of that.
			throw new IllegalStateException("Internal schema error: " + e.getMessage(), e);
		}
		Object propertyRealValue = JaxbTypeConverter.mapJaxbToPropertyRealValue(value);
		if (add) {
			property.addValue(prismContext.itemFactory().createPropertyValue(propertyRealValue));
		} else {
			property.setValue(prismContext.itemFactory().createPropertyValue(propertyRealValue));
		}
	}

	/**
	 * Returns the extension of {@code userType}. It creates it, if non yet set.
	 *
	 * @param userType
	 * @return the extension
	 */
	private ExtensionType getExtension(UserType userType) {
		ExtensionType extensionType = userType.getExtension();
		if (extensionType == null) {
			extensionType = new ExtensionType();
			userType.setExtension(extensionType);
		}
		return extensionType;
	}

	/**
	 * Executes a midPoint search
	 *
	 * @param scimFilter   SCIM filter
	 * @param offset       start index
	 * @param itemsPerPage count
	 * @param sortBy       attribute to sort by
	 * @param sortOrder    sort order
	 * @param task         task instance
	 * @param result       operation result
	 * @return list of found users
	 * @throws CommonException
	 * @throws Scim2WebServiceException
	 */
	protected <T> List<PrismObject<UserType>> findUsers(Filter scimFilter, Integer offset, Integer itemsPerPage,
			String sortBy, String sortOrder, Task task, OperationResult result)
			throws CommonException, Scim2WebServiceException {

		StopWatch sw = StopWatch.createStarted();
		ObjectQuery query = prismContext.queryFactory().createQuery(createObjectFilter(scimFilter));
		ExtendedQName propertyName = null;
		if (scimFilter != null && scimFilter.getAttributePath() != null) {
			propertyName = getQName(scimFilter.getAttributePath().toString());
		}

		ObjectPaging paging = null;
		if (propertyName != null && propertyName.isUnique() && FilterType.EQUAL.equals(scimFilter)) {
			LOGGER.debug("Setting paging to 0,1 for qname " + propertyName);
			paging = prismContext.queryFactory().createPaging(0, 1);
		} else if (offset >= 0 && itemsPerPage > 0) {
			paging = prismContext.queryFactory().createPaging(offset, itemsPerPage);
		} else if (itemsPerPage > 0) {
			paging = prismContext.queryFactory().createPaging(0, itemsPerPage);
		}

		if (paging != null) {
			if (sortBy != null) {
				ExtendedQName qName = getQName(sortBy);
				if (qName == null) {
					throw new Scim2WebServiceBadRequestException("No mapping found for property " + sortBy,
							"configuration");
				}
				// Default sortOrder is ascending
				OrderDirection direction = (sortOrder == null) ? OrderDirection.ASCENDING
						: OrderDirection.valueOf(sortOrder.toUpperCase());
				paging.setOrdering(ItemPath.create(qName), direction);
			}
			query.setPaging(paging);
		}

		Collection<SelectorOptions<GetOperationOptions>> searchOptions = SelectorOptions.createCollection(
				GetOperationOptions.createDefinitionProcessing(DefinitionProcessingOption.ONLY_IF_EXISTS));
		GetOperationOptions nonStaticOptions = new GetOperationOptions();
		searchOptions = SelectorOptions.createCollection(nonStaticOptions);
		searchOptions.addAll(GetOperationOptions.createNoFetchCollection());
		searchOptions.addAll(GetOperationOptions.createReadOnlyCollection());
		searchOptions.addAll(GetOperationOptions.createRawCollection());
		searchOptions.addAll(SelectorOptions.createCollection(GetOperationOptions.createDontRetrieve()));
		nonStaticOptions.setAttachDiagData(false);

		List<PrismObject<UserType>> foundObjects = new ArrayList<PrismObject<UserType>>();
		ResultHandler<UserType> resultHandler = new ResultHandler<UserType>() {

			@Override
			public boolean handle(PrismObject<UserType> object, OperationResult parentResult) {
				foundObjects.add(object);
				return foundObjects.size() < itemsPerPage;
			}
		};
		modelService.searchObjectsIterative(UserType.class, query, resultHandler, searchOptions, task, result);

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Query {} returned {} objects", query.toString(), foundObjects.size());
		}
		LOGGER.debug("STOPWATCH searchObjects {}", sw.getTime());
		return foundObjects;
	}

	/**
	 * Gets the object with the given id.
	 *
	 * @param id     object id
	 * @param task   task instance
	 * @param result operation result
	 * @return the object with the given id
	 * @throws CommonException
	 * @throws Scim2WebServiceException
	 * @throws BadRequestException
	 */
	private PrismObject<UserType> getUser(String id, Task task, OperationResult result)
			throws CommonException, Scim2WebServiceException, BadRequestException {
		PrismObject<UserType> foundObject = null;

		if (config.getIdentifierQName() != null && !config.getIdentifierRegExp().isEmpty() && id.matches(config.getIdentifierRegExp())) {
			List<PrismObject<UserType>> users = findUsers(Filter.eq(config.mapAttrToScim( config.getIdentifierQName() ), id), -1, -1, null,
					null, task, result);
			if (users != null && users.size() == 1) {
				foundObject = users.get(0);
			} else if (users.size() > 1) {
				throw new Scim2WebServiceNotUniqueException("More than one objects found for id " + id, "fatal");
			}
		} else {
			foundObject = modelService.getObject(UserType.class, id, null, task, result);
		}
		return foundObject;

	}

	protected <T> ObjectFilter createObjectFilter(Filter scimFilter) throws SchemaException, Scim2WebServiceException {
		ObjectFilter objectFilter = null;
		if (scimFilter == null) {
			objectFilter = prismContext.queryFactory().createAll();
		} else {
			boolean isNotFilter = false;
			while (scimFilter.isNotFilter()) {
				scimFilter = scimFilter.getInvertedFilter();
				isNotFilter = !isNotFilter;
			}
			//handle mails
			if (scimFilter.isCombiningFilter()) {
				List<Filter> combinedFilters = scimFilter.getCombinedFilters();
				List<ObjectFilter> objectFilters = new ArrayList<ObjectFilter>();
				for (Filter filter : combinedFilters) {
					objectFilters.add(createObjectFilter(filter));
				}
				FilterType filterType = scimFilter.getFilterType();
				switch (filterType) {
				case AND:
					objectFilter = prismContext.queryFactory().createAnd(objectFilters);
					break;
				case OR:
					objectFilter = prismContext.queryFactory().createOr(objectFilters);
					break;
				default:
					throw new Scim2WebServiceNotSupportedException("Filter type '" + filterType + "' not supported",
							"not implemented");
				}
			} else if (scimFilter.isComplexValueFilter()) {
				throw new Scim2WebServiceNotSupportedException("Complex value filter not supported", "not implemented");
			} else if (scimFilter.getAttributePath() != null) {
				String scimAttr = scimFilter.getAttributePath().toString();
				String value = "";
				QName propertyName = null;

				FilterType op = scimFilter.getFilterType();
				if (scimFilter.getComparisonValue() != null) {
					value = scimFilter.getComparisonValue().asText();
				}

				propertyName = getQName(scimAttr);
				if (propertyName == null) {
					LOGGER.warn("Bad attribute in filter: " + scimAttr);
					throw new Scim2WebServiceBadRequestException("Bad attribute in filter: " + scimAttr,
							"invalidFilter");
				}
				try {
					objectFilter = createSimpleObjectFilter(propertyName, value, op);
					// handle emails
					if (scimAttr.equals("emails")) {
						ObjectFilter additionalFilter = createSimpleObjectFilter(
							config.getConfiguredAdditionalEMailAttribute(), value, op);
						List<ObjectFilter> combinedFilters = new ArrayList<ObjectFilter>();
						combinedFilters.add(objectFilter);

						if (additionalFilter != null) {
							combinedFilters.add(additionalFilter);
						}

						objectFilter = prismContext.queryFactory().createOr(combinedFilters);
					}
				} catch (ParseException | DatatypeConfigurationException e) {
					throw new Scim2WebServiceBadRequestException(e.getMessage(), "invalidFilter");
				}
			} else {
				throw new Scim2WebServiceNotSupportedException("Filter '" + scimFilter + "' not supported",
						"not implemented");
			}

			if (isNotFilter && objectFilter != null) {
				objectFilter = prismContext.queryFactory().createNot(objectFilter);
			}
		}
		return objectFilter;
	}

	/**
	 * Creates an object filter according to the SCIM operation.
	 *
	 * @param property property name
	 * @param value    property value
	 * @param op       SCIM operation
	 * @return search query
	 * @throws SchemaException
	 * @throws Scim2WebServiceException
	 * @throws ParseException
	 * @throws DatatypeConfigurationException
	 */
	protected ObjectFilter createSimpleObjectFilter(QName property, Object value, FilterType op)
			throws SchemaException, Scim2WebServiceException, ParseException, DatatypeConfigurationException {

		if (property == null) {
			return null;
		}

		PrismPropertyDefinition<?> def = getUserDefinition().getExtensionDefinition().findPropertyDefinition(ItemPath.create(property));
		ItemPath itemPath = ItemPath.create(SchemaConstantsGenerated.C_EXTENSION, property);
		if (def == null) {
			def = getUserDefinition().findPropertyDefinition(ItemPath.create(property));
			itemPath = ItemPath.create(property);
		}
		if (def == null) {
			def = getMetadataDefinition().findPropertyDefinition(ItemPath.create(property));
			itemPath = ItemPath.create(new QName(SchemaConstantsGenerated.NS_COMMON, "metadata"), property);
		}
		if (def == null) {
			property = ExtendedUserResource.F_EFFECTIVE_STATUS;
			def = getActivationDefinition().findPropertyDefinition(ItemPath.create(property));
			itemPath = ItemPath.create(ExtendedUserResource.F_ACTIVATION, property);
			if (value != null) {
				String sValue = value.toString().toLowerCase();
				value = ActivationStatusType.ENABLED;
				if (sValue.equals("false")) {
					if (FilterType.EQUAL.equals(op)) {
						op = FilterType.NOT_EQUAL;
					} else if (FilterType.NOT_EQUAL.equals(op)) {
						op = FilterType.EQUAL;
					}
				}
			}
		}
		if (def == null) {
			throw new Scim2WebServiceInternalErrorException(
					"Did not find property " + property.toString() + " in user definitions!", "fatal");
		}
		//
		Class<?> typeClass = null;
		if (def.getTypeClass() != null) {
			typeClass = def.getTypeClass();
		} else if (def.getTypeClass() != null) {
			typeClass = def.getTypeClass();
		} else {
			typeClass = IllegalArgumentException.class;
		}

		if (LOGGER.isDebugEnabled()) {
			String prop = property.toString();
			String typeName = (def.getTypeName() != null) ? def.getTypeName().toString() : null;
			LOGGER.debug("Property {}, TypeClass {}, TypeName {}", prop, typeClass.getName(), typeName);
		}

		// See https://jira.cornelsen.de/browse/BIDM-288
		ObjectFilter filter;
		QName matchingRule = PrismConstants.DEFAULT_MATCHING_RULE_NAME;
		if (String.class.equals(typeClass)) {
			matchingRule = PrismConstants.STRING_IGNORE_CASE_MATCHING_RULE_NAME;
		} else if (PolyString.class.equals(typeClass)) {
			matchingRule = PrismConstants.POLY_STRING_NORM_MATCHING_RULE_NAME;
		} else if (XMLGregorianCalendar.class.equals(typeClass)) {
			matchingRule = XMLGregorianCalendarMatchingRule.NAME;
			value = (Object) DatatypeFactory.newInstance().newXMLGregorianCalendar(value.toString());
		} else {
			LOGGER.warn(
					"Unknown type class {} detected. Using '{}' matching rule. This can lead to unexpected results!",
					typeClass.getName(), matchingRule.toString());
		}

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Matchingrule: {}", matchingRule);
		}
		switch (op) {
		case EQUAL:
			filter = prismContext.queryFactory().createEqual(itemPath, def, matchingRule, prismContext,
					prismContext.itemFactory().createPropertyValue(value));
			break;
		case CONTAINS:
			filter = SubstringFilterImpl.createSubstring(itemPath, def, matchingRule, prismContext.itemFactory().createPropertyValue(value), false, false);
			break;
		case STARTS_WITH:
			filter = SubstringFilterImpl.createSubstring(itemPath, def, matchingRule,
					prismContext.itemFactory().createPropertyValue(value), true, false);
			break;
		case ENDS_WITH:
			filter = SubstringFilterImpl.createSubstring(itemPath, def, matchingRule,
					prismContext.itemFactory().createPropertyValue(value), false, true);
			break;
		case PRESENT:
			filter = SubstringFilterImpl.createSubstring(itemPath, def, matchingRule,
					prismContext.itemFactory().createPropertyValue(""), false, false);
			break;
		case NOT_EQUAL:
			filter = prismContext.queryFactory().createNot(prismContext.queryFactory().createEqual(itemPath, def, matchingRule, prismContext,
					prismContext.itemFactory().createPropertyValue(value)));
			break;
		case GREATER_THAN:
			filter = prismContext.queryFactory().createGreater(itemPath, def, matchingRule, prismContext.itemFactory().createPropertyValue(value),
					false, prismContext);
			break;
		case GREATER_OR_EQUAL:
			filter = prismContext.queryFactory().createGreater(itemPath, def, matchingRule, prismContext.itemFactory().createPropertyValue(value),
					true, prismContext);
			break;
		case LESS_THAN:
			filter = prismContext.queryFactory().createLess(itemPath, def, matchingRule, prismContext.itemFactory().createPropertyValue(value), false,
					prismContext);
			break;
		case LESS_OR_EQUAL:
			filter = prismContext.queryFactory().createLess(itemPath, def, matchingRule, prismContext.itemFactory().createPropertyValue(value), true,
					prismContext);
			break;
		default:
			throw new Scim2WebServiceNotSupportedException("Operation '" + op + "' not supported", "not implemented");
		}
		return filter;
	}

	/**
	 * Extracts user definition from the prism context
	 *
	 * @return
	 */
	private PrismObjectDefinition<? extends UserType> getUserDefinition() {
		if (userDefinition == null) {
			userDefinition = prismContext.getSchemaRegistry().findObjectDefinitionByCompileTimeClass(UserType.class);
		}
		return userDefinition;
	}

	/**
	 * Extracts metadata definition from the prism context
	 *
	 * @return
	 */
	private ComplexTypeDefinition getMetadataDefinition() {
		if (metadataDefinition == null) {
			metadataDefinition = prismContext.getSchemaRegistry()
					.findComplexTypeDefinitionByCompileTimeClass(MetadataType.class);
		}
		return metadataDefinition;
	}

	/**
	 * Extracts activation definition from the prism context
	 *
	 * @return
	 */
	private ComplexTypeDefinition getActivationDefinition() {
		if (activationDefinition == null) {
			activationDefinition = prismContext.getSchemaRegistry()
					.findComplexTypeDefinitionByCompileTimeClass(ActivationType.class);
		}
		return activationDefinition;
	}


	protected ExtendedQName buildMapping(String value, String nameSpace) {
		if (value.indexOf(":") >= 0) {
			nameSpace = StringUtils.substringBeforeLast(value, ":");
			value = StringUtils.substringAfterLast(value, ":");
		}
		return new ExtendedQName(nameSpace, value);
	}

	protected Map<String, List<String>> getMappings(Configuration config) throws Scim2WebServiceException {
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

    @Override
    protected Task initRequest() {
        return super.initRequest();
    }

//	protected Task createTaskInstance(String operationName) {
//		return super.createTaskInstance(operationName);
//	}
//
//	@Override
//	protected void auditLogin(Task task) {
//		if( config.isEnableAuditLogin() ) {
//			super.auditLogin(task);
//		}
//	}

}
