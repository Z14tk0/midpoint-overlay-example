/**
 * Copyright: DAASI International GmbH 2020-2020. All rights reserved.
 *
 * This is Open Source Software
 * License: Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 *
 * Author: Tamim Ziai DAASI International GmbH, www.daasi.de
 * For questions please mail to info@daasi.de
 */
package com.example.midpoint.service.exception;

import com.example.midpoint.service.Scim2WebServiceException;
import jakarta.ws.rs.core.Response.Status;

public class Scim2WebServiceInternalErrorException extends Scim2WebServiceException {

	private static final long serialVersionUID = -6406285996263572162L;

	public Scim2WebServiceInternalErrorException( String message, String scimDetail ) {
		super(Status.INTERNAL_SERVER_ERROR, message, scimDetail);
	}

	public Scim2WebServiceInternalErrorException( String message, String scimDetail, Throwable cause) {
		super(Status.INTERNAL_SERVER_ERROR, message, scimDetail, cause);
	}

}
