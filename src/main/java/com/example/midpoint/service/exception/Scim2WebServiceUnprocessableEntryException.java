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

public class Scim2WebServiceUnprocessableEntryException extends Scim2WebServiceException {

    public Scim2WebServiceUnprocessableEntryException( String message, String scimDetail ) {
        super(new UnprocessableEntryStatus(), message, scimDetail);
    }

    public Scim2WebServiceUnprocessableEntryException( String message, String scimDetail, Throwable cause) {
        super(new UnprocessableEntryStatus().toEnum(), message, scimDetail, cause);
    }
}
