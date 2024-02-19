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

import com.evolveum.midpoint.prism.PrismConstants;
import com.evolveum.midpoint.prism.match.MatchingRule;
import com.evolveum.midpoint.util.DOMUtil;
import com.evolveum.midpoint.util.exception.SchemaException;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import java.util.regex.Pattern;

public class XMLGregorianCalendarMatchingRule implements MatchingRule<XMLGregorianCalendar> {

	public static final QName NAME = new QName(PrismConstants.NS_MATCHING_RULE, "xmlGregorianCalendar");

	public XMLGregorianCalendarMatchingRule() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public QName getName() {
		return NAME;
	}

	@Override
	public boolean supports(QName xsdType) {
		return (DOMUtil.XSD_DATETIME.equals(xsdType));
	}

	@Override
	public boolean match(XMLGregorianCalendar a, XMLGregorianCalendar b) throws SchemaException {
		if (a == null && b == null) {
			return true;
		}
		if (a == null || b == null) {
			return false;
		}
		return a.equals(b);
	}

	@Override
	public boolean matchRegex(XMLGregorianCalendar a, String regex) throws SchemaException {
		if (a == null){
			return false;
		}

		return Pattern.matches(regex, a.toString());
	}

	@Override
	public XMLGregorianCalendar normalize(XMLGregorianCalendar original) throws SchemaException {
		return original;
	}

}
