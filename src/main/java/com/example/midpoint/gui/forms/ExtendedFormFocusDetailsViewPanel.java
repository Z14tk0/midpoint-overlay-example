/*
 * Copyright (C) 2016-2021 Evolveum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.midpoint.gui.forms;

import com.evolveum.midpoint.gui.impl.page.admin.focus.FocusDetailsModels;

import com.example.midpoint.schema.ExampleSchemaConstants;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.basic.Label;

import com.evolveum.midpoint.gui.impl.page.admin.AbstractObjectMainPanel;
import com.evolveum.midpoint.prism.path.ItemPath;
import com.evolveum.midpoint.util.DOMUtil;
import com.evolveum.midpoint.web.application.PanelType;
import com.evolveum.midpoint.xml.ns._public.common.common_3.*;
import com.evolveum.prism.xml.ns._public.types_3.PolyStringType;

import static com.evolveum.midpoint.gui.api.util.WebModelServiceUtils.createSimpleTask;

/**
 * Sample showing a custom focus form that displays semi-static form.
 * This form is using extended attributes and role parameters. It needs extension-samples.xsd.
 *
 * @author Radovan Semancik
 */
@PanelType(name = "extendedFormPanel")
public class ExtendedFormFocusDetailsViewPanel<F extends FocusType> extends AbstractObjectMainPanel<F, FocusDetailsModels<F>> {

    private static final long serialVersionUID = 1L;

    private static final String ID_HEADER = "header";

    private static final String ID_PROP_NAME = "propName";

    private static final String ID_PROP_FULL_NAME = "propFullName";

    private static final String ID_PROP_SSN = "propSsn";

    private static final String ID_PERSONAL_NUMBER = "propPersonalNumber";

    private static final String ID_PROP_HAIRCOLOR = "propHairColor";

    public ExtendedFormFocusDetailsViewPanel(String id, FocusDetailsModels<F> model, ContainerPanelConfigurationType config) {
        super(id, model, config);
    }

    protected void initLayout() {
        add(new Label(ID_HEADER, "Object details"));
        WebMarkupContainer body = new WebMarkupContainer("body");
        add(body);

        addPrismPropertyPanel(body, ID_PROP_NAME, PolyStringType.COMPLEX_TYPE, FocusType.F_NAME);
        addPrismPropertyPanel(body, ID_PROP_FULL_NAME, PolyStringType.COMPLEX_TYPE, UserType.F_FULL_NAME);
        addPrismPropertyPanel(body, ID_PROP_SSN, DOMUtil.XSD_STRING, ItemPath.create(ObjectType.F_EXTENSION, ExampleSchemaConstants.SCHEMA_EXTENSION_SSN));

        //Adding existing property to web form (aka Details User Panel).
        addPrismPropertyPanel(body, ID_PERSONAL_NUMBER, PolyStringType.COMPLEX_TYPE, UserType.F_PERSONAL_NUMBER);

        //Here we created new property to object in a from of extension (look at m_user table, ext attribute)
        addPrismPropertyPanel(body, ID_PROP_HAIRCOLOR, DOMUtil.XSD_STRING, ItemPath.create(ObjectType.F_EXTENSION, ExampleSchemaConstants.SCHEMA_EXTENSION_HAIRCOLOR));
    }

}
