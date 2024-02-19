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

import java.util.ArrayList;
import java.util.List;

import com.example.midpoint.schema.ExampleSchemaConstants;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.basic.Label;

import com.evolveum.midpoint.gui.impl.page.admin.AbstractObjectMainPanel;
import com.evolveum.midpoint.gui.impl.page.admin.focus.FocusDetailsModels;
import com.evolveum.midpoint.prism.PrismObject;
import com.evolveum.midpoint.prism.query.ObjectQuery;
import com.evolveum.midpoint.task.api.Task;
import com.evolveum.midpoint.util.logging.LoggingUtils;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;
import com.evolveum.midpoint.web.application.PanelType;
import com.evolveum.midpoint.web.component.assignment.SimpleRoleSelector;
import com.evolveum.midpoint.web.model.PrismContainerWrapperModel;
import com.evolveum.midpoint.xml.ns._public.common.common_3.AssignmentType;
import com.evolveum.midpoint.xml.ns._public.common.common_3.ContainerPanelConfigurationType;
import com.evolveum.midpoint.xml.ns._public.common.common_3.FocusType;
import com.evolveum.midpoint.xml.ns._public.common.common_3.RoleType;


@PanelType(name = "rolesFormPanel")
public class RolesFormDetailsViewPanel<F extends FocusType> extends AbstractObjectMainPanel<F, FocusDetailsModels<F>> {

    private static final long serialVersionUID = 1L;

    private static final String DOT_CLASS = RolesFormDetailsViewPanel.class.getName() + ".";

    private static final String OPERATION_SEARCH_ROLES = DOT_CLASS + "searchRoles";

    private static final String ID_HEADER = "header";

    private static final String ID_ROLES_SIMPLE = "rolesSimple";

    private static final Trace LOGGER = TraceManager.getTrace(RolesFormDetailsViewPanel.class);

    public RolesFormDetailsViewPanel(String id, FocusDetailsModels<F> model, ContainerPanelConfigurationType config) {
        super(id, model, config);
    }

    protected void initLayout() {
        add(new Label(ID_HEADER, "Object details"));
        WebMarkupContainer body = new WebMarkupContainer("body");
        add(body);

        Task task = getPageBase().createSimpleTask(OPERATION_SEARCH_ROLES, null);
        List<PrismObject<RoleType>> availableSimpleRoles;
        try {
            ObjectQuery simpleRoleQuery = getPageBase().getPrismContext()
                    .queryFor(RoleType.class)
                    .item(RoleType.F_SUBTYPE).eq(ExampleSchemaConstants.ROLE_TYPE_SIMPLE)
                    .build();

            availableSimpleRoles = getPageBase().getModelService()
                    .searchObjects(RoleType.class, simpleRoleQuery, null, task, task.getResult());
        } catch (Throwable e) {
            task.getResult().recordFatalError(e);
            LoggingUtils.logException(LOGGER, "Couldn't load roles", e);
            availableSimpleRoles = new ArrayList<>();
        }

        PrismContainerWrapperModel<F, AssignmentType> assignmentsModel =
                PrismContainerWrapperModel.fromContainerWrapper(getObjectWrapperModel(), FocusType.F_ASSIGNMENT);

        add(new SimpleRoleSelector<>(ID_ROLES_SIMPLE, assignmentsModel, availableSimpleRoles));
    }


}
