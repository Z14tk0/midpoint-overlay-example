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

import org.apache.commons.io.FileUtils;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.upload.FileUpload;
import org.apache.wicket.markup.html.form.upload.FileUploadField;
import org.apache.wicket.util.file.File;
import org.jetbrains.annotations.NotNull;

import com.evolveum.midpoint.gui.impl.page.admin.AbstractObjectMainPanel;
import com.evolveum.midpoint.gui.impl.page.admin.focus.FocusDetailsModels;
import com.evolveum.midpoint.schema.result.OperationResult;
import com.evolveum.midpoint.util.logging.LoggingUtils;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;
import com.evolveum.midpoint.web.application.PanelType;
import com.evolveum.midpoint.web.component.AjaxSubmitButton;
import com.evolveum.midpoint.web.component.form.MidpointForm;
import com.evolveum.midpoint.web.security.MidPointApplication;
import com.evolveum.midpoint.web.security.WebApplicationConfiguration;
import com.evolveum.midpoint.xml.ns._public.common.common_3.ContainerPanelConfigurationType;
import com.evolveum.midpoint.xml.ns._public.common.common_3.FocusType;

@PanelType(name = "fileUploadFormPanel")
public class FileUploadFormDetailsViewPanel<F extends FocusType> extends AbstractObjectMainPanel<F, FocusDetailsModels<F>> {

    private static final long serialVersionUID = 1L;

    private static final String ID_HEADER = "header";

    private static final String ID_UPLOAD_FORM = "uploadForm";

    private static final String ID_BUTTON_BAR = "buttonBar";

    private static final String ID_INPUT = "input";

    private static final String ID_INPUT_FILE = "inputFile";

    private static final String ID_FILE_INPUT = "fileInput";

    private static final String ID_IMPORT_FILE_BUTTON = "importButton";

    private static final Trace LOGGER = TraceManager.getTrace(FileUploadFormDetailsViewPanel.class);

    public FileUploadFormDetailsViewPanel(String id, FocusDetailsModels<F> model, ContainerPanelConfigurationType config) {
        super(id, model, config);
    }

    protected void initLayout() {
        add(new Label(ID_HEADER, "Object details"));
        WebMarkupContainer body = new WebMarkupContainer("body");
        add(body);

        Form<?> mainForm = new MidpointForm<>(ID_UPLOAD_FORM);
        mainForm.setMultiPart(true);
        add(mainForm);

        WebMarkupContainer buttonBar = new WebMarkupContainer(ID_BUTTON_BAR);
        buttonBar.setOutputMarkupId(true);
        mainForm.add(buttonBar);
        final WebMarkupContainer input = new WebMarkupContainer(ID_INPUT);
        input.setOutputMarkupId(true);
        mainForm.add(input);
        WebMarkupContainer inputFile = new WebMarkupContainer(ID_INPUT_FILE);
        input.add(inputFile);

        FileUploadField fileInput = new FileUploadField(ID_FILE_INPUT);
        inputFile.add(fileInput);

        initButtons(buttonBar);

    }

    private void initButtons(@NotNull WebMarkupContainer buttonBar) {
        AjaxSubmitButton importFileButton = new AjaxSubmitButton(ID_IMPORT_FILE_BUTTON) {

            @Override
            protected void onSubmit(AjaxRequestTarget target) {
                saveFile(ID_IMPORT_FILE_BUTTON);
            }

            @Override
            protected void onError(AjaxRequestTarget target) {
                target.add(getPageBase().getFeedbackPanel());
            }
        };

        buttonBar.add(importFileButton);
    }

    private void saveFile(String operationName) {
        clearOldFeedback();
        OperationResult result = new OperationResult(operationName);
        MidPointApplication application = getPageBase().getMidpointApplication();
        WebApplicationConfiguration config = application.getWebApplicationConfiguration();

        File newFile = null;

        File folder = new File(config.getImportFolder());
        if (!folder.exists() || !folder.isDirectory()) {
            folder.mkdir();
        }

        FileUpload uploadedFile = getUploadedFile();
        newFile = new File(folder, uploadedFile.getClientFileName());

        // Check new file, delete if it already exists
        if (newFile.exists()) {
            newFile.delete();
        }

        // Save file
        try {
            newFile.createNewFile();
            FileUtils.copyInputStreamToFile(uploadedFile.getInputStream(), newFile);
        } catch (Exception ex) {
            result.recordFatalError(getString("PageImportObject.message.savePerformed.fatalError"), ex);
            LoggingUtils.logUnexpectedException(LOGGER, "Couldn't import file", ex);
        } finally {
//            if (newFile != null) {
//                FileUtils.deleteQuietly(newFile);
//            }
        }
    }

    private void clearOldFeedback() {
        getSession().getFeedbackMessages().clear();
        getFeedbackMessages().clear();
    }

    private FileUpload getUploadedFile() {
        FileUploadField file = (FileUploadField) get(getPageBase().createComponentPath(ID_UPLOAD_FORM, ID_INPUT, ID_INPUT_FILE, ID_FILE_INPUT));
        return file.getFileUpload();
    }

}

















//    private void savePerformed(String operationName, AjaxRequestTarget target) {
//        clearOldFeedback();
//
//        OperationResult result = new OperationResult(operationName);
//
//        try {
//            Task task = getPageBase().createSimpleTask(operationName);
//            InputDescription inputDescription = getInputDescription();
//            try (InputStream stream = inputDescription.inputStream) {
//                ImportOptionsType options = optionsModel.getObject();
//                if (isTrue(fullProcessingModel.getObject())) {
//                    options.setModelExecutionOptions(new ModelExecuteOptionsType(getPrismContext()).raw(false));
//                } else {
//                    options.setModelExecutionOptions(null);
//                }
//                getPageBase().getModelService().importObjectsFromStream(stream, inputDescription.dataLanguage, options, task, result);
//
//                result.recomputeStatus();
//            }
//        } catch (Exception ex) {
//            result.recordFatalError(getString("PageImportObject.message.savePerformed.fatalError"), ex);
//            LoggingUtils.logUnexpectedException(LOGGER, "Couldn't import file", ex);
//        }
//
//        getPageBase().showResult(result);
//        if (result.isFatalError()) {
//            target.add(getPageBase().getFeedbackPanel());
//        } else {
//            target.add(this);
//        }
//    }



//    private static class InputDescription {
//        private final InputStream inputStream;
//        private final String dataLanguage;
//
//        InputDescription(InputStream inputStream, String dataLanguage) {
//            this.inputStream = inputStream;
//            this.dataLanguage = dataLanguage;
//        }
//    }


//    @NotNull
//    private InputDescription getInputDescription() throws Exception {
//        File newFile = null;
//        try {
//            // Create new file
//            MidPointApplication application = getPageBase().getMidpointApplication();
//            WebApplicationConfiguration config = application.getWebApplicationConfiguration();
//            File folder = new File(config.getImportFolder());
//            if (!folder.exists() || !folder.isDirectory()) {
//                folder.mkdir();
//            }
//
//            FileUpload uploadedFile = getUploadedFile();
//            newFile = new File(folder, uploadedFile.getClientFileName());
//            // Check new file, delete if it already exists
//            if (newFile.exists()) {
//                newFile.delete();
//            }
//            // Save file
//
//            newFile.createNewFile();
//
//            FileUtils.copyInputStreamToFile(uploadedFile.getInputStream(), newFile);
//
//            String language = getPrismContext().detectLanguage(newFile);
//            return new InputDescription(new FileInputStream(newFile), language);
//        } finally {
//            if (newFile != null) {
//                FileUtils.deleteQuietly(newFile);
//            }
//        }
//    }



//    private boolean validateInput(boolean raw) {
//        if (raw) {
//            return StringUtils.isNotEmpty(xmlEditorModel.getObject());
//        }
//        return getUploadedFile() != null;
//
//    }
//
//
//}
