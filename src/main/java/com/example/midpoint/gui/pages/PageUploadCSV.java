/*
 * Copyright (C) 2010-2020 Evolveum and contributors
 *
 * This work is dual-licensed under the Apache License 2.0
 * and European Union Public License. See LICENSE file for details.
 */
package com.example.midpoint.gui.pages;

import java.io.FileInputStream;
import java.io.InputStream;

import org.apache.commons.io.FileUtils;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.upload.FileUpload;
import org.apache.wicket.markup.html.form.upload.FileUploadField;
import org.apache.wicket.util.file.File;
import org.jetbrains.annotations.NotNull;

import com.evolveum.midpoint.authentication.api.authorization.AuthorizationAction;
import com.evolveum.midpoint.authentication.api.authorization.PageDescriptor;
import com.evolveum.midpoint.authentication.api.authorization.Url;
import com.evolveum.midpoint.authentication.api.util.AuthConstants;
import com.evolveum.midpoint.schema.result.OperationResult;
import com.evolveum.midpoint.security.api.AuthorizationConstants;
import com.evolveum.midpoint.task.api.Task;
import com.evolveum.midpoint.util.logging.LoggingUtils;
import com.evolveum.midpoint.util.logging.Trace;
import com.evolveum.midpoint.util.logging.TraceManager;
import com.evolveum.midpoint.web.component.AjaxSubmitButton;
import com.evolveum.midpoint.web.component.form.MidpointForm;
import com.evolveum.midpoint.web.page.admin.PageAdmin;
import com.evolveum.midpoint.web.security.MidPointApplication;
import com.evolveum.midpoint.web.security.WebApplicationConfiguration;

/**
 * @author asd
 * @author asd
 */
@PageDescriptor(
        urls = {
                @Url(mountUrl = "/admin/config/upload", matchUrlForSecurity = "/admin/config/upload")
        },
        action = {
        @AuthorizationAction(actionUri = AuthConstants.AUTH_CONFIGURATION_ALL, label = AuthConstants.AUTH_CONFIGURATION_ALL_LABEL, description = AuthConstants.AUTH_CONFIGURATION_ALL_DESCRIPTION),
        @AuthorizationAction(actionUri = AuthorizationConstants.AUTZ_UI_CONFIGURATION_IMPORT_URL, label = "CSV upload", description = "Upload CSV users") })

public class PageUploadCSV extends PageAdmin {

    private static final Trace LOGGER = TraceManager.getTrace(PageUploadCSV.class);
    private static final String DOT_CLASS = PageUploadCSV.class.getName() + ".";
    private static final String OPERATION_UPLOAD_CVS_FILE = DOT_CLASS + "uploadFile";

    private static final String ID_MAIN_FORM = "mainForm";
    private static final String ID_BUTTON_BAR = "buttonBar";
    private static final String ID_IMPORT_OPTIONS = "importOptions";
    private static final String ID_BACK_BUTTON = "back";
    private static final String ID_IMPORT_CVS_BUTTON = "importFileButton";
    private static final String ID_INPUT = "input";
    private static final String ID_INPUT_FILE_LABEL = "inputFileLabel";
    private static final String ID_INPUT_FILE = "inputFile";
    private static final String ID_FILE_INPUT = "fileInput";

    private static final String LANG_CSV = "csv";

    public PageUploadCSV() {
        initLayout();
    }

    private void initLayout() {
        Form<?> mainForm = new MidpointForm<>(ID_MAIN_FORM);
        mainForm.setMultiPart(true);
        add(mainForm);

        final WebMarkupContainer input = new WebMarkupContainer(ID_INPUT);
        input.setOutputMarkupId(true);
        mainForm.add(input);

        WebMarkupContainer buttonBar = new WebMarkupContainer(ID_BUTTON_BAR);
        buttonBar.setOutputMarkupId(true);
        mainForm.add(buttonBar);

        WebMarkupContainer inputFileLabel = new WebMarkupContainer(ID_INPUT_FILE_LABEL);
        input.add(inputFileLabel);

        WebMarkupContainer inputFile = new WebMarkupContainer(ID_INPUT_FILE);
        input.add(inputFile);

        FileUploadField fileInput = new FileUploadField(ID_FILE_INPUT);
        inputFile.add(fileInput);

        initButtons(buttonBar);
    }

    private void initButtons(WebMarkupContainer buttonBar) {
        AjaxSubmitButton saveFileButton = new AjaxSubmitButton(ID_IMPORT_CVS_BUTTON) {

            @Override
            protected void onSubmit(AjaxRequestTarget target) {
                savePerformed(false, OPERATION_UPLOAD_CVS_FILE, target);
            }

            @Override
            protected void onError(AjaxRequestTarget target) {
                target.add(getFeedbackPanel());
            }
        };

        
        buttonBar.add(saveFileButton);
    }

    private FileUpload getUploadedFile() {
        FileUploadField file = (FileUploadField) get(
                createComponentPath(ID_MAIN_FORM, ID_INPUT, ID_INPUT_FILE, ID_FILE_INPUT));
        return file.getFileUpload();
    }

    private static class InputDescription {
        private final InputStream inputStream;
        private final String dataLanguage;

        InputDescription(InputStream inputStream, String dataLanguage) {
            this.inputStream = inputStream;
            this.dataLanguage = dataLanguage;
        }
    }

    @NotNull
    private InputDescription getInputDescription(boolean editor) throws Exception {

        File newFile = null;

        MidPointApplication application = getMidpointApplication();
        WebApplicationConfiguration config = application.getWebApplicationConfiguration();
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
        newFile.createNewFile();

        FileUtils.copyInputStreamToFile(uploadedFile.getInputStream(), newFile);

//      TODO check how to handle this There is no CSV file handeling in prism
        String language = newFile.getName().endsWith(".csv") ? LANG_CSV : null;

        return new InputDescription(new FileInputStream(newFile), language);

    }

    private void clearOldFeedback() {
        getSession().getFeedbackMessages().clear();
        getFeedbackMessages().clear();
    }

    private void savePerformed(boolean raw, String operationName, AjaxRequestTarget target) {
        clearOldFeedback();

        OperationResult result = new OperationResult(operationName);

        try {
            Task task = createSimpleTask(operationName);
            InputDescription inputDescription = getInputDescription(raw);
                result.recomputeStatus();
        } catch (Exception ex) {
            result.recordFatalError("Couldn't upload file", ex);
            LoggingUtils.logUnexpectedException(LOGGER, "Couldn't upload file", ex);
        }

        showResult(result);
        if (result.isFatalError()) {
            target.add(getFeedbackPanel());
        } else {
            target.add(PageUploadCSV.this);
        }
    }
}
