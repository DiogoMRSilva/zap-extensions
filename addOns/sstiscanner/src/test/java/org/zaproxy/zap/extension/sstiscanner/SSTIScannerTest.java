/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.IOException;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

// Based on ascanrules plugin tests
public class SSTIScannerTest extends ActiveScannerTestUtils<SSTIScanner> {

    private static final int SIZESMALLERTHATPOLYGLOT = 12;

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionSSTiScanner());
    }

    @Override
    protected SSTIScanner createScanner() {
        return new SSTIScanner();
    }

    @Test
    public void shouldSendReasonableNumberOfMessagesInLowStrength() throws Exception {
        // Given
        Plugin.AttackStrength strength = Plugin.AttackStrength.LOW;
        rule.setAttackStrength(strength);
        rule.init(getHttpMessage("?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(
                httpMessagesSent,
                hasSize(lessThanOrEqualTo(getRecommendMaxNumberMessagesPerParam(strength))));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldSendReasonableNumberOfMessagesInMediumStrength() throws Exception {
        // Given
        Plugin.AttackStrength strength = Plugin.AttackStrength.MEDIUM;
        rule.setAttackStrength(strength);
        rule.init(getHttpMessage("?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(
                httpMessagesSent,
                hasSize(lessThanOrEqualTo(getRecommendMaxNumberMessagesPerParam(strength) + 2)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldSendReasonableNumberOfMessagesInHighStrength() throws Exception {
        // Given
        Plugin.AttackStrength strength = Plugin.AttackStrength.HIGH;
        rule.setAttackStrength(strength);
        rule.init(getHttpMessage("?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(
                httpMessagesSent,
                hasSize(lessThanOrEqualTo(getRecommendMaxNumberMessagesPerParam(strength))));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldSendReasonableNumberOfMessagesInInsaneStrength() throws Exception {
        // Given
        Plugin.AttackStrength strength = Plugin.AttackStrength.INSANE;
        rule.setAttackStrength(strength);
        rule.init(getHttpMessage("?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(
                httpMessagesSent,
                hasSize(lessThanOrEqualTo(getRecommendMaxNumberMessagesPerParam(strength))));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotReportSSTIWithoutRendering() throws NullPointerException, IOException {
        // Given
        String test = "/shouldNotReportXssInFilteredParagraph/";
        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response = getHtml("Rendered.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        checkNoAlertsRaised(test, Plugin.AttackStrength.LOW);
        checkNoAlertsRaised(test, Plugin.AttackStrength.MEDIUM);
        checkNoAlertsRaised(test, Plugin.AttackStrength.HIGH);
        checkNoAlertsRaised(test, Plugin.AttackStrength.INSANE);
    }

    private void checkNoAlertsRaised(String test, Plugin.AttackStrength level)
            throws HttpMalformedHeaderException {
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setAlertThreshold(AlertThreshold.LOW);
        this.rule.setAttackStrength(level);
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotDoMathsExecutionTestIfInThresholdLowAndNoSuspectBehavior()
            throws HttpMalformedHeaderException {
        // Given
        String test = "/shouldNotDoMathsExecutionTestIfInThresholdLowAndNoSuspectBehavior/";
        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response = getHtml("Rendered.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setAlertThreshold(AlertThreshold.LOW);
        this.rule.setAttackStrength(Plugin.AttackStrength.LOW);
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(lessThanOrEqualTo(5)));
        assertThat(httpMessagesSent, hasSize(greaterThan(0)));
    }

    @Test
    public void shouldNotConsiderInputSizeErrorsAsStrangeBehavior()
            throws HttpMalformedHeaderException {
        // Given
        String test = "/shouldNotConsiderInputSizeErrorsAsStrangeBehavior/";
        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            if (name.length() > SIZESMALLERTHATPOLYGLOT) {
                                name = "Error: the maximum size is " + SIZESMALLERTHATPOLYGLOT;
                            }
                            response = getHtml("Rendered.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setAlertThreshold(AlertThreshold.LOW);
        this.rule.setAttackStrength(Plugin.AttackStrength.LOW);
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(lessThanOrEqualTo(5)));
        assertThat(httpMessagesSent, hasSize(greaterThan(0)));
    }

    @Test
    public void shouldReportSSTI1() throws NullPointerException, IOException {
        shouldReportSSTI("{", "}", Plugin.AttackStrength.LOW);
    }

    @Test
    public void shouldReportSSTI2() throws NullPointerException, IOException {
        shouldReportSSTI("${", "}", Plugin.AttackStrength.LOW);
    }

    @Test
    public void shouldReportSSTI3() throws NullPointerException, IOException {
        shouldReportSSTI("#{", "}", Plugin.AttackStrength.LOW);
    }

    @Test
    public void shouldReportSSTI4() throws NullPointerException, IOException {
        shouldReportSSTI("{#", "}", Plugin.AttackStrength.LOW);
    }

    @Test
    public void shouldReportSSTI5() throws NullPointerException, IOException {
        shouldReportSSTI("{@", "}", Plugin.AttackStrength.LOW);
    }

    @Test
    public void shouldReportSSTI6() throws NullPointerException, IOException {
        shouldReportSSTI("{{", "}}", Plugin.AttackStrength.LOW);
    }

    @Test
    public void shouldReportSSTI7() throws NullPointerException, IOException {
        shouldReportSSTI("{{=", "}}", Plugin.AttackStrength.LOW);
    }

    @Test
    public void shouldReportSSTI8() throws NullPointerException, IOException {
        shouldReportSSTI("<%=", "%>", Plugin.AttackStrength.LOW);
    }

    @Test
    public void shouldReportSSTI9() throws NullPointerException, IOException {
        shouldReportSSTI("#set($x=", ")${x}", Plugin.AttackStrength.MEDIUM);
    }

    @Test
    public void shouldReportSSTI10() throws NullPointerException, IOException {
        shouldReportSSTI("<p th:text=\"${", "}\"></p>", Plugin.AttackStrength.MEDIUM);
    }

    public void shouldReportSSTI(String startTag, String endTag, Plugin.AttackStrength level)
            throws NullPointerException, IOException {
        String test = "/shouldReportXssInParagraph/";
        // Given
        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            try {
                                name = templateRenderMock(startTag, endTag, name);
                                response =
                                        getHtml("Rendered.html", new String[][] {{"name", name}});
                            } catch (IllegalArgumentException e) {
                                response = getHtml("ErrorPage.html");
                            }
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setConfig(new ZapXmlConfiguration());
        this.rule.setAlertThreshold(AlertThreshold.LOW);
        this.rule.setAttackStrength(level);
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
    }

    private String templateRenderMock(String startTag, String endTag, String input)
            throws IllegalArgumentException {
        if (!input.contains(startTag)) {
            return input;
        }

        String[] prefixAndRest = input.split(Pattern.quote(startTag), 2);
        String prefix = prefixAndRest[0];

        if (prefixAndRest.length < 2 || !prefixAndRest[1].contains(endTag)) {
            return input;
        }

        String[] expressionAndSuffix = prefixAndRest[1].split(Pattern.quote(endTag), 2);
        String expression = expressionAndSuffix[0];
        String suffix = expressionAndSuffix[1];
        String expressionResult = getSimpleArithmeticResult(expression);
        return prefix + expressionResult + suffix;
    }

    private String getSimpleArithmeticResult(String expression) throws IllegalArgumentException {
        if (expression.contains("+")) {
            String[] numbers = expression.split(Pattern.quote("+"), 2);
            if (numbers.length == 1 && expression.endsWith("+")) {
                throw new IllegalArgumentException("invalid template code");
            } else if (numbers.length != 2) {
                throw new IllegalArgumentException("invalid template code");
            }
            return Integer.toString((Integer.parseInt(numbers[0]) + Integer.parseInt(numbers[1])));
        } else if (expression.contains("*")) {
            String[] numbers = expression.split(Pattern.quote("*"), 2);
            if (numbers.length == 1 && expression.endsWith("*")) {
                throw new IllegalArgumentException("invalid template code");
            } else if (numbers.length != 2) {
                throw new IllegalArgumentException("invalid template code");
            }
            return Integer.toString((Integer.parseInt(numbers[0]) * Integer.parseInt(numbers[1])));
        } else if (StringUtils.isNumeric(expression)) {
            return expression;
        } else {
            throw new IllegalArgumentException("invalid template code");
        }
    }
}
