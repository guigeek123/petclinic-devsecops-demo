import json
import re
import sys
from behave import *
zap_results_file = '../reports/zap/zap_results.json'
@given('we have valid zap json alert output')
def step_impl(context):
    with open(zap_results_file, 'r') as f:
        try:
            context.zap_alerts = json.load(f)
        except Exception as e:
            sys.stdout.write('Error: Invalid JSON in %s: %s\n' %
                             (zap_results_file, e))
            assert False


@given('the following false positive are ignored')
def step_impl(context):
    fp_list = list()

    for row in context.table:
        fp_list.append(row)

    matches = list()
    for alert in context.zap_alerts:
        temp_alert= [alert['url'], alert['param'], alert['cweid'], alert['wascid']]
        fp_found = False
        for fp in fp_list:
            if (fp[0]==temp_alert[0] and fp[1]==temp_alert[1] and fp[2]==temp_alert[2] and fp[3]==temp_alert[3]) :
                fp_found = True;
                break

        if (fp_found == False):
            matches.append(alert)

    context.matches = matches

@then('none of these risk levels should be present')
def step_impl(context):
    high_risks = list()
    risk_list = list()
    for row in context.table:
        risk_list.append(row['risk'])
    for alert in context.matches:
         if alert['risk'] in risk_list:
             #if not any(n['alert'] == alert['alert'] for n in high_risks):
                 high_risks.append(dict({'alert': alert['alert'],
                                          'risk': alert['risk'],
                                          'confidence': alert['confidence'],
                                          'url': alert['url'],
                                          'param': alert['param'],
                                          'cweId': alert['cweid'],
                                          'wascId': alert['wascid']
                                         }))
    if len(high_risks) > 0:
        sys.stderr.write("The following alerts failed:\n")
        for risk in high_risks:
            sys.stderr.write("\t%-5s: %s, (confidence : %s, |%s|%s|%s|%s|)\n" % (risk['alert'], risk['risk'], risk['confidence'], risk['url'], risk['param'], risk['cweId'], risk['wascId']))
        sys.stderr.write("\nFormated list for false positive management:\n")
        for risk in high_risks:
            sys.stderr.write("|%s|%s|%s|%s|\n" % (risk['url'], risk['param'], risk['cweId'], risk['wascId']))

        assert False
    assert True
