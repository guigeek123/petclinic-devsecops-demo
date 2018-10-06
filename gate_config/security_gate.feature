Feature: Security Gate
  Scenario: The zap report should not contain blocking vulnerabilities
    Given we have valid zap json alert output
    And the following zap accepted vulnerabilities are ignored
      |url                    |parameter          |cweId      |wascId   |
      |http://petclinic-acceptance-frontend-defaultns/|X-Frame-Options|16|15|
      |http://petclinic-acceptance-frontend-defaultns/owners/find|X-Frame-Options|16|15|
      |http://petclinic-acceptance-frontend-defaultns/oups||200|13|
      |http://petclinic-acceptance-frontend-defaultns/vets.html|X-Frame-Options|16|15|
      |http://petclinic-acceptance-frontend-defaultns/owners/new|X-Frame-Options|16|15|
      |http://petclinic-acceptance-frontend-defaultns/owners?lastName=ZAP|X-Frame-Options|16|15|
      |http://petclinic-acceptance-frontend-defaultns/owners/new|X-Frame-Options|16|15|

    And the following zap false positive are ignored
      |url                    |parameter          |cweId      |wascId   |

    Then none of these zap risk levels should be present
      | risk |
      | High |
      | Medium |


  Scenario: The clair report should not contain blocking vulnerabilities
    Given we have valid clair json alert output

    And the following clair accepted vulnerabilities are ignored
      |component_and_version|
      |mercurial (Version :4.0-1+deb9u1)|
      |systemd (Version :232-25+deb9u4)|
      |util-linux (Version :2.29.2-1+deb9u1)|
      |libidn (Version :1.33-1)|
      |libsndfile (Version :1.0.27-3)|
      |glibc (Version :2.24-11+deb9u3)|
      |shadow (Version :1:4.4-4.1)|

    And the following clair false positive are ignored
      |component_and_version|

    Then none of these clair risk levels should be present
      | risk |
      | High |
      #| Medium |
