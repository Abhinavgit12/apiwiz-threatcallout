package com.apiwiz.security.threatcheck;

public enum Action {
        SUCCESS,
        JAVASCRIPT_THREAT_DETECTED,
        SQL_THREAT_DETECTED,
        EXCEPTION_OCCURRED,
        XPATH_THREAT_DETECTED,
        THREAT_DETECTED,
        SERVERSIDE_THREAT_DETECTED,
        ABORT;





        private Action() {
        }

}
