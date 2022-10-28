package com.apiwiz.security.threatcheck;

public class Result {

    private boolean success;
    public static Result SUCCESS;
    public static Result ABORT;
    public static Result EXCEPTION_OCCURRED;


    public static Result JAVASCRIPT_THREAT_DETECTED;

    public static Result THREAT_DETECTED;

    public static Result SQL_THREAT_DETECTED;

    public static Result XPATH_THREAT_DETECTED;

    public static Result SERVERSIDE_THREAT_DETECTED;


    private Action action;


    private String errorResponse;

    public Action getAction() {
        return this.action;
    }

    public Result(boolean isSuccess,Action action) {
        this.success = isSuccess;
        this.action = action;
    }

    public String getErrorResponse() {
        return this.errorResponse;
    }

    public void setErrorResponse(String errorResponse) {
        this.errorResponse = errorResponse;
    }

    static {
        SUCCESS = new Result(true, Action.SUCCESS) {
            public String toString() {
                return this.getAction().name();
            }
        };
        ABORT = new Result(false, Action.ABORT) {
            public String toString() {
                return this.getAction().name();
            }
        };

        JAVASCRIPT_THREAT_DETECTED = new Result(false, Action.JAVASCRIPT_THREAT_DETECTED) {
            public String toString() {
                return this.getAction().name();
            }
        };

        SQL_THREAT_DETECTED = new Result(false, Action.SQL_THREAT_DETECTED) {
            public String toString() {
                return this.getAction().name();
            }
        };

        XPATH_THREAT_DETECTED = new Result(false, Action.XPATH_THREAT_DETECTED) {
            public String toString() {
                return this.getAction().name();
            }
        };

        SERVERSIDE_THREAT_DETECTED = new Result(false, Action.SERVERSIDE_THREAT_DETECTED) {
            public String toString() {
                return this.getAction().name();
            }
        };

        THREAT_DETECTED = new Result(false, Action.THREAT_DETECTED) {
            public String toString() {
                return this.getAction().name();
            }
        };

        EXCEPTION_OCCURRED = new Result(false, Action.EXCEPTION_OCCURRED) {
            public String toString() {
                return this.getAction().name();
            }
        };
    }

}
