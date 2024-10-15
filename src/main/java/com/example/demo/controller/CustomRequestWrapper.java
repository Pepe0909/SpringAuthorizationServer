package com.example.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.util.*;

class CustomRequestWrapper extends HttpServletRequestWrapper {
    private final Map<String, String[]> modifiedParameters;
    private final Map<String, String> modifiedHeaders;

    public CustomRequestWrapper(HttpServletRequest request) {
        super(request);
        this.modifiedParameters = new HashMap<>(request.getParameterMap());
        this.modifiedHeaders = new HashMap<>();
    }

    public void setParameter(String name, String value) {
        this.modifiedParameters.put(name, new String[]{value});
    }

    public void removeParameter(String name) {
        this.modifiedParameters.remove(name);
    }

    public void addHeader(String name, String value) {
        this.modifiedHeaders.put(name, value);
    }

    @Override
    public String getHeader(String name) {
        String headerValue = modifiedHeaders.get(name);
        if (headerValue != null) {
            return headerValue;
        }
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        Set<String> headerNames = new HashSet<>(Collections.list(super.getHeaderNames()));
        headerNames.addAll(modifiedHeaders.keySet());
        return Collections.enumeration(headerNames);
    }

    @Override
    public String getParameter(String name) {
        String[] values = modifiedParameters.get(name);
        return values != null && values.length > 0 ? values[0] : null;
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return modifiedParameters;
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(modifiedParameters.keySet());
    }

    @Override
    public String[] getParameterValues(String name) {
        return modifiedParameters.get(name);
    }
}
