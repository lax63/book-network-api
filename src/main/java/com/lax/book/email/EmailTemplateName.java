package com.lax.book.email;

public enum EmailTemplateName {
    ACTIVATE_ACCOUNT("activation_account");
    private final String name;

    private EmailTemplateName(final String name) {
        this.name = name;
    }
}
