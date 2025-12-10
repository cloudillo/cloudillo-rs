# Email Templates

This directory contains Handlebars email templates for Cloudillo's email notification system.

## Files

Each email type has two versions:

- `{name}.html.hbs` - HTML email version (for HTML-capable clients)
- `{name}.txt.hbs` - Plain text version (for fallback/plain text clients)

## Current Templates

### IDP Activation (`idp-activation.{html,txt}.hbs`)

Sent when a new identity is created on an identity provider (IDP).

**Variables:**
- `identity_id` - The full identity tag (e.g., "alice.cloudillo.net")
- `activation_link` - Clickable URL to activate the identity
- `identity_provider` - The IDP domain (e.g., "cloudillo.net")
- `expire_hours` - Hours until the activation link expires

### Welcome (`welcome.{html,txt}.hbs`)

Sent after a user successfully registers on an instance.

**Variables:**
- `user_name` - User's display name or id_tag
- `instance_name` - Name of the Cloudillo instance
- `welcome_link` - Clickable URL to complete onboarding (optional)

### Password Reset (`password_reset.{html,txt}.hbs`)

Sent when an admin initiates a password reset for a user.

**Variables:**
- `user_name` - User's display name
- `reset_link` - Clickable URL to reset password
- `instance_name` - Name of the instance
- `expire_hours` - Hours until the reset link expires

## Creating New Templates

1. Create both `.html.hbs` and `.txt.hbs` files
2. Use Handlebars syntax for variables: `{{variable_name}}`
3. HTML version should be properly formatted with inline styles (for email compatibility)
4. Keep plain text version simple and readable
5. Use conditional logic if needed: `{{#if condition}}...{{/if}}`

## Handlebars Syntax

### Variables
```
Hello {{name}}!
```

### Conditionals
```
{{#if show_button}}
  <a href="{{button_url}}">Click here</a>
{{/if}}
```

### Loops
```
{{#each items}}
  - {{this}}
{{/each}}
```

### Helpers
```
{{#if (eq status "active")}}
  Active user
{{/if}}
```

## Email Best Practices

1. **HTML Emails**
   - Use inline CSS styles (not `<style>` tags)
   - Use table-based layouts for better compatibility
   - Include plain text alternative
   - Test in multiple email clients

2. **Plain Text Emails**
   - Keep lines under 80 characters
   - Use ASCII characters only
   - Format with clear section breaks
   - Provide links on separate lines

3. **Security**
   - Don't include sensitive data (passwords, tokens in subject)
   - Always use HTTPS in links
   - Handlebars auto-escapes HTML - safe from XSS
   - Never trust user input directly

4. **Deliverability**
   - Use clear sender name (not "no-reply")
   - Include unsubscribe link if applicable
   - Avoid spam trigger words
   - Test before deploying

## Testing Templates

```rust
// Load and render without sending
let (html, text) = app.email_module.template_engine
    .render(tn_id, "welcome", &vars)
    .await?;

println!("HTML:\n{}", html);
println!("TEXT:\n{}", text);
```

## Configuration

Template directory path is configurable via settings:

```
email.template_dir = "./templates/email"
```

Change this path in the Settings API if templates are stored elsewhere.
