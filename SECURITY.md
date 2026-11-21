# Security

## Reporting a vulnerability in Sandprobe

Please report it privately through GitHub: open this repository's **Security** tab and choose **Report a
vulnerability**. Don't open a public issue. Include what you ran, what you expected, and what happened; leave out any
credential or secret value.

We'll acknowledge the report, work on a fix, and credit you in the release notes unless you'd rather not be named.

Sandprobe runs a probe inside your sandbox and talks to your provider with your credentials, so these matter most:

- a way for a box to make the grader report a pass it didn't prove (a false pass);
- a way for Sandprobe to create, reach or delete anything other than the box its run created, or the existing box a
  person pointed `run exec` at (which it never resets or deletes);
- anything that reads a secret's value, or prints or logs a credential;
- anything that sends data anywhere other than the canary and the provider's own API.

## If Sandprobe finds something in a provider

Sandprobe checks your own sandbox's configuration. If a check suggests a real vulnerability in the provider itself,
stop: don't confirm, repeat or widen it, and delete the boxes. Report it privately to the provider through its own
disclosure program, and keep the details out of public issues and reports.
