# devsec-demo
## CSRF Protection Audit

Custom state-changing flows now use standard Django CSRF protection end to end:

- `RegisterView`, `ProfileDetailView`, and `logout_view` explicitly apply `csrf_protect`.
- The custom templates for registration, profile updates, and logout submit a real `{% csrf_token %}`.
- No `@csrf_exempt` shortcuts are used.
- Validation uses `Client(enforce_csrf_checks=True)` so the tests exercise real middleware behavior instead of a mocked shortcut.

This closes the gap where the project previously relied on a placeholder test instead of proving that a browser-style POST without a valid token is rejected.

## Redirect Safety Audit

Authentication redirects now validate `next` targets before they are used:

- Custom login, registration, and logout workflows accept only local redirect destinations validated with Django's safe-host checks.
- Unsafe external destinations fall back to predictable internal pages such as the dashboard or login screen.
- Safe internal navigation still works for legitimate users, including login success and post-registration navigation back into the application.
- Tests cover both allowed internal redirects and rejected external redirect attempts.

## Audit Logging

Security-relevant account events are now logged through the `philemon_mutabazi.audit` logger:

- Registration, login success, login failure, logout, password changes, and password reset flows emit structured audit events.
- Privilege-sensitive changes such as group membership updates, direct permission changes, and `is_staff` or `is_superuser` changes are logged for accountability.
- Logs include useful review fields like event name, user identity, request path, and client IP when available.
- Sensitive data is intentionally excluded: raw passwords are never logged, and password reset requests log a hashed email identifier instead of the submitted address.

## Stored XSS Protection

User-controlled profile bio content is now treated as plain text:

- Profile bio updates strip HTML tags before the content is stored.
- This prevents stored markup such as `<script>` tags from being persisted and later rendered back into the profile workflow.
- Legitimate profile text still works normally, while dangerous markup shortcuts are rejected instead of being preserved.

## Secure Upload Handling

Profile uploads now follow strict validation and private-storage rules:

- Avatar uploads accept only JPEG or PNG files, validated by extension, size limit, and file signature.
- Document uploads accept only PDF files, also validated by extension, size limit, and file signature.
- Uploaded files are stored under a private media directory and are not exposed through public media URLs.
- File access goes through owner-only download views so one user cannot fetch another user's uploaded content.
## Django security learning repository

This repository is used for Django and web security assignments. You will work
from your own fork, complete the assignment linked in GitHub issues, and submit
your work through a pull request.

## How to start an assignment

1. Open the assignment issue you were given.
2. Read the full task carefully.
3. Find the `## Required submission branch` section in the issue.
4. Fork the repository if you have not already done so.
5. Create your working branch from the required `assignment/...` branch named in the issue.

## Submission workflow

- Each assignment issue declares one required submission branch.
- Your pull request must target that exact branch.
- Link exactly one assignment issue in the `Related Issue` section of your pull request.
- Fill in the full pull request template, including:
  - target assignment branch
  - design note
  - security impact
  - validation
  - AI disclosure
  - authorship affirmation
- Your pull request is treated as your submission record for review and grading.
  - Assignment pull requests are expected to pass submission hygiene, lint, and Django health checks.

## AI and authorship policy

This course does not rely on AI detectors as proof. Instead, you are expected
to submit work you understand and can explain.

You may use AI in limited ways such as:

- asking for explanations of Django or security concepts
- getting debugging hints
- looking up documentation or examples
- refining wording or reorganizing code they already understand

You may not:

- delegate the entire assignment to an AI system
- submit code they cannot explain line by line when asked
- copy AI-generated output without reviewing, adapting, and understanding it
- misrepresent AI-authored work as fully their own

You must be able to explain:

- why you chose your implementation approach
- where security controls are enforced
- how you validated the work
- what you changed yourself after any AI assistance

Read [docs/ai-authorship-policy.md](docs/ai-authorship-policy.md) before you
start work on your submission.

## User Authentication Service (philemon_mutabazi)

### Setup

1. Install dependencies:
  pip install -r requirements.txt
2. Configure environment variables in `.env`:
  DJANGO_SECRET_KEY=replace-with-a-secret-key
  DJANGO_DEBUG=True
3. Apply migrations:
  python manage.py migrate
4. Run server:
  python manage.py runserver

### Authentication URLs

- /philemon/register/
- /philemon/login/
- /philemon/logout/
- /philemon/dashboard/
- /philemon/profile/
- /philemon/password-change/

### Authorization model

- Anonymous users can only access login and registration routes.
- Authenticated users can access dashboard, profile, password change, and logout.
- Privileged users can access /philemon/privileged/.
  - Privileged means is_staff, is_superuser, or member of the instructors group.
- Unauthorized privileged-area access is handled safely:
  - anonymous users are redirected to login
  - authenticated non-privileged users are redirected to dashboard with an error message

### Brute-force login protection

- Login flow includes username-based throttling to resist repeated credential guessing.
- After a configurable number of failed attempts (`LOGIN_MAX_ATTEMPTS`, default 5),
  the account login is temporarily blocked for `LOGIN_LOCKOUT_SECONDS` (default 300).
- During lockout, the login form shows a generic protective response and denies attempts,
  including correct credentials, until cooldown expires.
- On successful login, cached failed-attempt state is cleared for better usability.
- This design intentionally favors a simple, auditable mitigation over complex adaptive logic.

### IDOR protection

- Profile access now uses `/philemon/profile/<username>/` and checks the
  requested object explicitly.
- Profile routes are owner-only: authenticated users can access and update only
  their own profile resource.
- Attempts to view or modify another user's profile return a safe 404.
- The old assumption that login alone was enough for account-management access
  has been removed.

### Tests

Run UAS tests:
python manage.py test philemon_mutabazi -v 2
