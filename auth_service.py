Yes. For your R3/R4 Platform Service, this is where code review becomes more practical: not just "what does the code do?", but "what happens in a real production situation, what problem occurs, and what method solves it?"
Here are the important real-time problems you should know.
1. Brute-force login attack
Real problem
An attacker repeatedly tries:
user@gmail.com
password1
password2
password3
...
Without protection, they can keep trying indefinitely.
Your solution
Rate limiting
5 failed attempts
       ↓
within 15 minutes
       ↓
429 Too Many Requests
You check both:
Email
+
IP address
Method used
Database-backed rate limiting
Your methods:
get_recent_attempts_by_email()
get_recent_attempts_by_ip()
check_login_rate_limit()
log_failed_login()
Production improvement
For multiple backend instances, Redis is generally better than relying only on database counters:
Client
  ↓
Load Balancer
  ↓
Server 1 / Server 2 / Server 3
  ↓
Redis rate limiter
Because all servers see the same counter.
2. Attacker uses many IP addresses
Problem
Suppose attacker does:
IP 1 → 5 attempts
IP 2 → 5 attempts
IP 3 → 5 attempts
...
An IP-only rate limit isn't enough.
Solution
Use multiple dimensions:
Email-based limit
+
IP-based limit
+
Possibly device/fingerprint-based controls
Your current implementation already does:
email_attempts >= 5
or
ip_attempts >= 5
That's a good foundation.
3. User's access token gets stolen
Problem
Suppose an attacker gets:
Access Token
They can make API requests until the token expires.
Solution
Keep access tokens short-lived.
Your intended design:
Access Token → 15 minutes
So even if stolen, the attacker's useful window is limited.
Additional protection
For highly sensitive operations:
Access token
+
additional authorization
+
possibly re-authentication
4. Refresh token gets stolen
This is more serious because your refresh token lasts longer.
Problem
Attacker obtains:
Refresh Token A
They can potentially keep generating access tokens.
Solution
Store refresh tokens server-side:
RefreshToken
 ├── token
 ├── user_id
 ├── expires_at
 └── is_revoked
Then validate:
Token exists?
     ↓
Not revoked?
     ↓
Not expired?
     ↓
YES → continue
Your:
get_refresh_token()
does this.
5. Refresh-token replay attack
This is one of your important R4 test requirements.
Real attack
Imagine:
Refresh Token A
      ↓
used
      ↓
rotated/revoked
Attacker somehow has the old Token A.
They try:
Token A again
It should fail
Token A
  ↓
Already revoked/rotated
  ↓
401
Method
Refresh-token rotation + reuse detection
Conceptually:
Refresh A
   ↓
Revoke A
   ↓
Generate Refresh B
Then:
A → rejected
B → valid
Stronger solution
If an old token is reused:
Replay detected
      ↓
Revoke session/token family
      ↓
All related refresh tokens become invalid
That's the "ideally revoke the whole session chain" part of your R4 requirement.
6. Logout doesn't actually invalidate access token
Problem
User logs out:
POST /logout
You revoke the refresh token.
But the existing access token may still work until its 15-minute expiration.
That's normal for stateless JWT access tokens.
Solution options
Method 1 — Short expiration
Access token → 15 min
Simple and scalable.
Method 2 — Token blacklist
Store revoked access-token IDs.
JWT jti
 ↓
Redis
 ↓
revoked
But this makes every request more stateful.
Method 3 — Session/version checking
Store a session/version value and invalidate tokens belonging to an old session version.
For your current project, short-lived access tokens + refresh-token revocation is a reasonable approach.
7. Concurrent login attempts
This is one of your R4 requirements.
Problem
Imagine the user has already failed 4 times.
Then two requests arrive simultaneously:
Request A → checks count = 4
Request B → checks count = 4
Both think:
4 < 5 → allowed
Then both fail and record attempts.
You can get race-condition behavior.
Solution
Use atomic operations.
For example:
Redis INCR
with an expiration window.
Or database locking/transaction techniques where appropriate.
Better production method
Redis
 ↓
Atomic increment
 ↓
Check counter
 ↓
Allow / reject
This is why Redis is commonly used for distributed rate limiting.
8. Two servers don't share rate-limit state
Problem
Suppose:
Request 1 → Server A
Request 2 → Server B
Request 3 → Server C
If each server stores rate-limit information in local memory:
Server A → 2 attempts
Server B → 2 attempts
Server C → 1 attempt
Each server thinks the user hasn't reached 5.
Solution
Use shared storage:
             ┌── Server A
Client → LB ─┼── Server B
             └── Server C
                   ↓
                 Redis
All servers share the same rate-limit state.
9. Password reset token is reused
Problem
User requests password reset:
Token ABC
Uses it successfully.
Then attacker tries:
Token ABC again
Solution
Make reset tokens single-use.
Database concept:
PasswordResetToken

token
user_id
expires_at
used_at
After successful reset:
used_at = current time
Then:
used_at != NULL
      ↓
Reject
10. Password reset token expires
Problem
User requests reset today but tries to use the link several days later.
Solution
Give the token a short lifetime.
Your requirement:
Reset token → 15 minutes
Check:
expires_at > now
If false:
401/400
Token expired
11. User enumeration
Problem
If login says:
Email doesn't exist
an attacker can discover valid accounts.
Example:
test@gmail.com → account exists
abc@gmail.com  → doesn't exist
Solution
Use the same generic response:
Invalid credentials
Your code already does this:
detail="Invalid credentials"
That's good.
12. Inactive user tries to log in
Problem
Admin disables:
is_active = False
But the user tries to log in.
Solution
Check:
if not user.is_active:
and reject authentication.
Your code already does this.
13. User has no role
Problem
A newly registered user may have:
role_id = NULL
But protected APIs need a role.
Solution
Don't issue a role-dependent access token when the role is missing.
Your code:
if not user.role:
    raise HTTPException(...)
This prevents:
role = None
from being used for RBAC.
14. Privilege escalation
Real problem
A normal user tries:
PATCH /admin/users/5/role
and changes themselves to:
CEO
Solution
Authorization must happen before the operation.
JWT
 ↓
Current user
 ↓
Role
 ↓
RBAC dependency
 ↓
Allowed?
 ├── YES → operation
 └── NO → 403
For example:
Depends(require_any_role("ceo", "vp_operations"))
15. Role hierarchy mistake
Problem
Suppose:
CEO
 ↓
VP Operations
 ↓
Manager
Endpoint requires:
VP Operations
CEO should be allowed if your hierarchy says CEO inherits VP permissions.
But a flat check:
user.role == required_role
would reject CEO.
Solution
Use your:
ROLE_HIERARCHY
to resolve inherited permissions.
This was one of your important R3 corrections.
16. Admin changes someone's role while they're logged in
This is a very real problem.
Suppose:
User = Analyst
User gets an access token:
role = analyst
Admin changes database role:
Analyst → Manager
The old JWT still contains:
role = analyst
until it expires.
Possible solutions
Simple
Short-lived access token:
15 minutes
New token gets the latest role.
Stronger
Store a:
token_version
or:
permissions_version
in the user/session.
Then invalidate old tokens when permissions change.
17. Admin deactivates a user who already has a token
Similar issue.
Database:
is_active = False
But an already-issued JWT may still be valid.
Options
Simple:
15-minute access token
Immediate invalidation:
Check active/session state against DB or Redis for sensitive requests.
Session versioning:
session_version++
Old JWT becomes invalid.
18. Multiple sessions
User logs in from:
Laptop
Phone
Chrome
You need:
Session A
Session B
Session C
Problem
User says:
"Log out my phone only."
You shouldn't destroy every session.
Solution
Give each session its own refresh-token/session record:
User
 ├── Session A → refresh token
 ├── Session B → refresh token
 └── Session C → refresh token
Then revoke only Session B.
This is your R4 per-session management.
19. Logout all devices
A common real-world requirement:
"Log me out everywhere."
Solution
Revoke all active sessions for the user:
User 10
 ├── Session A → revoked
 ├── Session B → revoked
 └── Session C → revoked
Or use a session/token version:
session_version = 7
Old tokens:
version = 6
→ rejected.
20. Audit requirements
Problem
Admin changes:
Rahul
Analyst → Manager
Six months later:
"Who changed Rahul's role?"
Without audit logging, you don't know.
Solution
Audit table:
AuditLog

actor_id
target_user_id
action
old_value
new_value
ip_address
timestamp
Example:
CEO
User 15
ROLE_CHANGED
Analyst → Manager
192.168.1.5
2026-08-21 10:30
21. Database transaction failure
Problem
Suppose login does:
Create refresh token
       ↓
DB commit fails
But your application has already generated/returned something.
Or admin role change updates one table but fails before audit logging.
Solution
Use database transactions.
Conceptually:
BEGIN
 ↓
Update user
 ↓
Create audit log
 ↓
COMMIT
If something fails:
ROLLBACK
This keeps related changes consistent.
22. Duplicate registration under concurrency
Problem
Two requests arrive simultaneously:
Request A → check email → doesn't exist
Request B → check email → doesn't exist
Both then try to create:
rahul@gmail.com
Solution
Don't rely only on:
existing = db.query(...).first()
Also enforce a UNIQUE constraint on email at the database level.
Then the DB guarantees:
email UNIQUE
Application-level check + database constraint is stronger.
23. Timing/security information leaks
Problem
If your application behaves noticeably differently for:
existing email + wrong password
versus:
non-existing email
an attacker may infer whether an account exists.
Solution
Use a consistent authentication path and generic errors.
Your:
Invalid credentials
approach is good.
24. JWT secret gets leaked
Problem
If:
SECRET_KEY
is hardcoded or committed to Git, attackers can potentially forge tokens.
Solution
Use environment/secret management:
.env
environment variables
Docker/Kubernetes secrets
cloud secret manager
Never commit the real secret.
25. Refresh token stored improperly
Problem
If you store raw refresh tokens in your DB and the database is compromised, attackers may be able to use those tokens directly.
Stronger production approach
Store a hash of the refresh token, similar in principle to passwords.
Client:
RefreshToken ABC

Database:
hash(ABC)
When presented:
ABC
 ↓
hash
 ↓
compare DB hash
Whether you need this depends on your security requirements, but it's a useful production improvement to mention in review.
The Methods You Should Know
For your project, remember these methods:
Problem
Method
Brute force
Rate limiting
Distributed rate limiting
Redis
Stolen access token
Short expiry
Stolen refresh token
Rotation + revocation
Refresh replay
Reuse detection
Logout
Refresh-token revocation
Logout all devices
Revoke session family / versioning
Password attack
Password hashing + policy
Password reset abuse
Short-lived single-use tokens
Account enumeration
Generic errors
Privilege escalation
RBAC
Hierarchy permissions
Role hierarchy
Role changes
Audit log
Session management
Per-session refresh tokens
Concurrent requests
Atomic operations/transactions
Duplicate users
DB unique constraint
Data inconsistency
DB transactions
Multiple backend servers
Redis/shared state
Token invalidation
Token/session versioning
Security investigation
Audit logs
Most Important Architecture
For your R3/R4 project, the production-shaped architecture becomes:
                    CLIENT
                      │
                      ↓
               ┌─────────────┐
               │ Load Balancer│
               └──────┬──────┘
                      │
          ┌───────────┼───────────┐
          ↓           ↓           ↓
       FastAPI     FastAPI     FastAPI
       Server 1    Server 2    Server 3
          │           │           │
          └───────────┼───────────┘
                      │
              ┌───────┴───────┐
              ↓               ↓
           PostgreSQL       Redis
              │               │
              │               ├── Rate limits
              │               ├── Sessions
              │               └── Temporary state
              │
              ├── Users
              ├── Refresh tokens
              ├── Failed logins
              ├── Audit logs
              └── Role history
If the reviewer asks "Why Redis?"
Say:
"For distributed, high-frequency temporary state such as rate limiting, session state, or token-reuse detection. Database storage is useful for durable records like users and audit logs, while Redis gives fast shared state across multiple API instances."
If they ask "Why WebSockets?"
For your R3/R4 authentication requirements, WebSockets are not necessary.
REST APIs are enough for:
Login
Logout
Refresh
Password reset
Admin user management
Session management
Audit logs
WebSockets become useful later for things like:
Real-time admin notifications
Live audit events
Security alerts
Real-time dashboard updates
So don't add WebSockets just because something is "real-time." Authentication itself doesn't require WebSockets.

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.password_validator import validate_password
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)

from app.models.users import User
from app.models.refresh_token import RefreshToken
from app.models.failed_login_attempts import FailedLoginAttempt
from app.schemas.auth import RegisterRequest

MAX_ATTEMPTS = 5
WINDOW = timedelta(minutes=15)

# ============================================================
# REFRESH TOKEN
# ============================================================

def save_refresh_token(
    db: Session,
    user_id: int,
    token: str,
    expires_at: datetime
):
    refresh = RefreshToken(
        user_id=user_id,
        token=token,
        expires_at=expires_at,
    )

    db.add(refresh)
    db.commit()


def get_refresh_token(
    db: Session,
    token: str
):
    now = datetime.now(timezone.utc)

    return (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token == token,
            RefreshToken.is_revoked.is_(False),
            RefreshToken.expires_at > now,
        )
        .first()
    )

def revoke_refresh_token(
    db: Session,
    token: str
):
    refresh = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token == token
        )
        .first()
    )

    if refresh is None:
        return False

    refresh.is_revoked = True
    db.commit()

    return True

# ============================================================
# FAILED LOGIN TRACKING
# ============================================================

def log_failed_login(
    db: Session,
    email: str,
    ip_address: str
):
    db.add(
        FailedLoginAttempt(
            email=email,
            ip_address=ip_address,
            attempted_at=datetime.now(timezone.utc),
        )
    )

    db.commit()


def get_recent_attempts_by_email(
    db: Session,
    email: str
):
    cutoff = (
        datetime.now(timezone.utc)
        - WINDOW
    )

    return (
        db.query(FailedLoginAttempt)
        .filter(
            FailedLoginAttempt.email == email,
            FailedLoginAttempt.attempted_at >= cutoff,
        )
        .count()
    )


def get_recent_attempts_by_ip(
    db: Session,
    ip_address: str
):
    cutoff = (
        datetime.now(timezone.utc)
        - WINDOW
    )

    return (
        db.query(FailedLoginAttempt)
        .filter(
            FailedLoginAttempt.ip_address == ip_address,
            FailedLoginAttempt.attempted_at >= cutoff,
        )
        .count()
    )


def check_login_rate_limit(
    db: Session,
    email: str,
    client_ip: str
):
    email_attempts = get_recent_attempts_by_email(
        db=db,
        email=email,
    )

    ip_attempts = get_recent_attempts_by_ip(
        db=db,
        ip_address=client_ip,
    )

    if (
        email_attempts >= MAX_ATTEMPTS
        or ip_attempts >= MAX_ATTEMPTS
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again after 15 minutes.",
        )

# ============================================================
# REGISTER
# ============================================================

def register_user(
    db: Session,
    request: RegisterRequest
):
    existing = (
        db.query(User)
        .filter(
            User.email == request.email
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists"
        )

    #Validate password before hashing
    validate_password(request.password)
    
    hashed_password = hash_password(
        request.password
    )

    user = User(
        email=request.email,
        full_name=request.full_name,
        password=hashed_password,
        is_active=True,
        role_id=None

    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "User registered successfully"
    }

# ============================================================
# LOGIN
# ============================================================

def login(
    db: Session,
    username: str,
    password: str
):
    username = username.lower()

    user = (
        db.query(User)
        .filter(
            User.email == username
        )
        .first()
    )

    if user is None:
        return None

    if not verify_password(
        password,
        user.password
    ):
        return None

    return user

def login_user(
    db: Session,
    username: str,
    password: str,
    client_ip: str
):
    username = username.lower()

    check_login_rate_limit(
        db=db,
        email=username,
        client_ip=client_ip,
    )

    user= login(
        db=db,
        username=username,
        password=password,
    )

    # --------------------------------------------------------
    # Wrong username OR wrong password
    # --------------------------------------------------------

    if not user:
        log_failed_login(
            db=db,
            email=username,
            ip_address=client_ip,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        log_failed_login(
            db=db,
            email=username,
            ip_address=client_ip,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User role is not assigned",
        )

    # --------------------------------------------------------
    # Access token
    # --------------------------------------------------------

    access_token = create_access_token(
        {
            "sub": user.email,
            "role": user.role.name,
            "user_id": user.id,
        }
    )

    # --------------------------------------------------------
    # Refresh token
    # --------------------------------------------------------

    refresh_token = create_refresh_token(
        {
            "sub": user.email,
            "user_id": user.id,
        }
    )

    refresh_expires_at = (
        datetime.now(timezone.utc)
        + timedelta(days=7)
    )

    save_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_token,
        expires_at=refresh_expires_at,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }
