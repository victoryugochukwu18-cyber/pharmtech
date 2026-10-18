import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from auditlog import chain_hash, diff_section
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

url = os.getenv("DATABASE_URL", "sqlite:///pharmatech_team.db")
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql://", 1)
engine = create_engine(url)
Session = sessionmaker(bind=engine)
Base = declarative_base()

SECTIONS = ["stock", "qms", "phyto", "analytics", "lab"]
ROLES = ("owner", "staff", "viewer")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Org(Base):
    __tablename__ = "orgs"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)


class Member(Base):
    __tablename__ = "members"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, nullable=False)
    email = Column(String, unique=True, nullable=False)
    name = Column(String, default="")
    salt = Column(String, nullable=False)
    pw_hash = Column(String, nullable=False)
    role = Column(String, default="staff")
    sections = Column(String, default="*")
    active = Column(Boolean, default=True)


class Invite(Base):
    __tablename__ = "invites"
    code = Column(String, primary_key=True)
    org_id = Column(Integer, nullable=False)
    role = Column(String, default="staff")
    sections = Column(String, default="*")
    created = Column(DateTime, default=datetime.utcnow)
    used = Column(Boolean, default=False)


class Sess(Base):
    __tablename__ = "sessions_v2"
    token = Column(String, primary_key=True)
    member_id = Column(Integer, nullable=False)
    created = Column(DateTime, default=datetime.utcnow)
    hours = Column(Integer, default=12)


class SectionData(Base):
    __tablename__ = "section_data"
    org_id = Column(Integer, primary_key=True)
    key = Column(String, primary_key=True)
    data = Column(Text, default="{}")
    version = Column(Integer, default=0)


class AuditEntry(Base):
    __tablename__ = "audit_trail"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, index=True)
    at = Column(DateTime)
    who = Column(String)
    who_id = Column(Integer)
    section = Column(String)
    record = Column(String, default="")
    action = Column(String)
    detail = Column(Text, default="")
    prev_hash = Column(String)
    hash = Column(String)


for attempt in range(15):
    try:
        Base.metadata.create_all(engine)
        break
    except Exception:
        time.sleep(2)
else:
    raise RuntimeError("Could not connect to the database.")


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()


def log(s, org_id, who, action, detail="", who_id=None, section="account", record=""):
    last = s.query(AuditEntry).filter_by(org_id=org_id).order_by(AuditEntry.id.desc()).first()
    prev = last.hash if last else "0" * 64
    at = datetime.utcnow()
    h = chain_hash(prev, at.isoformat(), who, who_id, section, record, action, detail)
    s.add(AuditEntry(org_id=org_id, at=at, who=who, who_id=who_id, section=section, record=record,
                     action=action, detail=detail, prev_hash=prev, hash=h))
    s.flush()


def allowed(sections, key):
    return sections == "*" or key in sections.split(",")


def view(m, org):
    return {"id": m.id, "email": m.email, "name": m.name, "role": m.role, "sections": m.sections, "org": org.name if org else ""}


def start(s, m, keep):
    token = secrets.token_urlsafe(32)
    s.add(Sess(token=token, member_id=m.id, hours=720 if keep else 12))
    return token


def current(authorization: str = Header("")):
    token = authorization[7:] if authorization.startswith("Bearer ") else ""
    with Session() as s:
        ses = s.get(Sess, token) if token else None
        if not ses or datetime.utcnow() - ses.created > timedelta(hours=ses.hours or 12):
            if ses:
                s.delete(ses)
                s.commit()
            raise HTTPException(401, "Please sign in.")
        m = s.get(Member, ses.member_id)
        if not m or not m.active:
            raise HTTPException(401, "This account is not active.")
        org = s.get(Org, m.org_id)
        return view(m, org) | {"org_id": m.org_id}


def owner_only(u=Depends(current)):
    if u["role"] != "owner":
        raise HTTPException(403, "Owners only.")
    return u


def clean_sections(sections):
    if sections in ("*", None, ""):
        return "*"
    keys = [k for k in sections.split(",") if k in SECTIONS]
    if not keys:
        raise HTTPException(400, "Choose at least one section.")
    return ",".join(dict.fromkeys(keys))


class SignUp(BaseModel):
    name: str
    org: str = ""
    invite: str = ""
    email: str
    password: str
    keep: bool = False


class Login(BaseModel):
    email: str
    password: str
    keep: bool = False


class PwChange(BaseModel):
    old: str
    new: str


class SectionIn(BaseModel):
    version: int
    data: dict


class InviteIn(BaseModel):
    role: str = "staff"
    sections: str = "*"


class MemberPatch(BaseModel):
    role: Optional[str] = None
    sections: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None


FAILS = {}
app = FastAPI(title="PharmaTech Solutions")


@app.post("/api/signup")
def signup(b: SignUp):
    email = b.email.strip().lower()
    if not EMAIL.match(email) or len(email) > 120:
        raise HTTPException(400, "Enter a valid email address.")
    if len(b.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    if not b.name.strip():
        raise HTTPException(400, "Enter your name.")
    with Session() as s:
        if s.query(Member).filter_by(email=email).first():
            raise HTTPException(400, "An account with that email already exists. Sign in instead.")
        if b.invite.strip():
            inv = s.get(Invite, b.invite.strip().upper())
            if not inv or inv.used or datetime.utcnow() - inv.created > timedelta(days=14):
                raise HTTPException(400, "That invite code is invalid, used or expired.")
            org, role, sections = s.get(Org, inv.org_id), inv.role, inv.sections
            inv.used = True
        else:
            org = Org(name=(b.org.strip() or b.name.strip() + "'s organisation")[:120])
            s.add(org)
            s.flush()
            role, sections = "owner", "*"
        salt = secrets.token_hex(16)
        m = Member(org_id=org.id, email=email, name=b.name.strip()[:80], salt=salt, pw_hash=hash_pw(b.password, salt),
                   role=role, sections=sections)
        s.add(m)
        s.flush()
        token = start(s, m, b.keep)
        log(s, org.id, m.name, "Joined the workspace" if b.invite.strip() else "Created the workspace", "", m.id)
        s.commit()
        return {"token": token, "user": view(m, org)}


@app.post("/api/login")
def login(b: Login):
    email = b.email.strip().lower()
    count, first = FAILS.get(email, (0, time.time()))
    if count >= 5 and time.time() - first < 900:
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
    with Session() as s:
        m = s.query(Member).filter_by(email=email).first()
        if not m or not m.active or not hmac.compare_digest(m.pw_hash, hash_pw(b.password, m.salt)):
            FAILS[email] = (count + 1, first if count else time.time())
            time.sleep(0.5)
            raise HTTPException(401, "Wrong email or password, or the account is deactivated.")
        FAILS.pop(email, None)
        token = start(s, m, b.keep)
        log(s, m.org_id, m.name, "Signed in", "", m.id)
        s.commit()
        return {"token": token, "user": view(m, s.get(Org, m.org_id))}


@app.post("/api/logout")
def logout(authorization: str = Header("")):
    token = authorization[7:] if authorization.startswith("Bearer ") else ""
    with Session() as s:
        ses = s.get(Sess, token) if token else None
        if ses:
            s.delete(ses)
            s.commit()
    return {"ok": True}


@app.get("/api/me")
def me(u=Depends(current)):
    return {k: v for k, v in u.items() if k != "org_id"}


@app.post("/api/password")
def change_password(b: PwChange, u=Depends(current)):
    if len(b.new) < 8:
        raise HTTPException(400, "New password must be at least 8 characters.")
    with Session() as s:
        m = s.get(Member, u["id"])
        if not hmac.compare_digest(m.pw_hash, hash_pw(b.old, m.salt)):
            raise HTTPException(400, "Your current password is wrong.")
        m.salt = secrets.token_hex(16)
        m.pw_hash = hash_pw(b.new, m.salt)
        log(s, m.org_id, m.name, "Changed own password", "", m.id)
        s.commit()
    return {"ok": True}


@app.get("/api/state")
def get_state(u=Depends(current)):
    with Session() as s:
        rows = s.query(SectionData).filter_by(org_id=u["org_id"]).all()
        return {r.key: {"version": r.version, "data": json.loads(r.data or "{}")}
                for r in rows if allowed(u["sections"], r.key)}


@app.get("/api/people")
def people(u=Depends(current)):
    with Session() as s:
        return {str(m.id): m.name for m in s.query(Member).filter_by(org_id=u["org_id"]).all()}


@app.get("/api/versions")
def versions(u=Depends(current)):
    with Session() as s:
        rows = s.query(SectionData).filter_by(org_id=u["org_id"]).all()
        return {r.key: r.version for r in rows if allowed(u["sections"], r.key)}


@app.get("/api/state/{key}")
def get_section(key: str, u=Depends(current)):
    if key not in SECTIONS or not allowed(u["sections"], key):
        raise HTTPException(403, "You do not have access to this section.")
    with Session() as s:
        r = s.get(SectionData, (u["org_id"], key))
        return {"version": r.version if r else 0, "data": json.loads(r.data) if r else {}}


@app.put("/api/state/{key}")
def put_section(key: str, body: SectionIn, u=Depends(current)):
    if key not in SECTIONS or not allowed(u["sections"], key):
        raise HTTPException(403, "You do not have access to this section.")
    if u["role"] == "viewer":
        raise HTTPException(403, "You have view-only access, so changes are not saved.")
    text = json.dumps(body.data)
    if len(text) > 4_000_000:
        raise HTTPException(400, "This section is too large to save.")
    with Session() as s:
        r = s.get(SectionData, (u["org_id"], key))
        if not r:
            r = SectionData(org_id=u["org_id"], key=key, data="{}", version=0)
            s.add(r)
            s.flush()
        if body.version != r.version:
            raise HTTPException(409, "A colleague changed this section.")
        old = json.loads(r.data or "{}")
        r.data = text
        r.version += 1
        try:
            changes = diff_section(key, old, body.data)
        except Exception:
            changes = [("", "Changed", "Saved changes (details unavailable)")]
        for rec, action, detail in changes:
            log(s, u["org_id"], u["name"], action, detail, u["id"], key, rec)
        s.commit()
        return {"version": r.version}


@app.get("/api/audit")
def audit(section: str = "", q: str = "", u=Depends(current)):
    with Session() as s:
        qry = s.query(AuditEntry).filter_by(org_id=u["org_id"])
        if section:
            qry = qry.filter(AuditEntry.section == section)
        rows = qry.order_by(AuditEntry.id.desc()).limit(1500).all()
    ql = q.strip().lower()
    out = []
    for e in rows:
        if u["role"] != "owner" and (e.section == "account" or not allowed(u["sections"], e.section)):
            continue
        if ql and ql not in f"{e.who} {e.record} {e.action} {e.detail}".lower():
            continue
        out.append({"id": e.id, "at": e.at.isoformat(), "who": e.who, "section": e.section, "record": e.record,
                    "action": e.action, "detail": e.detail})
        if len(out) >= 300:
            break
    return out


@app.get("/api/audit/verify")
def audit_verify(u=Depends(owner_only)):
    with Session() as s:
        rows = s.query(AuditEntry).filter_by(org_id=u["org_id"]).order_by(AuditEntry.id).all()
    prev = "0" * 64
    for e in rows:
        want = chain_hash(prev, e.at.isoformat(), e.who, e.who_id, e.section, e.record, e.action, e.detail)
        if e.prev_hash != prev or e.hash != want:
            return {"ok": False, "count": len(rows), "broken_at": e.id}
        prev = e.hash
    return {"ok": True, "count": len(rows), "broken_at": None}


@app.get("/api/team")
def team(u=Depends(owner_only)):
    with Session() as s:
        ms = s.query(Member).filter_by(org_id=u["org_id"]).order_by(Member.id).all()
        iv = s.query(Invite).filter_by(org_id=u["org_id"], used=False).order_by(Invite.created.desc()).all()
        ac = s.query(AuditEntry).filter_by(org_id=u["org_id"]).order_by(AuditEntry.id.desc()).limit(40).all()
        return {
            "members": [{"id": m.id, "name": m.name, "email": m.email, "role": m.role, "sections": m.sections,
                         "active": m.active} for m in ms],
            "invites": [{"code": i.code, "role": i.role, "sections": i.sections,
                         "expires": (i.created + timedelta(days=14)).date().isoformat()} for i in iv
                        if datetime.utcnow() - i.created <= timedelta(days=14)],
            "activity": [{"at": a.at.isoformat(), "who": a.who,
                          "action": (a.section + ": " if a.section != "account" else "") + a.action + (" · " + a.record if a.record else "")} for a in ac],
        }


@app.post("/api/team/invite")
def make_invite(b: InviteIn, u=Depends(owner_only)):
    if b.role not in ROLES:
        raise HTTPException(400, "Unknown role.")
    code = secrets.token_hex(4).upper()
    with Session() as s:
        s.add(Invite(code=code, org_id=u["org_id"], role=b.role, sections=clean_sections(b.sections)))
        log(s, u["org_id"], u["name"], "Created an invite", f"role {b.role}, sections {b.sections}", u["id"])
        s.commit()
    return {"code": code}


@app.delete("/api/team/invite/{code}")
def revoke(code: str, u=Depends(owner_only)):
    with Session() as s:
        i = s.get(Invite, code)
        if i and i.org_id == u["org_id"]:
            s.delete(i)
            s.commit()
    return {"ok": True}


@app.patch("/api/team/member/{mid}")
def patch_member(mid: int, p: MemberPatch, u=Depends(owner_only)):
    with Session() as s:
        m = s.get(Member, mid)
        if not m or m.org_id != u["org_id"]:
            raise HTTPException(404, "Member not found")
        if m.id == u["id"] and (p.active is False or (p.role not in (None, m.role))):
            raise HTTPException(400, "You cannot change your own role or deactivate yourself.")
        if p.role is not None:
            if p.role not in ROLES:
                raise HTTPException(400, "Unknown role.")
            m.role = p.role
        if p.sections is not None:
            m.sections = clean_sections(p.sections)
        if p.active is not None:
            m.active = p.active
            if not p.active:
                for ses in s.query(Sess).filter_by(member_id=m.id).all():
                    s.delete(ses)
        if p.password:
            if len(p.password) < 8:
                raise HTTPException(400, "Password must be at least 8 characters.")
            m.salt = secrets.token_hex(16)
            m.pw_hash = hash_pw(p.password, m.salt)
        s.flush()
        if not s.query(Member).filter_by(org_id=u["org_id"], role="owner", active=True).count():
            raise HTTPException(400, "There must be at least one active owner.")
        log(s, u["org_id"], u["name"], "Changed access", m.name + ": " + ", ".join(
            [f"{k} -> {v}" for k, v in p.dict(exclude_none=True).items() if k != "password"]
            + (["password reset"] if p.password else [])), u["id"])
        s.commit()
    return {"ok": True}


@app.get("/")
def home():
    return FileResponse(Path(__file__).parent / "index.html")
