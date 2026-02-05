# Event Management System

This project is a complete event‑management platform built for college events.  
It allows the President to create events and sub‑events, handle approvals through a hierarchy, and lets students register and pay securely.

---

## ✅ What this project does

- **Role‑based system** with different dashboards:
  - President
  - Faculty
  - HOD
  - Dean
  - VP
  - Coordinator
  - Volunteer

- **Event creation system**
  - Create unlimited main events
  - Add unlimited sub‑events
  - Poster upload
  - Delete events and auto‑delete their sub‑events

- **Approval workflow**
  - President → Faculty → HOD → Dean → VP  
  - Reject sends back to President for edits

- **Student registration**
  - Public registration page
  - Payment step (UPI QR)
  - QR confirmation after payment

- **Payments**
  - UPI QR upload
  - Transaction ID verification
  - Payment status tracking

- **Dashboards**
  - Role‑specific access and views
  - Coordinator and Volunteer can only view participants

- **Audit + analytics**
  - Audit logs of actions
  - Analytics for events and registrations

---

## 🛠 Tech Stack

- **Frontend:** HTML, CSS, JavaScript  
- **Backend:** Node.js + Express  
- **Data:** JSON storage (demo‑safe)

---

## ▶️ Local Run

```bash
cd backend
npm install
node server.js
