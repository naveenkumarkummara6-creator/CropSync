const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Razorpay = require('razorpay');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC = ROOT;
const DB = path.join(ROOT, 'data.json');

/* ==================== RAZORPAY ==================== */

const razorpay =
  process.env.RAZORPAY_KEY_ID &&
  process.env.RAZORPAY_KEY_SECRET
    ? new Razorpay({
        key_id: process.env.RAZORPAY_KEY_ID,
        key_secret: process.env.RAZORPAY_KEY_SECRET
      })
    : null;

/* ================================================= */

const sessions = new Map();
const attempts = new Map();
const otps = new Map();

const seed = {
  farmers: [],
  bookings: [],
  prices: [],
  centres: [
    "Mandapeta Procurement Centre",
    "Rajahmundry Procurement Centre",
    "Amalapuram Procurement Centre"
  ],
  crops: [
    "Rice",
    "Wheat",
    "Maize",
    "Groundnut",
    "Cotton",
    "Other"
  ],
  audit: [],
  admin: null,
  settings: {
    upiId: "",
    payeeName: "CropSync"
  }
};

function load() {
  try {
    return JSON.parse(fs.readFileSync(DB, 'utf8'));
  } catch {
    save(seed);
    return structuredClone(seed);
  }
}

function save(d) {
  fs.writeFileSync(DB, JSON.stringify(d, null, 2));
}

let db = load();

function json(res, code, obj) {
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store'
  });

  res.end(JSON.stringify(obj));
}

function body(req) {
  return new Promise((resolve, reject) => {
    let s = '';

    req.on('data', c => {
      s += c;

      if (s.length > 1e6) {
        req.destroy();
      }
    });

    req.on('end', () => {
      try {
        resolve(s ? JSON.parse(s) : {});
      } catch (e) {
        reject(e);
      }
    });
  });
}

function cookie(req, n) {
  const m = (req.headers.cookie || '')
    .match(new RegExp('(?:^|; )' + n + '=([^;]*)'));

  return m && decodeURIComponent(m[1]);
}

function session(req) {
  const id = cookie(req, 'cs_session');
  const s = id && sessions.get(id);

  if (!s) return null;

  if (s.expires < Date.now()) {
    sessions.delete(id);
    return null;
  }

  s.expires = Date.now() + 15 * 60e3;

  return s;
}

function admin(req, res) {
  const s = session(req);

  if (!s?.admin) {
    json(res, 401, {
      error: 'Admin authentication required'
    });

    return null;
  }

  return s;
}

function hash(p, salt) {
  return crypto.scryptSync(p, salt, 64).toString('hex');
}

function newSalt() {
  return crypto.randomBytes(16).toString('hex');
}

function audit(action, details) {
  db.audit.unshift({
    id: 'AUD-' + Date.now(),
    time: new Date().toISOString(),
    action,
    details
  });

  db.audit = db.audit.slice(0, 200);

  save(db);
}

function id(p) {
  return (
    p +
    '-' +
    Date.now().toString(36).toUpperCase() +
    '-' +
    crypto.randomBytes(3).toString('hex').toUpperCase()
  );
}

function today() {
  const d = new Date();

  d.setMinutes(
    d.getMinutes() -
    d.getTimezoneOffset()
  );

  return d.toISOString().slice(0, 10);
}

function queue(date, centre) {
  return db.bookings
    .filter(
      b =>
        b.date === date &&
        b.centre === centre &&
        b.queueStatus === 'waiting'
    )
    .sort(
      (a, b) =>
        a.queueNumber - b.queueNumber
    );
}

function nextQ(date, centre) {
  const n = db.bookings
    .filter(
      b =>
        b.date === date &&
        b.centre === centre
    )
    .map(
      b =>
        Number(b.queueNumber) || 0
    );

  return (
    n.length
      ? Math.max(...n)
      : 0
  ) + 1;
}

function safeFarmer(f) {
  return {
    id: f.id,
    name: f.name,
    phone: f.phone,
    village: f.village,
    crop: f.crop,
    land: f.land,
    createdAt: f.createdAt,
    updatedAt: f.updatedAt
  };
}

/* ==================== PAYMENT HELPERS ==================== */

function calculateAmount(quantity, rate) {
  const q = Number(quantity);
  const r = Number(rate);

  if (!Number.isFinite(q) || q <= 0) {
    throw new Error('Invalid quantity');
  }

  if (!Number.isFinite(r) || r <= 0) {
    throw new Error('Invalid rate per Quintal');
  }

  return Number((q * r).toFixed(2));
}

/* ======================================================= */

async function route(req, res) {

  try {

    const u =
      new URL(req.url, 'http://localhost');

    const p = u.pathname;

    /* ==================== BOOTSTRAP ==================== */

    if (
      req.method === 'GET' &&
      p === '/api/bootstrap'
    ) {
      return json(res, 200, {
        crops: db.crops,
        centres: db.centres,

        settings: {
          payeeName:
            db.settings.payeeName,

          upiConfigured:
            !!db.settings.upiId
        },

        today: today(),

        adminConfigured:
          !!db.admin
      });
    }

    /* ==================== ADMIN SETUP ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/admin/setup'
    ) {

      if (db.admin) {
        return json(res, 409, {
          error:
            'Admin is already configured'
        });
      }

      const b = await body(req);

      if (
        !b.email ||
        !b.password ||
        b.password.length < 8
      ) {
        return json(res, 400, {
          error:
            'Email and password (8+ characters) are required'
        });
      }

      const salt = newSalt();

      db.admin = {
        email:
          b.email.toLowerCase().trim(),

        salt,

        hash:
          hash(b.password, salt)
      };

      save(db);

      audit(
        'ADMIN_SETUP',
        'Initial administrator account created'
      );

      return json(res, 200, {
        ok: true
      });
    }

    /* ==================== ADMIN LOGIN ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/admin/login'
    ) {

      const ip =
        req.socket.remoteAddress ||
        'unknown';

      const a =
        attempts.get(ip) ||
        {
          n: 0,
          until: 0
        };

      if (a.until > Date.now()) {
        return json(res, 429, {
          error:
            'Too many failed attempts. Try again later.'
        });
      }

      const b = await body(req);

      if (!db.admin) {
        return json(res, 400, {
          error:
            'Admin setup required'
        });
      }

      const ok =
        b.email?.toLowerCase().trim() ===
          db.admin.email &&
        crypto.timingSafeEqual(
          Buffer.from(
            hash(
              b.password || '',
              db.admin.salt
            )
          ),
          Buffer.from(db.admin.hash)
        );

      if (!ok) {

        a.n++;

        if (a.n >= 5) {
          a.until =
            Date.now() +
            5 * 60e3;

          a.n = 0;
        }

        attempts.set(ip, a);

        return json(res, 401, {
          error:
            'Invalid administrator credentials'
        });
      }

      attempts.delete(ip);

      const sid =
        crypto.randomBytes(32)
          .toString('hex');

      sessions.set(sid, {
        admin: true,
        expires:
          Date.now() + 15 * 60e3
      });

      res.setHeader(
        'Set-Cookie',
        `cs_session=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=900`
      );

      audit(
        'ADMIN_LOGIN',
        'Administrator logged in'
      );

      return json(res, 200, {
        ok: true
      });
    }

    /* ==================== ADMIN LOGOUT ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/admin/logout'
    ) {

      const s = session(req);

      if (s) {
        audit(
          'ADMIN_LOGOUT',
          'Administrator logged out'
        );
      }

      const sid =
        cookie(req, 'cs_session');

      if (sid) {
        sessions.delete(sid);
      }

      res.setHeader(
        'Set-Cookie',
        'cs_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
      );

      return json(res, 200, {
        ok: true
      });
    }

    /* ==================== ADMIN ME ==================== */

    if (
      req.method === 'GET' &&
      p === '/api/admin/me'
    ) {

      return json(res, 200, {
        authenticated:
          !!session(req),

        configured:
          !!db.admin
      });
    }

    /* ==================== OTP ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/otp'
    ) {

      const b = await body(req);

      if (
        !/^\d{10}$/.test(
          b.phone || ''
        )
      ) {
        return json(res, 400, {
          error:
            'Enter a valid 10-digit mobile number'
        });
      }

      const code =
        String(
          crypto.randomInt(
            100000,
            1000000
          )
        );

      otps.set(b.phone, {
        code,
        expires:
          Date.now() + 5 * 60e3
      });

      return json(res, 200, {
        ok: true,
        demoOtp: code,
        message:
          'Demo OTP generated. Production should send this through an SMS provider.'
      });
    }

    if (
      req.method === 'POST' &&
      p === '/api/otp/verify'
    ) {

      const b = await body(req);

      const o = otps.get(b.phone);

      if (
        !o ||
        o.expires < Date.now() ||
        o.code !== String(b.code)
      ) {
        return json(res, 401, {
          error:
            'Invalid or expired OTP'
        });
      }

      otps.delete(b.phone);

      return json(res, 200, {
        verified: true
      });
    }

    /* ==================== FARMERS ==================== */

    if (
      req.method === 'GET' &&
      p === '/api/farmers'
    ) {

      const s = session(req);

      if (!s?.admin) {
        return json(res, 200, {
          farmers: []
        });
      }

      return json(res, 200, {
        farmers:
          db.farmers.map(safeFarmer)
      });
    }

    if (
      req.method === 'POST' &&
      p === '/api/farmers'
    ) {

      const b = await body(req);

      if (
        !b.name ||
        !/^\d{10}$/.test(b.phone) ||
        !b.village ||
        !b.crop ||
        !(Number(b.land) > 0)
      ) {
        return json(res, 400, {
          error:
            'Invalid registration details'
        });
      }

      if (!db.crops.includes(b.crop)) {
        return json(res, 400, {
          error:
            'Invalid crop'
        });
      }

      if (
        db.farmers.some(
          f =>
            f.phone === b.phone
        )
      ) {
        return json(res, 409, {
          error:
            'Mobile number already registered'
        });
      }

      const f = {
        id:
          b.farmerId?.trim() ||
          id('FARM'),

        name:
          b.name.trim(),

        phone: b.phone,

        village:
          b.village.trim(),

        crop: b.crop,

        land:
          Number(b.land),

        createdAt:
          new Date().toISOString(),

        updatedAt:
          new Date().toISOString()
      };

      db.farmers.push(f);

      save(db);

      return json(res, 201, {
        farmer:
          safeFarmer(f)
      });
    }

    if (
      req.method === 'PUT' &&
      p.startsWith('/api/farmers/')
    ) {

      if (!admin(req, res))
        return;

      const f =
        db.farmers.find(
          x =>
            x.id ===
            decodeURIComponent(
              p.split('/').pop()
            )
        );

      if (!f) {
        return json(res, 404, {
          error:
            'Farmer not found'
        });
      }

      const b = await body(req);

      if (
        !/^\d{10}$/.test(b.phone) ||
        db.farmers.some(
          x =>
            x.id !== f.id &&
            x.phone === b.phone
        )
      ) {
        return json(res, 400, {
          error:
            'Invalid or duplicate mobile number'
        });
      }

      Object.assign(f, {
        name: b.name.trim(),
        phone: b.phone,
        village:
          b.village.trim(),
        crop: b.crop,
        land:
          Number(b.land),
        updatedAt:
          new Date().toISOString()
      });

      save(db);

      audit(
        'FARMER_UPDATE',
        f.id
      );

      return json(res, 200, {
        farmer:
          safeFarmer(f)
      });
    }

    if (
      req.method === 'DELETE' &&
      p.startsWith('/api/farmers/')
    ) {

      if (!admin(req, res))
        return;

      const fid =
        decodeURIComponent(
          p.split('/').pop()
        );

      if (
        db.bookings.some(
          b =>
            b.farmerId === fid &&
            ![
              'Rejected',
              'Payment Completed'
            ].includes(b.status)
        )
      ) {
        return json(res, 409, {
          error:
            'Cannot delete a farmer with an active booking'
        });
      }

      db.farmers =
        db.farmers.filter(
          f => f.id !== fid
        );

      save(db);

      audit(
        'FARMER_DELETE',
        fid
      );

      return json(res, 200, {
        ok: true
      });
    }

    /* ==================== BOOKINGS ==================== */

    if (
      req.method === 'GET' &&
      p === '/api/bookings'
    ) {

      const bq =
        new URL(
          req.url,
          'http://localhost'
        )
          .searchParams
          .get('phone');

      if (!bq) {
        return json(res, 400, {
          error:
            'Mobile required'
        });
      }

      const f =
        db.farmers.find(
          x => x.phone === bq
        );

      if (!f) {
        return json(res, 404, {
          error:
            'Farmer not found'
        });
      }

      return json(res, 200, {
        bookings:
          db.bookings
            .filter(
              b =>
                b.farmerId === f.id
            )
            .map(
              b => ({
                ...b,
                farmerName:
                  f.name
              })
            )
      });
    }

    if (
      req.method === 'POST' &&
      p === '/api/bookings'
    ) {

      const b = await body(req);

      const f =
        db.farmers.find(
          x => x.phone === b.phone
        );

      if (!f) {
        return json(res, 404, {
          error:
            'No farmer profile found'
        });
      }

      if (
        !db.crops.includes(b.crop) ||
        !db.centres.includes(b.centre) ||
        !b.date ||
        b.date < today() ||
        !b.slot ||
        !(Number(b.quantity) > 0)
      ) {
        return json(res, 400, {
          error:
            'Invalid booking details'
        });
      }

      if (
        db.bookings.some(
          x =>
            x.farmerId === f.id &&
            x.date === b.date &&
            x.centre === b.centre &&
            x.slot === b.slot &&
            ![
              'Rejected',
              'Payment Completed'
            ].includes(x.status)
        )
      ) {
        return json(res, 409, {
          error:
            'Active booking already exists for this centre, date and slot'
        });
      }

      const pr =
        db.prices.find(
          x =>
            x.date === b.date &&
            x.centre === b.centre &&
            x.crop === b.crop
        );

      const q =
        b.date === today()
          ? nextQ(
              b.date,
              b.centre
            )
          : null;

      const quantity =
        Number(b.quantity);

      const x = {
        id: id('BK'),
        farmerId: f.id,
        centre: b.centre,
        crop: b.crop,
        date: b.date,
        slot: b.slot,

        quantity,

        queueNumber: q,

        queueStatus:
          q
            ? 'waiting'
            : 'scheduled',

        status: 'Booked',

        paymentStatus:
          'Pending',

        paymentMode: null,

        transactionId: null,

        estimatedAmount:
          pr
            ? calculateAmount(
                quantity,
                Number(pr.price)
              )
            : null,

        amount: null,

        paymentReference: null,

        razorpayPaymentLinkId:
          null,

        createdAt:
          new Date().toISOString(),

        updatedAt:
          new Date().toISOString()
      };

      db.bookings.push(x);

      save(db);

      return json(res, 201, {
        booking: x
      });
    }

    /* ==================== QUEUE ==================== */

    if (
      req.method === 'GET' &&
      p === '/api/queue'
    ) {

      const q =
        queue(
          today(),
          new URL(
            req.url,
            'http://localhost'
          )
            .searchParams
            .get('centre') ||
            db.centres[0]
        );

      return json(res, 200, {
        queue:
          q.map(
            (b, i) => ({
              id: b.id,
              queueNumber:
                b.queueNumber,
              centre: b.centre,
              slot: b.slot,
              position:
                i + 1,
              estimatedWait:
                i * 15
            })
          )
      });
    }

    /* ==================== ADMIN DATA ==================== */

    if (
      req.method === 'GET' &&
      p === '/api/admin/data'
    ) {

      if (!admin(req, res))
        return;

      return json(res, 200, {
        farmers:
          db.farmers,

        bookings:
          db.bookings,

        prices:
          db.prices,

        centres:
          db.centres,

        crops:
          db.crops,

        audit:
          db.audit.slice(0, 50),

        settings: {
          payeeName:
            db.settings.payeeName,

          upiId:
            db.settings.upiId
        }
      });
    }

    /* ==================== ADMIN PRICE ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/admin/price'
    ) {

      if (!admin(req, res))
        return;

      const b = await body(req);

      if (
        !b.date ||
        !db.centres.includes(b.centre) ||
        !db.crops.includes(b.crop) ||
        !(Number(b.price) > 0)
      ) {
        return json(res, 400, {
          error:
            'Invalid price'
        });
      }

      let x =
        db.prices.find(
          x =>
            x.date === b.date &&
            x.centre === b.centre &&
            x.crop === b.crop
        );

      if (x) {
        x.price =
          Number(b.price);
      } else {
        x = {
          id: id('PR'),
          date: b.date,
          centre: b.centre,
          crop: b.crop,
          price:
            Number(b.price)
        };

        db.prices.push(x);
      }

      save(db);

      audit(
        'PRICE_UPDATE',
        `${b.date}/${b.crop}/${b.centre}`
      );

      return json(res, 200, {
        price: x
      });
    }

    /* ==================== DELETE PRICE ==================== */

    if (
      req.method === 'DELETE' &&
      p.startsWith('/api/admin/price/')
    ) {

      if (!admin(req, res))
        return;

      const pid =
        decodeURIComponent(
          p.split('/').pop()
        );

      db.prices =
        db.prices.filter(
          x => x.id !== pid
        );

      save(db);

      audit(
        'PRICE_DELETE',
        pid
      );

      return json(res, 200, {
        ok: true
      });
    }

    /* ==================== CENTRES ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/admin/centre'
    ) {

      if (!admin(req, res))
        return;

      const b = await body(req);

      if (!b.name?.trim()) {
        return json(res, 400, {
          error:
            'Centre name required'
        });
      }

      if (
        !db.centres.includes(
          b.name.trim()
        )
      ) {
        db.centres.push(
          b.name.trim()
        );
      }

      save(db);

      audit(
        'CENTRE_CREATE',
        b.name.trim()
      );

      return json(res, 200, {
        centres:
          db.centres
      });
    }

    if (
      req.method === 'DELETE' &&
      p.startsWith('/api/admin/centre/')
    ) {

      if (!admin(req, res))
        return;

      const name =
        decodeURIComponent(
          p.split('/')
            .slice(4)
            .join('/')
        );

      if (
        db.bookings.some(
          b => b.centre === name
        )
      ) {
        return json(res, 409, {
          error:
            'Cannot remove a centre used by bookings'
        });
      }

      db.centres =
        db.centres.filter(
          x => x !== name
        );

      save(db);

      return json(res, 200, {
        centres:
          db.centres
      });
    }

    /* ==================== CROPS ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/admin/crop'
    ) {

      if (!admin(req, res))
        return;

      const b = await body(req);

      if (!b.name?.trim()) {
        return json(res, 400, {
          error:
            'Crop name required'
        });
      }

      if (
        !db.crops.includes(
          b.name.trim()
        )
      ) {
        db.crops.push(
          b.name.trim()
        );
      }

      save(db);

      audit(
        'CROP_CREATE',
        b.name.trim()
      );

      return json(res, 200, {
        crops:
          db.crops
      });
    }

    /* ==================== BOOKING STATUS ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/admin/booking/status'
    ) {

      if (!admin(req, res))
        return;

      const b = await body(req);

      const x =
        db.bookings.find(
          x => x.id === b.id
        );

      if (!x) {
        return json(res, 404, {
          error:
            'Booking not found'
        });
      }

      const allowed = [
        'Booked',
        'Arrived',
        'Quality Check',
        'Awaiting Approval',
        'Approved',
        'Procurement Complete',
        'Payment Processing',
        'Payment Completed'
      ];

      if (!allowed.includes(b.status)) {
        return json(res, 400, {
          error:
            'Invalid status'
        });
      }

      x.status = b.status;

      x.paymentMode =
        b.paymentMode ||
        x.paymentMode;

      if (
        b.status ===
        'Payment Completed'
      ) {

        x.paymentStatus =
          'Completed';

        x.transactionId =
          x.transactionId ||
          id('TXN');
      }

      x.updatedAt =
        new Date().toISOString();

      save(db);

      audit(
        'BOOKING_STATUS',
        `${x.id} -> ${x.status}`
      );

      return json(res, 200, {
        booking: x
      });
    }

    /* ==================== REJECT ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/admin/booking/reject'
    ) {

      if (!admin(req, res))
        return;

      const b = await body(req);

      const x =
        db.bookings.find(
          x => x.id === b.id
        );

      if (!x) {
        return json(res, 404, {
          error:
            'Booking not found'
        });
      }

      x.status = 'Rejected';

      x.rejectReason =
        b.reason ||
        'Not specified';

      x.updatedAt =
        new Date().toISOString();

      save(db);

      audit(
        'BOOKING_REJECT',
        x.id
      );

      return json(res, 200, {
        booking: x
      });
    }

    /* ==================== QUEUE SERVE ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/admin/queue/serve'
    ) {

      if (!admin(req, res))
        return;

      const x =
        queue(
          today(),
          db.centres[0]
        )[0] ||
        db.bookings.find(
          b =>
            b.date === today() &&
            b.queueStatus ===
              'waiting'
        );

      if (!x) {
        return json(res, 404, {
          error:
            'No farmer waiting today'
        });
      }

      x.queueStatus =
        'served';

      x.status =
        'Arrived';

      x.updatedAt =
        new Date().toISOString();

      save(db);

      audit(
        'QUEUE_SERVE',
        x.id
      );

      return json(res, 200, {
        booking: x
      });
    }

    /* =========================================================
       CROPSYNC AUTOMATIC PAYMENT
       Quantity (Quintal) × Rate per Quintal
       ========================================================= */

    if (
      req.method === 'POST' &&
      p === '/api/payment/request'
    ) {

      const b = await body(req);

      const f =
        db.farmers.find(
          x => x.phone === b.phone
        );

      const x =
        db.bookings.find(
          x => x.id === b.bookingId
        );

      if (
        !f ||
        !x ||
        x.farmerId !== f.id
      ) {
        return json(res, 403, {
          error:
            'You can pay only for your own booking'
        });
      }

      if (
        ![
          'Procurement Complete',
          'Payment Processing'
        ].includes(x.status)
      ) {
        return json(res, 400, {
          error:
            'Payment is not yet available'
        });
      }

      /*
       * IMPORTANT:
       * Amount is calculated on the server.
       * The farmer cannot change the amount
       * from the browser.
       */

      let amount =
        Number(
          x.amount ||
          x.estimatedAmount ||
          0
        );

      /*
       * If an admin price exists, calculate:
       *
       * Quantity × ₹/Quintal
       */

      const price =
        db.prices.find(
          p =>
            p.date === x.date &&
            p.centre === x.centre &&
            p.crop === x.crop
        );

      if (price) {

        amount =
          calculateAmount(
            x.quantity,
            price.price
          );

        x.estimatedAmount =
          amount;
      }

      if (!(amount > 0)) {
        return json(res, 400, {
          error:
            'Payable amount is not available yet'
        });
      }

      /* ==================== RAZORPAY ==================== */

      if (!razorpay) {
        return json(res, 500, {
          error:
            'Razorpay is not configured on the server. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in Render Environment Variables.'
        });
      }

      const referenceId =
        ('CS-' + x.id)
          .substring(0, 40);

      try {

        const paymentLink =
          await razorpay.paymentLink.create({

            upi_link: true,

            amount:
              Math.round(
                amount * 100
              ),

            currency: 'INR',

            accept_partial:
              false,

            reference_id:
              referenceId,

            description:
              `CropSync ${x.crop} - ${x.quantity} Quintal`,

            customer: {
              name:
                f.name,

              contact:
                '+91' + f.phone
            },

            callback_url:
              `${
                process.env.APP_URL ||
                'https://cropsync-mowm.onrender.com'
              }/api/payment/callback`,

            callback_method:
              'get'
          });

        x.amount =
          amount;

        x.paymentStatus =
          'Initiated';

        x.paymentMode =
          'UPI';

        x.paymentReference =
          referenceId;

        x.razorpayPaymentLinkId =
          paymentLink.id;

        x.updatedAt =
          new Date().toISOString();

        save(db);

        audit(
          'PAYMENT_LINK_CREATED',
          `${x.id} / ₹${amount}`
        );

        return json(res, 200, {

          ok: true,

          booking: x,

          amount,

          quantityQuintal:
            x.quantity,

          ratePerQuintal:
            price
              ? Number(price.price)
              : null,

          paymentId:
            paymentLink.id,

          paymentUrl:
            paymentLink.short_url,

          /*
           * Kept for compatibility
           * with the existing frontend.
           */
          upiUrl:
            paymentLink.short_url
        });

      } catch (error) {

        console.error(
          'Razorpay payment error:',
          error
        );

        return json(res, 500, {
          error:
            'Unable to create Razorpay payment link'
        });
      }
    }

    /* =========================================================
       RAZORPAY PAYMENT CALLBACK
       ========================================================= */

    if (
      req.method === 'GET' &&
      p === '/api/payment/callback'
    ) {

      const params =
        new URL(
          req.url,
          'http://localhost'
        ).searchParams;

      const paymentId =
        params.get(
          'razorpay_payment_id'
        );

      const linkId =
        params.get(
          'razorpay_payment_link_id'
        );

      const referenceId =
        params.get(
          'razorpay_payment_link_reference_id'
        );

      const status =
        params.get(
          'razorpay_payment_link_status'
        );

      const signature =
        params.get(
          'razorpay_signature'
        );

      if (
        !paymentId ||
        !linkId ||
        !referenceId ||
        !status ||
        !signature
      ) {
        return json(res, 400, {
          error:
            'Invalid payment callback'
        });
      }

      /*
       * Razorpay Payment Link callback
       * signature verification.
       */

      const payload =
        linkId +
        '|' +
        referenceId +
        '|' +
        status +
        '|' +
        paymentId;

      const expected =
        crypto
          .createHmac(
            'sha256',
            process.env.RAZORPAY_KEY_SECRET || ''
          )
          .update(payload)
          .digest('hex');

      if (
        expected !== signature
      ) {

        return json(res, 400, {
          error:
            'Payment signature verification failed'
        });
      }

      const booking =
        db.bookings.find(
          b =>
            b.razorpayPaymentLinkId ===
            linkId
        );

      if (!booking) {
        return json(res, 404, {
          error:
            'Booking associated with payment not found'
        });
      }

      booking.transactionId =
        paymentId;

      if (
        status === 'paid'
      ) {

        booking.paymentStatus =
          'Completed';

        booking.status =
          'Payment Completed';

      } else {

        booking.paymentStatus =
          status;
      }

      booking.updatedAt =
        new Date().toISOString();

      save(db);

      audit(
        'PAYMENT_CALLBACK',
        `${booking.id} / ${status}`
      );

      res.writeHead(200, {
        'Content-Type':
          'text/html; charset=utf-8'
      });

      return res.end(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport"
                content="width=device-width,initial-scale=1">
          <title>CropSync Payment</title>
        </head>

        <body style="
          font-family:Arial,sans-serif;
          text-align:center;
          padding:50px;
          background:#f5f7f5;
        ">

          <div style="
            max-width:500px;
            margin:auto;
            background:white;
            padding:35px;
            border-radius:18px;
            box-shadow:0 10px 30px rgba(0,0,0,.08);
          ">

            <h1>🌾 CropSync</h1>

            ${
              status === 'paid'
                ? `
                  <h2 style="color:green">
                    Payment Successful
                  </h2>

                  <p>
                    Your payment has been
                    successfully recorded.
                  </p>

                  <p>
                    Transaction ID:
                    <strong>
                      ${paymentId}
                    </strong>
                  </p>
                `
                : `
                  <h2>
                    Payment Status:
                    ${status}
                  </h2>
                `
            }

            <p>
              You can close this page and
              return to CropSync.
            </p>

          </div>

        </body>
        </html>
      `);
    }

    /* ==================== ADMIN SETTINGS ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/admin/settings'
    ) {

      if (!admin(req, res))
        return;

      const b = await body(req);

      /*
       * UPI ID remains available for
       * existing CropSync settings.
       */

      if (
        !b.upiId ||
        !b.upiId.includes('@')
      ) {
        return json(res, 400, {
          error:
            'Enter a valid UPI ID'
        });
      }

      db.settings.upiId =
        b.upiId.trim();

      db.settings.payeeName =
        (
          b.payeeName ||
          'CropSync'
        ).trim();

      save(db);

      audit(
        'PAYMENT_SETTINGS',
        'UPI payment settings updated'
      );

      return json(res, 200, {
        ok: true
      });
    }

    /* ==================== ADMIN AMOUNT ==================== */

    if (
      req.method === 'POST' &&
      p === '/api/admin/booking/amount'
    ) {

      if (!admin(req, res))
        return;

      const b = await body(req);

      const x =
        db.bookings.find(
          x => x.id === b.id
        );

      if (
        !x ||
        !(Number(b.amount) > 0)
      ) {
        return json(res, 400, {
          error:
            'Invalid booking or amount'
        });
      }

      x.amount =
        Number(b.amount);

      x.updatedAt =
        new Date().toISOString();

      save(db);

      audit(
        'PAYABLE_AMOUNT',
        `${x.id} amount updated`
      );

      return json(res, 200, {
        booking: x
      });
    }

    /* ==================== TRACKING ==================== */

    if (
      req.method === 'GET' &&
      p === '/api/tracking'
    ) {

      const phone =
        new URL(
          req.url,
          'http://localhost'
        )
          .searchParams
          .get('phone');

      const f =
        db.farmers.find(
          x => x.phone === phone
        );

      if (!f) {
        return json(res, 404, {
          error:
            'Farmer not found'
        });
      }

      return json(res, 200, {
        bookings:
          db.bookings.filter(
            b =>
              b.farmerId === f.id
          )
      });
    }

    /* ==================== HEALTH ==================== */

    if (
      req.method === 'GET' &&
      p === '/api/health'
    ) {
      return json(res, 200, {
        ok: true
      });
    }

    /* ==================== STATIC FILES ==================== */

    if (req.method === 'GET') {

      let file =
        p === '/'
          ? '/index.html'
          : p;

      file =
        path
          .normalize(file)
          .replace(
            /^\.\.(\/|\\)/,
            ''
          );

      const fp =
        path.join(
          PUBLIC,
          file
        );

      if (
        !fp.startsWith(PUBLIC) ||
        !fs.existsSync(fp) ||
        fs.statSync(fp).isDirectory()
      ) {
        return json(res, 404, {
          error:
            'Not found'
        });
      }

      const ext =
        path.extname(fp);

      const types = {
        '.html':
          'text/html; charset=utf-8',

        '.js':
          'text/javascript; charset=utf-8',

        '.css':
          'text/css; charset=utf-8',

        '.json':
          'application/json'
      };

      res.writeHead(200, {
        'Content-Type':
          types[ext] ||
          'application/octet-stream'
      });

      return fs
        .createReadStream(fp)
        .pipe(res);
    }

    return json(res, 404, {
      error:
        'Not found'
    });

  } catch (e) {

    console.error(e);

    return json(res, 500, {
      error:
        'Server error'
    });
  }
}

http
  .createServer(route)
  .listen(
    PORT,
    () =>
      console.log(
        `CropSync running at http://localhost:${PORT}`
      )
  );
