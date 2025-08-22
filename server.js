const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const nodemailer = require("nodemailer");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const axios = require("axios");
require("dotenv").config();

const app = express();

// ========================= Database =========================
const db = new sqlite3.Database(
  "./data.db",
  sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
  (err) => {
    if (err) {
      console.error("Error opening database:", err.message);
      process.exit(1);
    }
    console.log("Connected to SQLite database");
  }
);

// إنشاء الجداول
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    playerId TEXT,
    email TEXT,
    type TEXT,
    ucAmount TEXT,
    bundle TEXT,
    totalAmount TEXT,
    transactionId TEXT,
    screenshot TEXT,
    status TEXT DEFAULT 'لم يتم الدفع'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS inquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    message TEXT,
    status TEXT DEFAULT 'قيد الانتظار',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS suggestions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    contact TEXT,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// ========================= Middleware =========================
app.use(cors({
  origin: [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://king-store-esport-production.up.railway.app",
  ],
  credentials: true,
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// بعض مزودي الدفع ممكن يرسلوا callback كـ form urlencoded
app.use("/api/payment/callback", bodyParser.urlencoded({ extended: true }));
app.use("/api/payment/callback", bodyParser.json());

app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  secret: process.env.SESSION_SECRET || "default-secret-key",
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: "lax",
  },
}));

// ========================= Uploads (multer) =========================
if (!fs.existsSync("public/uploads")) {
  fs.mkdirSync("public/uploads", { recursive: true });
}
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "public/uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// ========================= Mail + Telegram =========================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendTelegramMessage(text) {
  try {
    if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) return;
    await axios.post(
      `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`,
      { chat_id: process.env.TELEGRAM_CHAT_ID, text }
    );
  } catch (err) {
    console.error("Telegram error:", err?.response?.data || err.message);
  }
}

async function sendEmail(subject, text) {
  try {
    const recipients = (process.env.NOTIFICATION_EMAIL || "")
      .split(",")
      .map((e) => e.trim())
      .filter(Boolean);
    if (recipients.length === 0) return;

    await transporter.sendMail({
      from: `"King STORE" <${process.env.SMTP_USER}>`,
      to: recipients,
      subject,
      text,
    });
  } catch (err) {
    console.error("Email error:", err?.response?.data || err.message);
  }
}

// ========================= Pages =========================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/dashboard", (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/login");
  }
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// ========================= Kashier Payment Integration =========================
// إنشاء عملية دفع (Order) في Kashier — تُرجع رابط الدفع للعميل
app.post("/api/payment", async (req, res) => {
  const { amount, currency, orderId, customerEmail } = req.body;

  if (!amount || !currency || !orderId || !customerEmail) {
    return res.status(400).json({ success: false, message: "جميع الحقول مطلوبة" });
  }

  try {
    const response = await axios.post(
      "https://checkout.kashier.io/api/v2/orders",
      {
        amount: amount,
        currency: currency,
        merchantId: process.env.KASHIER_MERCHANT_ID,
        orderId: String(orderId),
        redirectUrl: `${process.env.BASE_URL || "https://yourdomain.com"}/api/payment/callback`,
        customer: { email: customerEmail },
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.KASHIER_API_KEY}`,
          "Content-Type": "application/json",
        },
        timeout: 20000,
      }
    );

    // حسب استجابة Kashier — بنرجّع رابط الدفع
    const checkoutUrl =
      response.data?.redirectUrl ||
      response.data?.url ||
      response.data?.checkoutUrl;

    if (!checkoutUrl) {
      throw new Error("Checkout URL not returned from Kashier");
    }

    res.json({ success: true, checkoutUrl });
  } catch (error) {
    console.error("Kashier Payment Error:", error?.response?.data || error.message);
    res.status(500).json({ success: false, message: "فشل إنشاء عملية الدفع" });
  }
});

// Callback/Webhook من كاشير لتحديث حالة الطلب
// ملاحظة: حسب إعداداتك في Kashier قد تستقبل حقول مختلفة (paymentStatus / success / status)
// هنا هندعم القيم الشائعة.
app.post("/api/payment/callback", (req, res) => {
  const body = req.body || {};
  const orderId = body.orderId || body.merchantOrderId || body.id;
  const paymentStatus = (body.paymentStatus || body.status || "").toString().toUpperCase();

  if (!orderId) return res.status(400).json({ success: false, message: "Invalid callback (missing orderId)" });

  const successStatuses = new Set(["SUCCESS", "PAID", "CAPTURED"]);
  const isSuccess = successStatuses.has(paymentStatus);

  const status = isSuccess ? "تم الدفع" : "فشل الدفع";

  db.run(`UPDATE orders SET status = ? WHERE id = ?`, [status, orderId], function (err) {
    if (err) {
      console.error("DB error:", err.message);
      return res.status(500).json({ success: false, message: "DB error" });
    }

    const msg = `💳 تحديث حالة الدفع
🆔 رقم الطلب: ${orderId}
📌 الحالة: ${status}`;
    sendTelegramMessage(msg);
    sendEmail("تحديث حالة الدفع", msg);

    // ممكن تعيد توجيه العميل لصفحة نجاح/فشل دفع حسب رغبتك
    res.json({ success: true });
  });
});

// ========================= API Routes =========================
// إنشاء طلب (UC أو Bundle)
app.post("/api/order", upload.single("screenshot"), (req, res) => {
  const { name, playerId, email, ucAmount, bundle, totalAmount, transactionId } = req.body;

  if (!name || !playerId || !email || !transactionId || !totalAmount || (!ucAmount && !bundle)) {
    return res.status(400).json({ success: false, message: "جميع الحقول مطلوبة" });
  }

  const type = ucAmount ? "UC" : "Bundle";
  const screenshot = req.file ? `/uploads/${req.file.filename}` : null;

  db.run(
    `INSERT INTO orders (name, playerId, email, type, ucAmount, bundle, totalAmount, transactionId, screenshot) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, playerId, email, type, ucAmount || null, bundle || null, totalAmount, transactionId, screenshot],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "حدث خطأ أثناء الحفظ" });
      }

      // إشعارات عند إنشاء الطلب
      const notifyText = `📦 طلب جديد (${type})
👤 الاسم: ${name}
🆔 ID: ${playerId}
📧 الإيميل: ${email}
${ucAmount ? `💰 UC: ${ucAmount}` : `🎁 الباقة: ${bundle}`}
💵 السعر: ${totalAmount}
#️⃣ رقم المعاملة: ${transactionId}
🧾 صورة: ${screenshot ? screenshot : "لا يوجد"}`;

      sendTelegramMessage(notifyText);
      sendEmail("طلب جديد", notifyText);

      res.json({ success: true, id: this.lastID });
    }
  );
});

// استفسار
app.post("/api/inquiry", async (req, res) => {
  const { email, message } = req.body;

  if (!email || !message) {
    return res.status(400).json({ success: false, message: "البريد والرسالة مطلوبان" });
  }

  try {
    db.run(
      "INSERT INTO inquiries (email, message) VALUES (?, ?)",
      [email, message],
      async function (err) {
        if (err) return res.status(500).json({ success: false, message: "خطأ في قاعدة البيانات" });

        // بريد للإدارة
        await transporter.sendMail({
          from: `"فريق الدعم" <${process.env.SMTP_USER}>`,
          to: process.env.SMTP_USER,
          subject: "استفسار جديد من العميل",
          html: `
            <div dir="rtl">
              <h2 style="color: #ffa726;">استفسار جديد</h2>
              <p><strong>البريد:</strong> ${email}</p>
              <p><strong>الرسالة:</strong></p>
              <p style="background: #f5f5f5; padding: 10px; border-right: 3px solid #ffa726;">${message}</p>
            </div>
          `,
        });

        // إشعارات تليجرام + إيميل عام
        const text = `❓ استفسار جديد
📧 ${email}
💬 ${message}`;
        sendTelegramMessage(text);
        sendEmail("استفسار جديد", text);

        res.json({ success: true });
      }
    );
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "فشل إرسال البريد الإلكتروني" });
  }
});

// اقتراح
app.post("/api/suggestion", async (req, res) => {
  const { name, contact, message } = req.body;

  if (!name || !contact || !message) {
    return res.status(400).json({ success: false, message: "جميع الحقول مطلوبة" });
  }

  try {
    db.run(
      "INSERT INTO suggestions (name, contact, message) VALUES (?, ?, ?)",
      [name, contact, message],
      async function (err) {
        if (err) return res.status(500).json({ success: false, message: "خطأ في قاعدة البيانات" });

        await transporter.sendMail({
          from: `"اقتراح جديد" <${process.env.SMTP_USER}>`,
          to: process.env.SMTP_USER,
          subject: "اقتراح جديد للموقع",
          html: `
            <div dir="rtl">
              <h2 style="color: #ffa726;">اقتراح جديد</h2>
              <p><strong>الاسم:</strong> ${name}</p>
              <p><strong>طريقة التواصل:</strong> ${contact}</p>
              <p><strong>الاقتراح:</strong></p>
              <p style="background: #f5f5f5; padding: 10px; border-right: 3px solid #ffa726;">${message}</p>
            </div>
          `,
        });

        const text = `💡 اقتراح جديد
👤 ${name}
📞 ${contact}
💬 ${message}`;
        sendTelegramMessage(text);
        sendEmail("اقتراح جديد", text);

        res.json({ success: true });
      }
    );
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "فشل إرسال الاقتراح" });
  }
});

// ========================= Admin Routes =========================
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
    req.session.admin = true;
    return res.json({ success: true });
  }
  res.status(401).json({ success: false, message: "بيانات الدخول غير صحيحة" });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ success: false });
    res.json({ success: true });
  });
});

app.get("/api/admin/orders", (req, res) => {
  if (!req.session.admin) return res.status(403).json({ success: false, message: "غير مصرح" });

  db.all("SELECT * FROM orders ORDER BY id DESC", (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "خطأ في قاعدة البيانات" });
    }
    res.json({ success: true, data: rows });
  });
});

app.get("/api/admin/inquiries", (req, res) => {
  if (!req.session.admin) return res.status(403).json({ success: false, message: "غير مصرح" });

  db.all("SELECT * FROM inquiries ORDER BY created_at DESC", (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "خطأ في قاعدة البيانات" });
    }
    res.json({ success: true, data: rows });
  });
});

app.get("/api/admin/suggestions", (req, res) => {
  if (!req.session.admin) return res.status(403).json({ success: false, message: "غير مصرح" });

  db.all("SELECT * FROM suggestions ORDER BY created_at DESC", (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "خطأ في قاعدة البيانات" });
    }
    res.json({ success: true, data: rows });
  });
});

app.post("/api/admin/update-status", (req, res) => {
  if (!req.session.admin) return res.status(403).json({ success: false, message: "غير مصرح" });

  const { id, status } = req.body;
  if (!id || !status) {
    return res.status(400).json({ success: false, message: "معرّف الطلب والحالة مطلوبان" });
  }

  db.run("UPDATE orders SET status = ? WHERE id = ?", [status, id], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "حدث خطأ أثناء التحديث" });
    }
    res.json({ success: true });
  });
});

app.delete("/api/admin/delete-order", (req, res) => {
  if (!req.session.admin) return res.status(403).json({ success: false, message: "غير مصرح" });

  const { id } = req.body;
  if (!id) {
    return res.status(400).json({ success: false, message: "معرّف الطلب مطلوب" });
  }

  db.run("DELETE FROM orders WHERE id = ?", [id], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "حدث خطأ أثناء الحذف" });
    }
    res.json({ success: true });
  });
});

app.delete("/api/admin/delete-inquiry", (req, res) => {
  if (!req.session.admin) return res.status(403).json({ success: false, message: "غير مصرح" });

  const { id } = req.body;
  if (!id) {
    return res.status(400).json({ success: false, message: "معرّف الاستفسار مطلوب" });
  }

  db.run("DELETE FROM inquiries WHERE id = ?", [id], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "حدث خطأ أثناء الحذف" });
    }
    res.json({ success: true });
  });
});

app.delete("/api/admin/delete-suggestion", (req, res) => {
  if (!req.session.admin) return res.status(403).json({ success: false, message: "غير مصرح" });

  const { id } = req.body;
  if (!id) {
    return res.status(400).json({ success: false, message: "معرّف الاقتراح مطلوب" });
  }

  db.run("DELETE FROM suggestions WHERE id = ?", [id], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "حدث خطأ أثناء الحذف" });
    }
    res.json({ success: true });
  });
});

app.post("/api/admin/reply-inquiry", async (req, res) => {
  if (!req.session.admin) return res.status(403).json({ success: false, message: "غير مصرح" });

  const { inquiryId, email, message, reply } = req.body;
  if (!inquiryId || !email || !message || !reply) {
    return res.status(400).json({ success: false, message: "جميع الحقول مطلوبة" });
  }

  try {
    await transporter.sendMail({
      from: `"فريق الدعم" <${process.env.SMTP_USER}>`,
      to: email,
      subject: "رد على استفسارك",
      html: `
        <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #ffa726;">شكراً لتواصلك معنا</h2>
          <p><strong>استفسارك:</strong></p>
          <p style="background: #f5f5f5; padding: 10px; border-right: 3px solid #ffa726;">${message}</p>
          <h3 style="color: #ffa726;">رد الفريق:</h3>
          <p style="background: #f5f5f5; padding: 10px; border-right: 3px solid #2196F3;">${reply}</p>
          <hr>
          <p style="text-align: center; color: #777;">مع تحيات فريق الدعم</p>
        </div>
      `,
    });

    db.run("UPDATE inquiries SET status = 'تم الرد' WHERE id = ?", [inquiryId]);
    res.json({ success: true });
  } catch (error) {
    console.error("Error sending reply:", error);
    res.status(500).json({ success: false, message: "فشل إرسال الرد" });
  }
});

app.post("/api/admin/send-message", async (req, res) => {
  if (!req.session.admin) return res.status(403).json({ success: false, message: "غير مصرح" });

  const { email, subject, message } = req.body;
  if (!email || !subject || !message) {
    return res.status(400).json({ success: false, message: "جميع الحقول مطلوبة" });
  }

  try {
    await transporter.sendMail({
      from: `"فريق الدعم" <${process.env.SMTP_USER}>`,
      to: email,
      subject: subject,
      html: `
        <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #ffa726;">${subject}</h2>
          <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; border-right: 3px solid #2196F3;">
            ${message.replace(/\n/g, "<br>")}
          </div>
          <hr>
          <p style="text-align: center; color: #777;">مع تحيات فريق الدعم</p>
        </div>
      `,
    });

    res.json({ success: true });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ success: false, message: "فشل إرسال الرسالة" });
  }
});

// ========================= Start Server =========================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
