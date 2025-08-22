const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const nodemailer = require("nodemailer");
const path = require("path");
const multer = require('multer');
const fs = require('fs');
const axios = require('axios'); // لإجراء طلبات HTTP إلى Cashier API
require('dotenv').config();

const app = express();

// إعداد قاعدة البيانات
const db = new sqlite3.Database("./data.db", sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    console.error("Error opening database:", err.message);
    process.exit(1);
  }
  console.log("Connected to SQLite database");
});

// إعدادات الميدل وير
app.use(cors({ 
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'https://king-store-esport-production.up.railway.app'],
  credentials: true 
}));
// يجب أن يكون bodyParser.json() لـ webhooks قبل التحقق من التوقيع إذا كان Cashier يتطلب ذلك
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// إعداد الجلسة
app.use(session({
  secret: process.env.SESSION_SECRET || 'default-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // استخدم secure: true في الإنتاج
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

// إنشاء مجلد uploads إذا لم يكن موجوداً
if (!fs.existsSync('public/uploads')) {
  fs.mkdirSync('public/uploads', { recursive: true });
}

// إعداد multer لرفع الملفات
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

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
    totalAmount REAL, -- تغيير إلى REAL لتخزين الأرقام العشرية
    cashierPaymentId TEXT, -- لتخزين معرف الدفع من Cashier
    status TEXT DEFAULT 'قيد الانتظار', -- تغيير الحالة الافتراضية
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

// إعداد البريد الإلكتروني
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Routes لخدمة صفحات HTML
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get("/dashboard", (req, res) => {
  if (!req.session.admin) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get("/pay", (req, res) => {
  res.sendFile(path.join(__dirname, 'pay.html'));
});

app.get("/success", (req, res) => {
  res.sendFile(path.join(__dirname, 'success.html'));
});

app.get("/failed", (req, res) => {
  res.sendFile(path.join(__dirname, 'failed.html'));
});

// API Routes
app.post("/api/order", async (req, res) => {
  const { name, playerId, email, ucAmount, bundle, totalAmount } = req.body;
  
  if (!name || !playerId || !email || !totalAmount || (!ucAmount && !bundle)) {
    return res.status(400).json({ success: false, message: "جميع الحقول مطلوبة" });
  }

  const type = ucAmount ? "UC" : "Bundle";
  const amountInCents = parseFloat(totalAmount) * 100; // Cashier يتوقع المبلغ بالوحدات الصغرى (سنتات)

  try {
    // 1. حفظ الطلب في قاعدة البيانات أولاً للحصول على orderId
    db.run(
      `INSERT INTO orders (name, playerId, email, type, ucAmount, bundle, totalAmount, status) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, playerId, email, type, ucAmount, bundle, parseFloat(totalAmount), 'قيد الانتظار'],
      async function(err) {
        if (err) {
          console.error("Error saving order to DB:", err);
          return res.status(500).json({ success: false, message: "حدث خطأ أثناء حفظ الطلب" });
        }
        const orderId = this.lastID;

        // 2. إنشاء جلسة دفع مع Cashier
        try {
          const cashierResponse = await axios.post('https://api.cashier.com/v1/checkout', { // استبدل بالـ endpoint الصحيح لـ Cashier
            amount: amountInCents,
            currency: 'EGP', // أو العملة المناسبة
            customer_email: email,
            metadata: {
              order_id: orderId,
              player_id: playerId,
              item_type: type,
              item_amount: ucAmount || bundle
            },
            success_url: `${process.env.APP_URL}/success?orderId=${orderId}`, // استبدل بـ APP_URL من .env
            cancel_url: `${process.env.APP_URL}/failed?orderId=${orderId}`,
            // أضف أي معلمات أخرى يطلبها Cashier API
          }, {
            headers: {
              'Authorization': `Bearer ${process.env.CASHIER_SECRET_KEY}`,
              'Content-Type': 'application/json'
            }
          });

          const checkoutUrl = cashierResponse.data.checkout_url; // استبدل بالخاصية الصحيحة التي تحتوي على رابط الدفع
          const cashierPaymentId = cashierResponse.data.id; // استبدل بالخاصية الصحيحة التي تحتوي على معرف الدفع

          // 3. تحديث الطلب في قاعدة البيانات بمعرف الدفع من Cashier
          db.run(
            `UPDATE orders SET cashierPaymentId = ? WHERE id = ?`,
            [cashierPaymentId, orderId],
            function(updateErr) {
              if (updateErr) {
                console.error("Error updating order with Cashier Payment ID:", updateErr);
                // يمكنك اختيار ما إذا كنت تريد إرجاع خطأ هنا أو المتابعة
              }
              res.json({ success: true, id: orderId, checkoutUrl: checkoutUrl });
            }
          );

        } catch (cashierError) {
          console.error("Error creating Cashier checkout session:", cashierError.response ? cashierError.response.data : cashierError.message);
          return res.status(500).json({ success: false, message: "فشل إنشاء جلسة الدفع مع Cashier" });
        }
      }
    );
  } catch (error) {
    console.error("Unhandled error in /api/order:", error);
    res.status(500).json({ success: false, message: "حدث خطأ غير متوقع" });
  }
});

// مسار لجلب تفاصيل الطلب (لصفحة الدفع)
app.get("/api/order/:orderId", (req, res) => {
  const { orderId } = req.params;
  db.get("SELECT id, name, playerId, email, type, ucAmount, bundle, totalAmount, status FROM orders WHERE id = ?", [orderId], (err, row) => {
    if (err) {
      console.error("Error fetching order details:", err);
      return res.status(500).json({ success: false, message: "خطأ في قاعدة البيانات" });
    }
    if (!row) {
      return res.status(404).json({ success: false, message: "الطلب غير موجود" });
    }
    res.json({ success: true, ...row });
  });
});

// مسار لجلب حالة الدفع (لصفحة الدفع)
app.get("/api/order/:orderId/status", async (req, res) => {
  const { orderId } = req.params;
  db.get("SELECT status FROM orders WHERE id = ?", [orderId], (err, row) => {
    if (err) {
      console.error("Error fetching order status:", err);
      return res.status(500).json({ success: false, message: "خطأ في قاعدة البيانات" });
    }
    if (!row) {
      return res.status(404).json({ success: false, message: "الطلب غير موجود" });
    }
    res.json({ success: true, payment_status: row.status });
  });
});

// Cashier Webhook Endpoint
app.post('/api/cashier/webhook', (req, res) => {
  const event = req.body;

  // يمكنك إضافة التحقق من توقيع الـ webhook هنا إذا كان Cashier يوفره
  // const signature = req.headers['cashier-signature'];
  // if (!verifyWebhookSignature(req.rawBody, signature, process.env.CASHIER_WEBHOOK_SECRET)) {
  //   return res.status(400).send('Webhook signature verification failed.');
  // }

  console.log('Received Cashier webhook event:', event.type);

  switch (event.type) {
    case 'checkout.session.completed': // استبدل بنوع الحدث الصحيح لإتمام الدفع
      const paymentIntent = event.data.object; // استبدل بالخاصية الصحيحة التي تحتوي على بيانات الدفع
      const orderId = paymentIntent.metadata.order_id; // استبدل بالخاصية الصحيحة التي تحتوي على order_id
      
      if (orderId) {
        db.run("UPDATE orders SET status = 'تم الدفع' WHERE id = ?", [orderId], function(err) {
          if (err) {
            console.error("Error updating order status on webhook:", err);
          } else {
            console.log(`Order ${orderId} status updated to 'تم الدفع'`);
            // يمكنك إرسال إشعار بالبريد الإلكتروني للمسؤول هنا
          }
        });
      }
      break;
    case 'checkout.session.failed': // استبدل بنوع الحدث الصحيح لفشل الدفع
      const failedPayment = event.data.object;
      const failedOrderId = failedPayment.metadata.order_id;
      if (failedOrderId) {
        db.run("UPDATE orders SET status = 'فشل الدفع' WHERE id = ?", [failedOrderId], function(err) {
          if (err) {
            console.error("Error updating order status on webhook (failed):", err);
          } else {
            console.log(`Order ${failedOrderId} status updated to 'فشل الدفع'`);
          }
        });
      }
      break;
    // أضف المزيد من حالات الأحداث حسب الحاجة
    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  res.status(200).send('Webhook received');
});

// وظيفة للتحقق من توقيع الـ webhook (إذا كان Cashier يوفره)
// function verifyWebhookSignature(payload, signature, secret) {
//   // تنفيذ منطق التحقق من التوقيع الخاص بـ Cashier
//   // هذا يعتمد على كيفية قيام Cashier بتوقيع الـ webhooks
//   // عادةً ما يتضمن استخدام crypto.createHmac
//   return true; // استبدل بالمنطق الفعلي
// }


app.post("/api/inquiry", async (req, res) => {
  const { name, email, message } = req.body; // أضفت name هنا
  
  if (!email || !message || !name) { // التحقق من name
    return res.status(400).json({ success: false, message: "الاسم والبريد والرسالة مطلوبان" });
  }

  try {
    db.run(
      "INSERT INTO inquiries (email, message) VALUES (?, ?)",
      [email, message],
      async function(err) {
        if (err) return res.status(500).json({ success: false, message: "خطأ في قاعدة البيانات" });
        
        await transporter.sendMail({
          from: `"فريق الدعم" <${process.env.SMTP_USER}>`,
          to: process.env.SMTP_USER,
          subject: `استفسار جديد من ${name}`, // استخدام الاسم في الموضوع
          html: `
            <div dir="rtl">
              <h2 style="color: #ffa726;">استفسار جديد</h2>
              <p><strong>الاسم:</strong> ${name}</p>
              <p><strong>البريد:</strong> ${email}</p>
              <p><strong>الرسالة:</strong></p>
              <p style="background: #f5f5f5; padding: 10px; border-right: 3px solid #ffa726;">${message}</p>
            </div>
          `,
        });
        
        res.json({ success: true });
      }
    );
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "فشل إرسال البريد الإلكتروني" });
  }
});

app.post("/api/suggestion", async (req, res) => {
  const { name, contact, message } = req.body;
  
  if (!name || !contact || !message) {
    return res.status(400).json({ success: false, message: "جميع الحقول مطلوبة" });
  }

  try {
    db.run(
      "INSERT INTO suggestions (name, contact, message) VALUES (?, ?, ?)",
      [name, contact, message],
      async function(err) {
        if (err) return res.status(500).json({ success: false, message: "خطأ في قاعدة البيانات" });
        
        await transporter.sendMail({
          from: `"اقتراح جديد" <${process.env.SMTP_USER}>`,
          to: process.env.SMTP_USER,
          subject: `اقتراح جديد من ${name}`,
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
        
        res.json({ success: true });
      }
    );
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "فشل إرسال الاقتراح" });
  }
});

// Admin Routes
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
    req.session.admin = true;
    return res.json({ success: true });
  }
  res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة' });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ success: false });
    }
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

  db.run(
    "UPDATE orders SET status = ? WHERE id = ?",
    [status, id],
    function(err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "حدث خطأ أثناء التحديث" });
      }
      res.json({ success: true });
    }
  );
});

app.delete("/api/admin/delete-order", (req, res) => {
  if (!req.session.admin) return res.status(403).json({ success: false, message: "غير مصرح" });
  
  const { id } = req.body;
  if (!id) {
    return res.status(400).json({ success: false, message: "معرّف الطلب مطلوب" });
  }

  db.run("DELETE FROM orders WHERE id = ?", [id], function(err) {
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

  db.run("DELETE FROM inquiries WHERE id = ?", [id], function(err) {
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

  db.run("DELETE FROM suggestions WHERE id = ?", [id], function(err) {
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
      `
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
            ${message.replace(/\n/g, '<br>')}
          </div>
          <hr>
          <p style="text-align: center; color: #777;">مع تحيات فريق الدعم</p>
        </div>
      `
    });

    res.json({ success: true });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ success: false, message: "فشل إرسال الرسالة" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
