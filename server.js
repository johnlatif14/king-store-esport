const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const nodemailer = require("nodemailer");
const path = require("path");
const multer = require('multer');
const fs = require('fs');
const axios = require('axios');
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
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// إعداد الجلسة
app.use(session({
  secret: process.env.SESSION_SECRET || 'default-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false,
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
    totalAmount TEXT,
    transactionId TEXT DEFAULT NULL,
    screenshot TEXT DEFAULT NULL,
    status TEXT DEFAULT 'قيد الانتظار',
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

// دالة لإرسال إشعار التيليجرام
async function sendTelegramNotification(message) {
  try {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
    
    if (!botToken || !chatId) {
      console.error('Telegram bot token or chat ID not configured');
      return;
    }

    const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
    await axios.post(url, {
      chat_id: chatId,
      text: message,
      parse_mode: 'HTML'
    });
  } catch (error) {
    console.error('Error sending Telegram notification:', error.message);
  }
}

// دالة لإرسال إشعار الجيميل
async function sendGmailNotification(subject, htmlContent) {
  try {
    await transporter.sendMail({
      from: `"نظام الإشعارات" <${process.env.SMTP_USER}>`,
      to: process.env.NOTIFICATION_EMAIL || process.env.SMTP_USER,
      subject: subject,
      html: htmlContent
    });
  } catch (error) {
    console.error('Error sending Gmail notification:', error);
  }
}

// Routes لخدمة صفحات HTML
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get("/dashboard", (req, res) => {
  if (!req.session.admin) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get("/pay.html", (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pay.html'));
});

// API Routes
app.post("/api/order", (req, res) => {
  const { name, playerId, email, ucAmount, bundle, totalAmount } = req.body;
  
  if (!name || !playerId || !email || !totalAmount || (!ucAmount && !bundle)) {
    return res.status(400).json({ success: false, message: "جميع الحقول المطلوبة (الاسم، ID اللاعب، البريد، المبلغ الإجمالي، ونوع الشحن) مطلوبة" });
  }

  const type = ucAmount ? "UC" : "Bundle";
  
  db.run(
    `INSERT INTO orders (name, playerId, email, type, ucAmount, bundle, totalAmount, status) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, playerId, email, type, ucAmount, bundle, totalAmount, 'قيد الانتظار'],
    async function(err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "حدث خطأ أثناء حفظ الطلب" });
      }
      
      // إرسال إشعار التيليجرام
      const telegramMessage = `
        <b>طلب جديد 🚀</b>
        \n<b>الاسم:</b> ${name}
        \n<b>ID اللاعب:</b> ${playerId}
        \n<b>البريد:</b> ${email}
        \n<b>النوع:</b> ${type}
        \n<b>الكمية:</b> ${ucAmount || bundle}
        \n<b>المبلغ:</b> ${totalAmount}
        \n<b>رقم الطلب:</b> ${this.lastID}
        \n<b>التاريخ:</b> ${new Date().toLocaleString()}
      `;
      await sendTelegramNotification(telegramMessage);

      // إرسال إشعار الجيميل
      const mailSubject = `طلب جديد - ${name}`;
      const mailHtml = `
        <div dir="rtl">
          <h2 style="color: #ff5722;">طلب جديد 🚀</h2>
          <p><strong>رقم الطلب:</strong> ${this.lastID}</p>
          <p><strong>الاسم:</strong> ${name}</p>
          <p><strong>ID اللاعب:</strong> ${playerId}</p>
          <p><strong>البريد الإلكتروني:</strong> ${email}</p>
          <p><strong>نوع الطلب:</strong> ${type}</p>
          <p><strong>الكمية:</strong> ${ucAmount || bundle}</p>
          <p><strong>المبلغ الإجمالي:</strong> ${totalAmount}</p>
          <p><strong>تاريخ الطلب:</strong> ${new Date().toLocaleString()}</p>
          <hr>
          <p style="color: #607d8b;">يمكنك مراجعة الطلب من لوحة التحكم</p>
        </div>
      `;
      await sendGmailNotification(mailSubject, mailHtml);

      res.json({ success: true, id: this.lastID, message: "تم إنشاء الطلب بنجاح. يرجى إتمام الدفع." });
    }
  );
});

app.post("/api/payment", upload.single('screenshot'), async (req, res) => {
  const { orderId, transactionId } = req.body;
  const screenshot = req.file ? `/uploads/${req.file.filename}` : null;

  if (!orderId || !transactionId || !screenshot) {
    return res.status(400).json({ success: false, message: "معرف الطلب ورقم التحويل وصورة الإيصال مطلوبة." });
  }

  db.run(
    `UPDATE orders SET transactionId = ?, screenshot = ?, status = 'تم الدفع' WHERE id = ?`,
    [transactionId, screenshot, orderId],
    async function(err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "حدث خطأ أثناء تحديث بيانات الدفع." });
      }
      if (this.changes === 0) {
        return res.status(404).json({ success: false, message: "الطلب غير موجود أو تم تحديثه مسبقاً." });
      }

      // الحصول على تفاصيل الطلب لإرسال الإشعارات
      db.get(`SELECT * FROM orders WHERE id = ?`, [orderId], async (err, order) => {
        if (order) {
          // إرسال إشعار التيليجرام
          const telegramMessage = `
            <b>تم الدفع ✅</b>
            \n<b>رقم الطلب:</b> ${orderId}
            \n<b>الاسم:</b> ${order.name}
            \n<b>رقم التحويل:</b> ${transactionId}
            \n<b>المبلغ:</b> ${order.totalAmount}
            \n<b>رابط الصورة:</b> ${req.headers.host}${screenshot}
          `;
          await sendTelegramNotification(telegramMessage);

          // إرسال إشعار الجيميل
          const mailSubject = `تم الدفع على الطلب #${orderId}`;
          const mailHtml = `
            <div dir="rtl">
              <h2 style="color: #4caf50;">تم استلام الدفع ✅</h2>
              <p><strong>رقم الطلب:</strong> ${orderId}</p>
              <p><strong>اسم العميل:</strong> ${order.name}</p>
              <p><strong>رقم التحويل:</strong> ${transactionId}</p>
              <p><strong>المبلغ:</strong> ${order.totalAmount}</p>
              <p><strong>رابط صورة الإيصال:</strong> <a href="http://${req.headers.host}${screenshot}">اضغط هنا</a></p>
              <hr>
              <p style="color: #607d8b;">يرجى مراجعة الطلب وإكمال الشحن</p>
            </div>
          `;
          await sendGmailNotification(mailSubject, mailHtml);
        }
      });

      res.json({ success: true, message: "تم استلام إثبات الدفع بنجاح. سيتم مراجعة طلبك." });
    }
  );
});

app.post("/api/inquiry", async (req, res) => {
  const { email, message } = req.body;
  
  if (!email || !message) {
    return res.status(400).json({ success: false, message: "البريد والرسالة مطلوبان" });
  }

  try {
    db.run(
      "INSERT INTO inquiries (email, message) VALUES (?, ?)",
      [email, message],
      async function(err) {
        if (err) return res.status(500).json({ success: false, message: "خطأ في قاعدة البيانات" });
        
        // إرسال إشعار التيليجرام للاستفسارات
        const telegramMessage = `
          <b>استفسار جديد ❓</b>
          \n<b>البريد:</b> ${email}
          \n<b>الرسالة:</b>
          \n${message}
        `;
        await sendTelegramNotification(telegramMessage);

        // إرسال إشعار الجيميل للاستفسارات
        const mailSubject = `استفسار جديد من ${email}`;
        const mailHtml = `
          <div dir="rtl">
            <h2 style="color: #2196F3;">استفسار جديد ❓</h2>
            <p><strong>البريد الإلكتروني:</strong> ${email}</p>
            <p><strong>الرسالة:</strong></p>
            <div style="background: #f5f5f5; padding: 10px; border-radius: 5px;">
              ${message.replace(/\n/g, '<br>')}
            </div>
          </div>
        `;
        await sendGmailNotification(mailSubject, mailHtml);

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
        
        // إرسال إشعار التيليجرام للاقتراحات
        const telegramMessage = `
          <b>اقتراح جديد 💡</b>
          \n<b>الاسم:</b> ${name}
          \n<b>طريقة التواصل:</b> ${contact}
          \n<b>الرسالة:</b>
          \n${message}
        `;
        await sendTelegramNotification(telegramMessage);

        // إرسال إشعار الجيميل للاقتراحات
        const mailSubject = `اقتراح جديد من ${name}`;
        const mailHtml = `
          <div dir="rtl">
            <h2 style="color: #9C27B0;">اقتراح جديد 💡</h2>
            <p><strong>الاسم:</strong> ${name}</p>
            <p><strong>طريقة التواصل:</strong> ${contact}</p>
            <p><strong>الرسالة:</strong></p>
            <div style="background: #f5f5f5; padding: 10px; border-radius: 5px;">
              ${message.replace(/\n/g, '<br>')}
            </div>
          </div>
        `;
        await sendGmailNotification(mailSubject, mailHtml);

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
    async function(err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "حدث خطأ أثناء التحديث" });
      }

      // الحصول على تفاصيل الطلب لإرسال الإشعارات
      db.get(`SELECT * FROM orders WHERE id = ?`, [id], async (err, order) => {
        if (order) {
          // إرسال إشعار التيليجرام لتغيير الحالة
          const telegramMessage = `
            <b>تحديث حالة الطلب 🔄</b>
            \n<b>رقم الطلب:</b> ${id}
            \n<b>الاسم:</b> ${order.name}
            \n<b>الحالة الجديدة:</b> ${status}
          `;
          await sendTelegramNotification(telegramMessage);

          // إرسال إشعار الجيميل لتغيير الحالة
          const mailSubject = `تحديث حالة الطلب #${id}`;
          const mailHtml = `
            <div dir="rtl">
              <h2 style="color: #FFC107;">تحديث حالة الطلب 🔄</h2>
              <p><strong>رقم الطلب:</strong> ${id}</p>
              <p><strong>اسم العميل:</strong> ${order.name}</p>
              <p><strong>الحالة الجديدة:</strong> ${status}</p>
              <hr>
              <p style="color: #607d8b;">تم تحديث حالة الطلب بنجاح</p>
            </div>
          `;
          await sendGmailNotification(mailSubject, mailHtml);
        }
      });

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

    // إرسال إشعار التيليجرام للرد على الاستفسار
    const telegramMessage = `
      <b>تم إرسال رد على استفسار 📩</b>
      \n<b>إلى:</b> ${email}
      \n<b>الرد:</b>
      \n${reply}
    `;
    await sendTelegramNotification(telegramMessage);

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

    // إرسال إشعار التيليجرام عند إرسال رسالة للعميل
    const telegramMessage = `
      <b>تم إرسال رسالة إلى العميل 📧</b>
      \n<b>إلى:</b> ${email}
      \n<b>الموضوع:</b> ${subject}
      \n<b>الرسالة:</b>
      \n${message}
    `;
    await sendTelegramNotification(telegramMessage);

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