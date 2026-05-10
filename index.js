'use strict';

// ⚡ FastFlow ERP - Single File Server
// All-in-one for easy deployment

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fastflow-secret-2026';

// ═══════════════════════════
// MIDDLEWARE
// ═══════════════════════════
app.use(helmet({ crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','PATCH','DELETE'], allowedHeaders: ['Content-Type','Authorization','X-Device-ID'] }));
app.use(rateLimit({ windowMs: 15*60*1000, max: 200 }));

// ═══════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════
async function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const session = await prisma.session.findUnique({
      where: { token },
      include: { user: { include: { company: true } } }
    });
    if (!session || session.expiresAt < new Date()) return res.status(401).json({ error: 'Session expired' });
    if (!session.user.isActive) return res.status(403).json({ error: 'Account disabled' });
    req.user = session.user;
    req.companyId = session.user.companyId;
    req.branchId = session.user.branchId;
    next();
  } catch(e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function ok(res, data, status=200) { res.status(status).json({ success: true, data }); }
function err(res, msg, status=400) { res.status(status).json({ error: msg }); }

// ═══════════════════════════
// HEALTH
// ═══════════════════════════
app.get('/', (req, res) => res.json({
  name: 'FastFlow ERP API',
  version: '2.0.0',
  status: 'running',
  endpoints: { health: '/health', api: '/api/v1', docs: 'See README' },
  features: ['ZATCA Phase 2','Double-Entry Accounting','JWT Auth','Multi-Branch','Audit Logs','VAT 15%']
}));

app.get('/health', async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: 'OK', db: 'connected', uptime: process.uptime(), time: new Date() });
  } catch(e) {
    res.status(500).json({ status: 'ERROR', db: 'disconnected', error: e.message });
  }
});

// ═══════════════════════════
// AUTH ROUTES
// ═══════════════════════════
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 5 });

app.post('/api/v1/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password, fullName, phone, companyNameAr, vatNumber, crNumber, sector } = req.body;
    if (!username || !email || !password || !fullName || !companyNameAr || !vatNumber || !crNumber)
      return err(res, 'All fields required');
    if (password.length < 8) return err(res, 'Password min 8 chars');

    const existing = await prisma.user.findFirst({ where: { OR: [{ username }, { email }] } });
    if (existing) return err(res, 'Username or email already exists', 409);

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await prisma.$transaction(async (tx) => {
      const company = await tx.company.create({
        data: {
          nameAr: companyNameAr, vatNumber, crNumber,
          sector: sector || 'company',
          branches: { create: { name: companyNameAr + ' - الرئيسي', isMain: true } }
        },
        include: { branches: true }
      });

      const user = await tx.user.create({
        data: { username, email, password: hashedPassword, fullName, phone, role: 'ADMIN', companyId: company.id, branchId: company.branches[0].id }
      });

      // Default chart of accounts
      const accounts = [
        { code: '1110', nameAr: 'الصندوق', nameEn: 'Cash', type: 'ASSET' },
        { code: '1120', nameAr: 'البنك', nameEn: 'Bank', type: 'ASSET' },
        { code: '1130', nameAr: 'الذمم المدينة', nameEn: 'Accounts Receivable', type: 'ASSET' },
        { code: '1200', nameAr: 'المخزون', nameEn: 'Inventory', type: 'ASSET' },
        { code: '2100', nameAr: 'الذمم الدائنة', nameEn: 'Accounts Payable', type: 'LIABILITY' },
        { code: '2200', nameAr: 'ضريبة القيمة المضافة المستحقة', nameEn: 'VAT Payable', type: 'LIABILITY' },
        { code: '3000', nameAr: 'حقوق الملكية', nameEn: 'Equity', type: 'EQUITY' },
        { code: '4100', nameAr: 'إيرادات المبيعات', nameEn: 'Sales Revenue', type: 'REVENUE' },
        { code: '5100', nameAr: 'تكلفة البضاعة المباعة', nameEn: 'COGS', type: 'EXPENSE' },
        { code: '5200', nameAr: 'المصروفات التشغيلية', nameEn: 'Operating Expenses', type: 'EXPENSE' },
        { code: '5300', nameAr: 'الرواتب والأجور', nameEn: 'Salaries', type: 'EXPENSE' },
      ];
      for (const acc of accounts) await tx.account.create({ data: { ...acc, companyId: company.id } });

      return { company, user };
    });

    const token = jwt.sign({ userId: result.user.id }, JWT_SECRET, { expiresIn: '24h' });
    await prisma.session.create({
      data: { token, userId: result.user.id, deviceId: req.headers['x-device-id'], ipAddress: req.ip, expiresAt: new Date(Date.now() + 86400000) }
    });

    ok(res, { token, user: { id: result.user.id, username, fullName, email, role: 'ADMIN', companyId: result.company.id } }, 201);
  } catch(e) {
    console.error(e);
    err(res, e.code === 'P2002' ? 'Duplicate entry' : e.message, 500);
  }
});

app.post('/api/v1/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return err(res, 'Username and password required');

    const user = await prisma.user.findFirst({
      where: { OR: [{ username }, { email: username }] },
      include: { company: true }
    });

    if (!user || !await bcrypt.compare(password, user.password)) return err(res, 'Invalid credentials', 401);
    if (!user.isActive) return err(res, 'Account disabled', 403);

    // Clean old sessions
    await prisma.session.deleteMany({ where: { userId: user.id, expiresAt: { lt: new Date() } } });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
    await prisma.session.create({
      data: { token, userId: user.id, deviceId: req.headers['x-device-id'], ipAddress: req.ip, expiresAt: new Date(Date.now() + 86400000) }
    });
    await prisma.user.update({ where: { id: user.id }, data: { lastLogin: new Date(), loginCount: { increment: 1 } } });

    ok(res, {
      token,
      user: { id: user.id, username: user.username, fullName: user.fullName, email: user.email, role: user.role, companyId: user.companyId,
        company: user.company ? { id: user.company.id, nameAr: user.company.nameAr, vatNumber: user.company.vatNumber, sector: user.company.sector } : null }
    });
  } catch(e) { err(res, e.message, 500); }
});

app.post('/api/v1/auth/logout', auth, async (req, res) => {
  try {
    await prisma.session.deleteMany({ where: { userId: req.user.id } });
    ok(res, { message: 'Logged out' });
  } catch(e) { err(res, e.message, 500); }
});

app.get('/api/v1/auth/me', auth, (req, res) => {
  const { password, ...user } = req.user;
  ok(res, user);
});

// ═══════════════════════════
// DASHBOARD
// ═══════════════════════════
app.get('/api/v1/dashboard', auth, async (req, res) => {
  try {
    const som = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
    const [rev, exp, invC, stkC, overdue, recentInv] = await Promise.all([
      prisma.invoice.aggregate({ where: { companyId: req.companyId, issueDate: { gte: som }, status: { in: ['PAID','ISSUED','PARTIAL'] } }, _sum: { total: true, vatAmount: true } }),
      prisma.expense.aggregate({ where: { companyId: req.companyId, date: { gte: som } }, _sum: { amount: true } }),
      prisma.invoice.count({ where: { companyId: req.companyId, issueDate: { gte: som } } }),
      prisma.product.aggregate({ where: { companyId: req.companyId }, _sum: { quantity: true } }),
      prisma.invoice.count({ where: { companyId: req.companyId, status: 'OVERDUE' } }),
      prisma.invoice.findMany({ where: { companyId: req.companyId }, orderBy: { createdAt: 'desc' }, take: 5, select: { invoiceNumber: true, clientName: true, total: true, status: true, issueDate: true } }),
    ]);
    const revenue = rev._sum.total || 0;
    const expenses = exp._sum.amount || 0;
    ok(res, { kpis: { revenue, expenses, profit: revenue - expenses, vatCollected: rev._sum.vatAmount || 0, invoiceCount: invC, stockUnits: stkC._sum.quantity || 0, overdueInvoices: overdue }, recentInvoices: recentInv });
  } catch(e) { err(res, e.message, 500); }
});

// ═══════════════════════════
// INVOICES (ZATCA)
// ═══════════════════════════
app.get('/api/v1/invoices', auth, async (req, res) => {
  try {
    const { status, search, page=1, limit=20 } = req.query;
    const where = {
      companyId: req.companyId,
      ...(status && { status }),
      ...(search && { OR: [{ invoiceNumber: { contains: search, mode: 'insensitive' } }, { clientName: { contains: search, mode: 'insensitive' } }] })
    };
    const [invoices, total] = await Promise.all([
      prisma.invoice.findMany({ where, include: { items: true, payments: true }, orderBy: { issueDate: 'desc' }, skip: (page-1)*limit, take: parseInt(limit) }),
      prisma.invoice.count({ where })
    ]);
    ok(res, { invoices, total, page: parseInt(page), pages: Math.ceil(total/limit) });
  } catch(e) { err(res, e.message, 500); }
});

app.post('/api/v1/invoices', auth, async (req, res) => {
  try {
    const { clientName, clientVat, clientAddress, items, discountAmount=0, notes, paymentMethod, dueDate, type='TAX_INVOICE' } = req.body;
    if (!clientName || !items?.length) return err(res, 'Client name and items required');

    const vatRate = req.user.company?.vatRate || 15;
    let subtotal = 0;
    const processedItems = items.map(item => {
      const lineTotal = item.quantity * item.unitPrice * (1 - (item.discount||0)/100);
      const vatAmt = lineTotal * (vatRate/100);
      subtotal += lineTotal;
      return { name: item.name, quantity: item.quantity, unitPrice: item.unitPrice, discount: item.discount||0, vatRate, vatAmount: Math.round(vatAmt*100)/100, total: Math.round((lineTotal+vatAmt)*100)/100, productId: item.productId };
    });

    const vatAmount = Math.round((subtotal-discountAmount)*vatRate/100*100)/100;
    const total = Math.round((subtotal-discountAmount+vatAmount)*100)/100;
    const count = await prisma.invoice.count({ where: { companyId: req.companyId } });
    const invoiceNumber = `INV-${new Date().getFullYear()}-${String(count+1).padStart(5,'0')}`;
    const invoiceUuid = uuidv4();

    // ZATCA QR (TLV)
    const company = req.user.company;
    function tlv(tag, value) {
      const enc = Buffer.from(value, 'utf8');
      return Buffer.concat([Buffer.from([tag]), Buffer.from([enc.length]), enc]);
    }
    const qrBuf = Buffer.concat([tlv(1,company.nameAr), tlv(2,company.vatNumber), tlv(3,new Date().toISOString()), tlv(4,total.toString()), tlv(5,vatAmount.toString())]);
    const qrCode = await QRCode.toDataURL(qrBuf.toString('base64'));

    const invoice = await prisma.invoice.create({
      data: {
        invoiceNumber, uuid: invoiceUuid, type, status: 'ISSUED',
        clientName, clientVat, clientAddress,
        subtotal, discountAmount, vatAmount, total, vatRate,
        issueDate: new Date(), dueDate: dueDate ? new Date(dueDate) : null,
        qrCode, notes, paymentMethod,
        companyId: req.companyId, branchId: req.branchId, userId: req.user.id,
        items: { create: processedItems }
      },
      include: { items: true }
    });

    // Update inventory
    for (const item of items) {
      if (item.productId) {
        await prisma.product.update({ where: { id: item.productId }, data: { quantity: { decrement: item.quantity } } });
      }
    }

    // Audit log
    await prisma.auditLog.create({ data: { action: 'CREATE_INVOICE', entity: 'Invoice', entityId: invoice.id, newData: JSON.stringify({ invoiceNumber, total }), userId: req.user.id, ipAddress: req.ip } });

    ok(res, invoice, 201);
  } catch(e) { console.error(e); err(res, e.message, 500); }
});

app.get('/api/v1/invoices/:id', auth, async (req, res) => {
  try {
    const inv = await prisma.invoice.findFirst({ where: { id: req.params.id, companyId: req.companyId }, include: { items: true, payments: true, createdBy: { select: { fullName: true } } } });
    if (!inv) return err(res, 'Invoice not found', 404);
    ok(res, inv);
  } catch(e) { err(res, e.message, 500); }
});

app.post('/api/v1/invoices/:id/payment', auth, async (req, res) => {
  try {
    const { amount, method, reference } = req.body;
    const inv = await prisma.invoice.findFirst({ where: { id: req.params.id, companyId: req.companyId }, include: { payments: true } });
    if (!inv) return err(res, 'Not found', 404);
    const totalPaid = inv.payments.reduce((s,p) => s+p.amount, 0) + amount;
    const status = totalPaid >= inv.total ? 'PAID' : 'PARTIAL';
    const [payment] = await Promise.all([
      prisma.payment.create({ data: { amount, method, reference, invoiceId: inv.id } }),
      prisma.invoice.update({ where: { id: inv.id }, data: { status } })
    ]);
    ok(res, { payment, status });
  } catch(e) { err(res, e.message, 500); }
});

// ═══════════════════════════
// PRODUCTS
// ═══════════════════════════
app.get('/api/v1/products', auth, async (req, res) => {
  try {
    const { search, category } = req.query;
    const products = await prisma.product.findMany({
      where: { companyId: req.companyId, isActive: true, ...(search && { OR: [{ name: { contains: search, mode: 'insensitive' } }, { barcode: { contains: search } }] }), ...(category && { category }) },
      orderBy: { name: 'asc' }
    });
    ok(res, products);
  } catch(e) { err(res, e.message, 500); }
});

app.post('/api/v1/products', auth, async (req, res) => {
  try {
    const product = await prisma.product.create({ data: { ...req.body, companyId: req.companyId } });
    ok(res, product, 201);
  } catch(e) { err(res, e.message, 500); }
});

app.get('/api/v1/products/barcode/:barcode', auth, async (req, res) => {
  try {
    const p = await prisma.product.findFirst({ where: { barcode: req.params.barcode, companyId: req.companyId } });
    if (!p) return err(res, 'Product not found', 404);
    ok(res, p);
  } catch(e) { err(res, e.message, 500); }
});

app.put('/api/v1/products/:id', auth, async (req, res) => {
  try {
    const p = await prisma.product.update({ where: { id: req.params.id }, data: req.body });
    ok(res, p);
  } catch(e) { err(res, e.message, 500); }
});

// ═══════════════════════════
// CUSTOMERS
// ═══════════════════════════
app.get('/api/v1/customers', auth, async (req, res) => {
  try {
    const { search } = req.query;
    const customers = await prisma.customer.findMany({
      where: { companyId: req.companyId, isActive: true, ...(search && { OR: [{ name: { contains: search, mode: 'insensitive' } }, { phone: { contains: search } }] }) },
      orderBy: { name: 'asc' }
    });
    ok(res, customers);
  } catch(e) { err(res, e.message, 500); }
});

app.post('/api/v1/customers', auth, async (req, res) => {
  try {
    const c = await prisma.customer.create({ data: { ...req.body, companyId: req.companyId } });
    ok(res, c, 201);
  } catch(e) { err(res, e.message, 500); }
});

// ═══════════════════════════
// EXPENSES
// ═══════════════════════════
app.get('/api/v1/expenses', auth, async (req, res) => {
  try {
    const expenses = await prisma.expense.findMany({ where: { companyId: req.companyId }, orderBy: { date: 'desc' }, take: 100 });
    ok(res, expenses);
  } catch(e) { err(res, e.message, 500); }
});

app.post('/api/v1/expenses', auth, async (req, res) => {
  try {
    const expense = await prisma.expense.create({ data: { ...req.body, companyId: req.companyId, userId: req.user.id } });
    ok(res, expense, 201);
  } catch(e) { err(res, e.message, 500); }
});

// ═══════════════════════════
// EMPLOYEES
// ═══════════════════════════
app.get('/api/v1/employees', auth, async (req, res) => {
  try {
    const emps = await prisma.employee.findMany({ where: { companyId: req.companyId }, orderBy: { name: 'asc' } });
    ok(res, emps);
  } catch(e) { err(res, e.message, 500); }
});

app.post('/api/v1/employees', auth, async (req, res) => {
  try {
    const emp = await prisma.employee.create({ data: { ...req.body, companyId: req.companyId } });
    ok(res, emp, 201);
  } catch(e) { err(res, e.message, 500); }
});

// ═══════════════════════════
// ACCOUNTS (شجرة الحسابات)
// ═══════════════════════════
app.get('/api/v1/accounts', auth, async (req, res) => {
  try {
    const accounts = await prisma.account.findMany({ where: { companyId: req.companyId }, orderBy: { code: 'asc' } });
    ok(res, accounts);
  } catch(e) { err(res, e.message, 500); }
});

app.post('/api/v1/accounts', auth, async (req, res) => {
  try {
    const acc = await prisma.account.create({ data: { ...req.body, companyId: req.companyId } });
    ok(res, acc, 201);
  } catch(e) { err(res, e.message, 500); }
});

// ═══════════════════════════
// JOURNAL ENTRIES (القيود اليومية)
// ═══════════════════════════
app.get('/api/v1/journal', auth, async (req, res) => {
  try {
    const entries = await prisma.journalEntry.findMany({
      where: { companyId: req.companyId },
      include: { lines: { include: { account: { select: { code: true, nameAr: true } } } } },
      orderBy: { date: 'desc' }, take: 50
    });
    ok(res, entries);
  } catch(e) { err(res, e.message, 500); }
});

app.post('/api/v1/journal', auth, async (req, res) => {
  try {
    const { date, description, reference, lines } = req.body;
    const totalDebit = lines.reduce((s,l) => s+(l.debit||0), 0);
    const totalCredit = lines.reduce((s,l) => s+(l.credit||0), 0);
    if (Math.abs(totalDebit-totalCredit) > 0.01) return err(res, 'Debits must equal credits');
    const count = await prisma.journalEntry.count({ where: { companyId: req.companyId } });
    const entry = await prisma.journalEntry.create({
      data: { entryNumber: `JE-${new Date().getFullYear()}-${String(count+1).padStart(5,'0')}`, date: new Date(date), description, reference, totalDebit, totalCredit, isPosted: true, companyId: req.companyId, lines: { create: lines } },
      include: { lines: true }
    });
    ok(res, entry, 201);
  } catch(e) { err(res, e.message, 500); }
});

// ═══════════════════════════
// REPORTS
// ═══════════════════════════
app.get('/api/v1/reports/profit-loss', auth, async (req, res) => {
  try {
    const from = req.query.from ? new Date(req.query.from) : new Date(new Date().getFullYear(), 0, 1);
    const to = req.query.to ? new Date(req.query.to) : new Date();
    const [revenue, expenses, vatCollected] = await Promise.all([
      prisma.invoice.aggregate({ where: { companyId: req.companyId, status: { in: ['PAID','ISSUED','PARTIAL'] }, issueDate: { gte: from, lte: to } }, _sum: { subtotal: true, vatAmount: true, total: true, discountAmount: true } }),
      prisma.expense.aggregate({ where: { companyId: req.companyId, date: { gte: from, lte: to } }, _sum: { amount: true, vatAmount: true } }),
      prisma.invoice.aggregate({ where: { companyId: req.companyId, status: { in: ['PAID','ISSUED','PARTIAL'] }, issueDate: { gte: from, lte: to } }, _sum: { vatAmount: true } }),
    ]);
    const totalRevenue = revenue._sum.subtotal || 0;
    const totalExpenses = expenses._sum.amount || 0;
    ok(res, { period: { from, to }, revenue: { gross: totalRevenue, vat: revenue._sum.vatAmount||0, net: revenue._sum.total||0 }, expenses: { total: totalExpenses, vat: expenses._sum.vatAmount||0 }, profit: { gross: totalRevenue-totalExpenses, percentage: totalRevenue > 0 ? ((totalRevenue-totalExpenses)/totalRevenue*100).toFixed(2) : 0 }, vatDue: (vatCollected._sum.vatAmount||0)-(expenses._sum.vatAmount||0) });
  } catch(e) { err(res, e.message, 500); }
});

app.get('/api/v1/reports/trial-balance', auth, async (req, res) => {
  try {
    const accounts = await prisma.account.findMany({
      where: { companyId: req.companyId, isActive: true },
      include: { journalLines: true },
      orderBy: { code: 'asc' }
    });
    const tb = accounts.map(a => {
      const debit = a.journalLines.reduce((s,l) => s+l.debit, 0);
      const credit = a.journalLines.reduce((s,l) => s+l.credit, 0);
      return { code: a.code, nameAr: a.nameAr, type: a.type, debit, credit, balance: Math.abs(debit-credit), side: debit >= credit ? 'DEBIT' : 'CREDIT' };
    }).filter(a => a.debit > 0 || a.credit > 0);
    const totals = tb.reduce((acc,a) => ({ debit: acc.debit+a.debit, credit: acc.credit+a.credit }), { debit:0, credit:0 });
    ok(res, { accounts: tb, totals, isBalanced: Math.abs(totals.debit-totals.credit) < 0.01 });
  } catch(e) { err(res, e.message, 500); }
});

app.get('/api/v1/reports/vat', auth, async (req, res) => {
  try {
    const from = req.query.from ? new Date(req.query.from) : new Date(new Date().getFullYear(), new Date().getMonth(), 1);
    const to = req.query.to ? new Date(req.query.to) : new Date();
    const [salesVat, purchaseVat] = await Promise.all([
      prisma.invoice.aggregate({ where: { companyId: req.companyId, status: { in: ['PAID','ISSUED','PARTIAL'] }, issueDate: { gte: from, lte: to } }, _sum: { vatAmount: true, subtotal: true, total: true } }),
      prisma.expense.aggregate({ where: { companyId: req.companyId, date: { gte: from, lte: to } }, _sum: { vatAmount: true, amount: true } }),
    ]);
    const vatCollected = salesVat._sum.vatAmount || 0;
    const vatPaid = purchaseVat._sum.vatAmount || 0;
    ok(res, { period: { from, to }, sales: { taxable: salesVat._sum.subtotal||0, vat: vatCollected, total: salesVat._sum.total||0 }, purchases: { amount: purchaseVat._sum.amount||0, vat: vatPaid }, netVatDue: vatCollected-vatPaid, status: vatCollected >= vatPaid ? 'DUE' : 'REFUND' });
  } catch(e) { err(res, e.message, 500); }
});

// ═══════════════════════════
// COMPANY
// ═══════════════════════════
app.get('/api/v1/company', auth, async (req, res) => {
  try {
    const company = await prisma.company.findUnique({ where: { id: req.companyId }, include: { branches: true } });
    ok(res, company);
  } catch(e) { err(res, e.message, 500); }
});

app.put('/api/v1/company', auth, async (req, res) => {
  try {
    const company = await prisma.company.update({ where: { id: req.companyId }, data: req.body });
    ok(res, company);
  } catch(e) { err(res, e.message, 500); }
});

app.get('/api/v1/company/users', auth, async (req, res) => {
  try {
    const users = await prisma.user.findMany({ where: { companyId: req.companyId }, select: { id:true, username:true, fullName:true, email:true, role:true, isActive:true, lastLogin:true } });
    ok(res, users);
  } catch(e) { err(res, e.message, 500); }
});

app.get('/api/v1/company/audit-log', auth, async (req, res) => {
  try {
    const logs = await prisma.auditLog.findMany({
      where: { user: { companyId: req.companyId } },
      include: { user: { select: { fullName: true } } },
      orderBy: { createdAt: 'desc' }, take: 100
    });
    ok(res, logs);
  } catch(e) { err(res, e.message, 500); }
});

// ═══════════════════════════
// 404 & ERROR
// ═══════════════════════════
app.use((req, res) => res.status(404).json({ error: `${req.method} ${req.path} not found` }));
app.use((e, req, res, next) => {
  console.error(e);
  res.status(e.status||500).json({ error: process.env.NODE_ENV==='production' ? 'Server error' : e.message });
});

// ═══════════════════════════
// START
// ═══════════════════════════
app.listen(PORT, async () => {
  console.log(`⚡ FastFlow ERP running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 API: http://localhost:${PORT}/api/v1`);
  console.log(`❤️  Health: http://localhost:${PORT}/health`);
  try {
    await prisma.$connect();
    console.log('✅ Database connected');
  } catch(e) {
    console.error('❌ Database error:', e.message);
  }
});

module.exports = app;
