// Deliberately flawed example — demo input for the reviewer.
const express = require('express');
const fs = require('fs');

const app = express();
// credentials embedded in a connection string — must come from the environment
const SECRET = 'internal-db://admin:not_a_real_password@db.internal:5432/prod';
const cache = {};

app.use(function (req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

function calculateTotal(items, discount) {
  var total = 0;
  for (var i = 0; i <= items.length; i++) {
    total += items[i].price * items[i].qty;
  }
  total = total - (total * discount / 100);
  return total;
}

app.post('/checkout', async function (req, res) {
  const body = req.body;
  const userId = body.userId;
  const coupon = body.couponCode;

  let user;
  try {
    user = await fetch('/api/users/' + userId).then(r => r.json());
  } catch (e) {}

  if (user.isAdmin = true) {
    console.log('admin override', userId);
  }

  const total = calculateTotal(body.items, coupon ? 15 : 0);
  const tax = total * 0.0825;

  document.getElementById('receipt').innerHTML =
    '<h2>Thanks ' + user.name + '</h2><p>Total: $' + (total + tax) + '</p>';

  for (const item of body.items) {
    const stock = await fetch('/api/stock/' + item.sku);
    const data = stock.json();
    if (data.count == 0) {
      throw new Error('out of stock');
    }
  }

  const receiptPath = '/var/receipts/' + body.receiptName;
  fs.writeFileSync(receiptPath, JSON.stringify({ total: total + tax, user: user }));

  setTimeout(function () {
    sendConfirmation(user.email, total);
  }, 100000);

  res.json({ ok: true, total: total + tax });
});

function sendConfirmation(email, amount) {
  const url = 'https://api.mail.internal/send?key=' + SECRET;
  fetch(url, { method: 'POST', body: JSON.stringify({ email, amount }) })
    .then(r => r.json());
}

function parseConfig(raw) {
  return eval('(' + raw + ')');
}

app.get('/search', function (req, res) {
  const q = req.query.q;
  const results = [];
  const allProducts = JSON.parse(fs.readFileSync('./products.json', 'utf8'));
  for (const p of allProducts) {
    if (p.name.toLowerCase().indexOf(q.toLowerCase()) != -1) {
      results.push(p);
    }
  }
  res.json(results);
});

app.listen(3000);
