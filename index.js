const favicon = require('serve-favicon');
const crypto = require('node:crypto');
const express = require('express');
const { Deta } = require('deta');
const path = require('path');
require('dotenv').config();

app = express();
app.set('view engine', 'ejs');
app.use(express.json({ limit: '3mb' }));
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(favicon(path.join(__dirname, 'public', 'icon.png')));
app.use(express.urlencoded({ extended: false, limit: '3mb' }));

const deta = Deta(process.env.DETA_BASE_KEY);
const AllCodes = deta.Base('Codes');

app.get('/', (req, res) => {
    res.render('options');
});

app.get('/:id', async (req, res) => {
    if (req.params.id == 'sitemap.xml') {
        res.send(path.join(__dirname, 'public', 'sitemap.xml'));
    }
    else if (req.params.id == 'icon.png') {
        res.send(path.join(__dirname, 'public', 'icon.png'));
    }
    else if (req.params.id == 'new') {
        res.render('new');
    }
    else {
        let Code = await AllCodes.get(req.params.id == 'edit' ? req.query.id : req.params.id);
        if (Code != null) {
            if (req.params.id == 'edit') {
                if (req.query.password != null) {
                    let EncryptedPassword1 = crypto.createHmac('sha512', req.query.password);
                    EncryptedPassword1.update(req.query.id);
                    EncryptedPassword2 = crypto.createHash('md5');
                    EncryptedPassword2.update(EncryptedPassword1.digest('hex'));
                    EncryptedPassword = EncryptedPassword2.digest('hex');
                    if (EncryptedPassword == Code.password) {
                        res.render('edit', { auth: false, password: EncryptedPassword, code: Code.code });
                    }
                    else {
                        res.send({ status: 401, message: 'Incorrect Password' });
                    }
                }
                else {
                    res.render('edit', { auth: true, code: Code.code });
                }
            }
            else {
                await AllCodes.put({
                    key: Code.key,
                    password: Code.password,
                    code: Code.code,
                    email: Code.email,
                    requests: Code.requests + 1
                }, '', {
                    expireIn: 3.154e+7
                });
                res.send(Code.code);
            }
        }
        else {
            res.status(404).render('404');
        }
    }
});

async function GenerateAUniqueCodeID() {
    let uuid = crypto.randomUUID();
    if (await AllCodes.get(uuid) != null) {
        GenerateAUniqueCodeID();
    }
    else {
        return uuid;
    }
}

app.post('/verify-password', async (req, res) => {
    if (req.headers.referer != null) {
        let url = new URL(req.headers.referer);
        let code = await AllCodes.get(url.searchParams.get('id'));
        if (req.body.password != null) {
            if (code != null) {
                let password = req.body.password;
                let EncryptedPassword1 = crypto.createHmac('sha512', password);
                EncryptedPassword1.update(code.key);
                EncryptedPassword2 = crypto.createHash('md5');
                EncryptedPassword2.update(EncryptedPassword1.digest('hex'));
                EncryptedPassword = EncryptedPassword2.digest('hex');
                if (EncryptedPassword == code.password) {
                    res.send({ success: true, encrypted: EncryptedPassword });
                }
                else {
                    res.send({ success: false, error: 'Incorrect Password' });
                }
            } else {
                res.send({ success: false, error: 'Invalid Code' });
            }
        } else {
            res.send({ success: false, error: 'Password Not Found In Request' });
        }
    } else {
        res.send({ success: false, error: 'Please Use Another Browser!' });
    }
});

app.post('/share', async (req, res) => {
    let password = req.body.password;
    let code = req.body.code;
    let id = req.body.id;
    let email = req.body.email;
    if (password != null && code != null && email != null) {
        if (id == null || id.trim() == '') {
            id = await GenerateAUniqueCodeID();
        }
        id = id.trim().replace(/[^\w\d]/g, '').toLowerCase();
        if (await AllCodes.get(id) == null && id != 'sitemap.xml' && id != 'edit' && id != 'new' && id != 'icon.png') {
            let EncryptedPassword1 = crypto.createHmac('sha512', password);
            EncryptedPassword1.update(id);
            EncryptedPassword2 = crypto.createHash('md5');
            EncryptedPassword2.update(EncryptedPassword1.digest('hex'));
            EncryptedPassword = EncryptedPassword2.digest('hex');

            await AllCodes.put({
                key: id,
                password: EncryptedPassword,
                code: code,
                email: email,
                requests: 0
            }, '', {
                expireIn: 3.154e+7
            });

            res.send({ success: true, id: id });
        } else {
            res.send({ success: false, error: 'Name Of Code Is Already Used, Try Something Else!' });
        }
    } else {
        res.send({ success: false, error: 'Invalid Request' });
    }
});

app.post('/save', async (req, res) => {
    if (req.body.password != null && req.body.code != null && req.body.id != null) {
        if (req.body.code.length < 405522) {
            let Code = await AllCodes.get(req.body.id);
            if (Code != null) {
                if (req.body.password == Code.password) {
                    await AllCodes.put({
                        key: req.body.id,
                        code: req.body.code,
                        password: Code.password,
                        email: Code.email,
                        requests: Code.requests
                    }, '', {
                        expireIn: 3.154e+7
                    });
                    res.send({ success: true });
                }
                else {
                    res.send({ success: false, error: 'Incorrect Password!' });
                }
            }
            else {
                res.send({ success: false, error: 'Invalid Code' });
            }
        }
        else {
            res.send({ success: false, error: 'Invalid Request' });
        }
    }
    else {
        res.send({ success: false, error: 'Request Size Too Big\nMax Characters: 405522' });
    }
});

app.post('/delete', async (req, res) => {
    if (req.body.id != null && req.body.password != null) {
        let Code = await AllCodes.get(req.body.id);
        if (Code != null) {
            await AllCodes.delete(Code.key);
            res.send({ success: true });
        }
        else {
            res.send({ success: false, error: 'Invalid Code' });
        }
    }
    else {
        res.send({ success: false, error: 'Invalid Request' });
    }
});

app.listen(8080);