// Skrip kecil console: tema, tombol salin, dan konfirmasi destruktif.
// Sengaja satu berkas agar CSP bisa memakai `script-src 'self'` tanpa
// `unsafe-inline` maupun hash per skrip.

// 1. Tema sebelum CSS dilukis, supaya tidak ada kedipan tema salah.
(function () {
    var pilihan = null;
    try { pilihan = localStorage.getItem('sanca-tema'); } catch (e) { /* mode privat */ }
    if (pilihan !== 'tanah-malam' && pilihan !== 'tanah-siang') {
        pilihan = window.matchMedia('(prefers-color-scheme: light)').matches
            ? 'tanah-siang'
            : 'tanah-malam';
    }
    document.documentElement.setAttribute('data-theme', pilihan);
})();

// 2. Toggle tema di navbar, jalan setelah DOM siap.
function initThemeToggle() {
    var tombol = document.getElementById('theme-toggle');
    if (!tombol) { return; }
    var gelap = document.documentElement.getAttribute('data-theme') === 'tanah-malam';
    tombol.setAttribute('aria-pressed', gelap ? 'true' : 'false');

    tombol.addEventListener('click', function () {
        var sekarang = document.documentElement.getAttribute('data-theme');
        var berikut = sekarang === 'tanah-malam' ? 'tanah-siang' : 'tanah-malam';
        document.documentElement.setAttribute('data-theme', berikut);
        tombol.setAttribute('aria-pressed', berikut === 'tanah-malam' ? 'true' : 'false');
        try { localStorage.setItem('sanca-tema', berikut); } catch (e) { /* abaikan */ }
    });
}

// 3. Tombol salin kredensial (Clipboard API, gagal diam-diam).
function initCopyButtons() {
    document.querySelectorAll('[data-copy]').forEach(function (tombol) {
        tombol.addEventListener('click', function () {
            var target = document.getElementById(tombol.getAttribute('data-copy'));
            if (!target) { return; }
            navigator.clipboard.writeText(target.textContent.trim()).then(function () {
                var asal = tombol.textContent;
                tombol.textContent = 'Tersalin';
                setTimeout(function () { tombol.textContent = asal; }, 2000);
            }).catch(function () { /* biarkan salin manual */ });
        });
    });
}

// 4. Konfirmasi aksi destruktif (rotasi secret).
function initConfirmForms() {
    document.querySelectorAll('form[data-confirm]').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!window.confirm(form.getAttribute('data-confirm'))) {
                event.preventDefault();
            }
        });
    });
}

// 5. Tombol batal modal: kosongkan slot modal.
function initModalCancel() {
    document.addEventListener('click', function (event) {
        var tombol = event.target && event.target.closest
            ? event.target.closest('[data-clear-modal]')
            : null;
        if (!tombol) { return; }
        var slot = document.getElementById('modal-slot');
        if (slot) { slot.innerHTML = ''; }
    });
}

function initAll() {
    initThemeToggle();
    initCopyButtons();
    initConfirmForms();
    initModalCancel();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAll);
} else {
    initAll();
}
