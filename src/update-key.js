'use strict';
// Öffentlicher Ed25519-Schlüssel, mit dem offizielle RF-NetGuard-Releases signiert werden (GitHub Actions).
// Er ist bewusst im Programm eingebaut: Updates, die nicht mit dem passenden privaten Schlüssel signiert sind, werden nie installiert.
// Eigene Forks tragen unter update.public_key ihren eigenen Schlüssel ein (und setzen update.builtin_key auf false).
module.exports = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhXxZXClJtKSlN1Zu2OYk2HHRSs7nVwf27Cgy4XIfq8k=
-----END PUBLIC KEY-----
`;
