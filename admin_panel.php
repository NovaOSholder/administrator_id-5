<?php
session_start();

// Veritabanı bağlantısı
$host = 'localhost';
$db = 'admin_panel';
$user = 'root';
$pass = '';
try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Veritabanı bağlantısı başarısız: " . $e->getMessage());
}

// Kullanıcı kontrol fonksiyonu
function checkLogin($username, $password, $pdo) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
    $stmt->execute([
        ':username' => $username,
        ':password' => md5($password) // Parolaları hashleyerek kontrol eder
    ]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Giriş kontrolü
if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $user = checkLogin($username, $password, $pdo);

    if ($user) {
        $_SESSION['user'] = $user;
        header("Location: ?page=admin");
        exit;
    } else {
        $error = "Geçersiz kullanıcı adı veya şifre!";
    }
}

// Çıkış işlemi
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: ?page=login");
    exit;
}

// Sayfa kontrolü
$page = $_GET['page'] ?? 'login';

// Kullanıcı ekleme işlemi
if (isset($_POST['add_user']) && isset($_SESSION['user'])) {
    $newUsername = $_POST['new_username'];
    $newPassword = md5($_POST['new_password']);
    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
    $stmt->execute([
        ':username' => $newUsername,
        ':password' => $newPassword
    ]);
    $success = "Yeni kullanıcı başarıyla eklendi!";
}

?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel</title>
</head>
<body>
    <?php if ($page == 'login'): ?>
        <!-- Giriş Formu -->
        <h2>Admin Panel Giriş</h2>
        <?php if (isset($error)) echo "<p style='color:red;'>$error</p>"; ?>
        <form method="POST">
            <label>Kullanıcı Adı:</label>
            <input type="text" name="username" required><br>
            <label>Şifre:</label>
            <input type="password" name="password" required><br>
            <button type="submit" name="login">Giriş Yap</button>
        </form>
    <?php elseif ($page == 'admin' && isset($_SESSION['user'])): ?>
        <!-- Admin Paneli -->
        <h2>Hoşgeldiniz, <?php echo htmlspecialchars($_SESSION['user']['username']); ?></h2>
        <a href="?logout=true">Çıkış Yap</a>
        <h3>Kullanıcı Ekle</h3>
        <?php if (isset($success)) echo "<p style='color:green;'>$success</p>"; ?>
        <form method="POST">
            <label>Yeni Kullanıcı Adı:</label>
            <input type="text" name="new_username" required><br>
            <label>Yeni Şifre:</label>
            <input type="password" name="new_password" required><br>
            <button type="submit" name="add_user">Ekle</button>
        </form>

        <h3>Mevcut Kullanıcılar</h3>
        <ul>
            <?php
            $stmt = $pdo->query("SELECT * FROM users");
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                echo "<li>" . htmlspecialchars($row['username']) . "</li>";
            }
            ?>
        </ul>
    <?php else: ?>
        <!-- Yetkisiz Erişim -->
        <h2>Erişim Engellendi</h2>
        <p>Lütfen <a href="?page=login">giriş yapın</a>.</p>
    <?php endif; ?>
</body>
</html>
