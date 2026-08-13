<?php
$id = $_GET['id'];
$pdo->query("SELECT * FROM users WHERE id=" . $id);
