<?php
session_start();
$base_url = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' 
    ? "https://" 
    : "http://" . $_SERVER['HTTP_HOST'];
require_once "db/connect.php";
date_default_timezone_set('Asia/Bangkok'); 

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
ini_set('error_log', 'php_errors.log');

// แก้ไขการตรวจสอบการสร้างโฟลเดอร์ผู้ใช้
if (!isset($_SESSION['username'])) {
    header("Location: index.php");
    exit();
}

$username = $_SESSION['username'];
$user_base_dir = "file_user66";
$user_dir = $user_base_dir . "/" . $username;

// ตรวจสอบและสร้างโฟลเดอร์หลัก
if (!file_exists($user_base_dir)) {
    try {
        if (!@mkdir($user_base_dir, 0777, true)) {
            throw new Exception('ไม่สามารถสร้างโฟลเดอร์หลักได้');
        }
        if (!@chmod($user_base_dir, 0777)) {
            throw new Exception('ไม่สามารถกำหนดสิทธิ์โฟลเดอร์หลัก');
        }
    } catch (Exception $e) {
        error_log("Error creating base directory: " . $e->getMessage());
        die($e->getMessage());
    }
}

// ตรวจสอบและสร้างโฟลเดอร์ผู้ใช้
if (!file_exists($user_dir)) {
    try {
        // ตรวจสอบสิทธิ์การเขียนของโฟลเดอร์หลัก
        if (!is_writable($user_base_dir)) {
            @chmod($user_base_dir, 0777);
            if (!is_writable($user_base_dir)) {
                throw new Exception('ไม่มีสิทธิ์เขียนในโฟลเดอร์หลัก');
            }
        }

        if (!@mkdir($user_dir, 0777, true)) {
            throw new Exception('ไม่สามารถสร้างโฟลเดอร์ผู้ใช้ได้');
        }
        if (!@chmod($user_dir, 0777)) {
            throw new Exception('ไม่สามารถกำหนดสิทธิ์โฟลเดอร์ผู้ใช้');
        }

        // สร้างเร็คคอร์ดสำหรับโฟลเดอร์ผู้ใช้
        $sql = "INSERT INTO file_folder (name, path, type, username, parent_id) VALUES (?, ?, 'folder', ?, NULL)";
        $stmt = $conn->prepare($sql);
        if (!$stmt->execute([$username, $user_dir, $username])) {
            throw new Exception('ไม่สามารถบันทึกข้อมูลโฟลเดอร์ผู้ใช้');
        }
    } catch (Exception $e) {
        error_log("Error creating user directory: " . $e->getMessage());
        die($e->getMessage());
    }
}

// แก้ไขการตรวจสอบโฟลเดอร์หลัก
$sql = "SELECT COUNT(*) FROM file_folder WHERE username = ? AND type = 'folder' AND parent_id = (
    SELECT id FROM file_folder WHERE username = ? AND path = ? AND type = 'folder' LIMIT 1
)";
$stmt = $conn->prepare($sql);
$stmt->execute([$username, $username, $user_dir]);
$has_folders = $stmt->fetchColumn() > 0;

// ตรวจสอบว่ามี record โฟลเดอร์ผู้ใช้ในฐานข้อมูลหรือไม่
$sql = "SELECT COUNT(*) FROM file_folder WHERE username = ? AND path = ? AND type = 'folder'";
$stmt = $conn->prepare($sql);
$stmt->execute([$username, $user_dir]);
$has_user_folder = $stmt->fetchColumn() > 0;

// Handle main folder creation - แก้ไขการสร้างแฟ้มหลัก
if (isset($_POST['create_main_folder'])) {
    $main_folder_name = trim($_POST['main_folder_name']);
    $main_folder_path = $user_dir . "/" . $main_folder_name;

    $response = array('success' => false, 'message' => '');

    try {
        // ตรวจสอบว่าโฟลเดอร์หลักมีอยู่และมีสิทธิ์เขียน
        if (!is_dir($user_base_dir) || !is_writable($user_base_dir)) {
            // พยายามสร้างและตั้งค่าสิทธิ์ใหม่
            if (!file_exists($user_base_dir)) {
                if (!@mkdir($user_base_dir, 0777, true)) {
                    throw new Exception('ไม่สามารถสร้างโฟลเดอร์หลักได้');
                }
            }
            @chmod($user_base_dir, 0777);
            
            if (!is_writable($user_base_dir)) {
                throw new Exception('ไม่มีสิทธิ์เขียนในโฟลเดอร์หลัก');
            }
        }

        // ตรวจสอบโฟลเดอร์ผู้ใช้
        if (!is_dir($user_dir) || !is_writable($user_dir)) {
            if (!file_exists($user_dir)) {
                if (!@mkdir($user_dir, 0777, true)) {
                    throw new Exception('ไม่สามารถสร้างโฟลเดอร์ผู้ใช้ได้');
                }
            }
            @chmod($user_dir, 0777);
            
            if (!is_writable($user_dir)) {
                throw new Exception('ไม่มีสิทธิ์เขียนในโฟลเดอร์ผู้ใช้');
            }
        }

        // หา ID ของโฟลเดอร์ผู้ใช้
        $sql = "SELECT id FROM file_folder WHERE username = ? AND path = ? LIMIT 1";
        $stmt = $conn->prepare($sql);
        $stmt->execute([$username, $user_dir]);
        $user_folder = $stmt->fetch();
        
        if (!$user_folder) {
            // สร้างเร็คคอร์ดโฟลเดอร์ผู้ใช้ถ้ายังไม่มี
            $sql = "INSERT INTO file_folder (name, path, type, username, parent_id) VALUES (?, ?, 'folder', ?, NULL)";
            $stmt = $conn->prepare($sql);
            if (!$stmt->execute([$username, $user_dir, $username])) {
                throw new Exception('ไม่สามารถสร้างข้อมูลโฟลเดอร์ผู้ใช้ได้');
            }
            
            // ดึง ID ที่เพิ่งสร้าง
            $sql = "SELECT id FROM file_folder WHERE username = ? AND path = ? LIMIT 1";
            $stmt = $conn->prepare($sql);
            $stmt->execute([$username, $user_dir]);
            $user_folder = $stmt->fetch();
            
            if (!$user_folder) {
                throw new Exception('ไม่สามารถดึงข้อมูลโฟลเดอร์ผู้ใช้ได้');
            }
        }

        // ตรวจสอบชื่อโฟลเดอร์
        if ($main_folder_name === '') {
            throw new Exception('กรุณากรอกชื่อแฟ้ม');
        }
        
        if (preg_match('/[\/\\\\:*?"<>|]/', $main_folder_name)) {
            throw new Exception('ชื่อแฟ้มมีอักขระต้องห้าม');
        }
        
        if (file_exists($main_folder_path)) {
            throw new Exception('มีแฟ้มชื่อนี้อยู่แล้ว');
        }

        // สร้างโฟลเดอร์ใหม่
        if (!@mkdir($main_folder_path, 0777, true)) {
            throw new Exception('ไม่สามารถสร้างแฟ้มได้ (รหัสข้อผิดพลาด: ' . error_get_last()['message'] . ')');
        }
        @chmod($main_folder_path, 0777);

        // บันทึกข้อมูลในฐานข้อมูล
        $sql = "INSERT INTO file_folder (name, path, type, username, parent_id) VALUES (?, ?, 'folder', ?, ?)";
        $stmt = $conn->prepare($sql);
        if (!$stmt->execute([$main_folder_name, $main_folder_path, $username, $user_folder['id']])) {
            // ถ้าบันทึกฐานข้อมูลไม่สำเร็จ ให้ลบโฟลเดอร์ที่สร้างไป
            @rmdir($main_folder_path);
            throw new Exception('ไม่สามารถบันทึกข้อมูลได้');
        }

        $response['success'] = true;
        $response['message'] = 'สร้างแฟ้มสำเร็จ';

    } catch (Exception $e) {
        $response['message'] = $e->getMessage();
        error_log("Folder creation error: " . $e->getMessage());
    }

    header('Content-Type: application/json');
    echo json_encode($response);
    exit();
}

// Add function to delete directory recursively
function deleteDirectory($dir) {
    if (!is_dir($dir)) {
        return true;
    }
    
    $files = array_diff(scandir($dir), array('.', '..'));
    foreach ($files as $file) {
        $path = $dir . '/' . $file;
        if (is_dir($path)) {
            chmod($path, 0777);
            deleteDirectory($path);
        } else {
            chmod($path, 0777);
            @unlink($path);
        }
    }
    return @rmdir($dir);
}

// Modify delete handler
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    
    try {
        // ดึงข้อมูลไฟล์/โฟลเดอร์ที่จะลบ
        $sql = "SELECT * FROM file_folder WHERE id = ? AND username = ?";
        $stmt = $conn->prepare($sql);
        $stmt->execute([$id, $username]);
        $item = $stmt->fetch();

        if (!$item) {
            throw new Exception('ไม่พบรายการที่ต้องการลบ');
        }

        // ลบข้อมูลในฐานข้อมูลก่อน
        if ($item['type'] == 'folder') {
            // ลบข้อมูลโฟลเดอร์และไฟล์ย่อยในฐานข้อมูล
            $sql = "DELETE FROM file_folder WHERE path LIKE ?";
            $stmt = $conn->prepare($sql);
            $pathPattern = $item['path'] . '%';
            if(!$stmt->execute([$pathPattern])) {
                throw new Exception('ไม่สามารถลบข้อมูลในฐานข้อมูลได้');
            }
            
            // ลบไฟล์จริง
            if (file_exists($item['path'])) {
                chmod($item['path'], 0777); // ให้สิทธิ์เต็มที่
                if (!deleteDirectory($item['path'])) {
                    throw new Exception('ไม่สามารถลบโฟลเดอร์ได้');
                }
            }
        } else {
            // ลบข้อมูลไฟล์ในฐานข้อมูล
            $sql = "DELETE FROM file_folder WHERE id = ?";
            $stmt = $conn->prepare($sql);
            if(!$stmt->execute([$id])) {
                throw new Exception('ไม่สามารถลบข้อมูลในฐานข้อมูลได้');
            }
            
            // ลบไฟล์จริง
            if (file_exists($item['path'])) {
                chmod($item['path'], 0777); // ให้สิทธิ์เต็มที่
                if (!@unlink($item['path'])) {
                    throw new Exception('ไม่สามารถลบไฟล์ได้');
                }
            }
        }

        echo json_encode([
            'success' => true,
            'message' => 'ลบรายการเรียบร้อยแล้ว'
        ]);

    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => $e->getMessage()
        ]);
    }
    exit();
}

// Handle folder creation
if (isset($_POST['create_folder'])) {
    $folder_name = $_POST['folder_name'];
    $parent_id = $_POST['parent_id'];
    
    // Get parent folder path
    if ($parent_id != 0) {
        $sql = "SELECT path FROM file_folder WHERE id = ? AND username = ?";
        $stmt = $conn->prepare($sql);
        $stmt->execute([$parent_id, $username]);
        $parent_folder = $stmt->fetch();
        
        if ($parent_folder) {
            $new_folder = $parent_folder['path'] . "/" . $folder_name;
            
            if (!file_exists($new_folder)) {
                if (mkdir($new_folder, 0777, true)) {
                    $sql = "INSERT INTO file_folder (name, path, type, username, parent_id) VALUES (?, ?, 'folder', ?, ?)";
                    $stmt = $conn->prepare($sql);
                    $stmt->execute([$folder_name, $new_folder, $username, $parent_id]);
                }
            }
        }
    } else {
        // สร้างโฟลเดอร์ในระดับรูท
        $new_folder = $user_dir . "/" . $folder_name;
        if (!file_exists($new_folder)) {
            if (mkdir($new_folder, 0777, true)) {
                // หา ID ของโฟลเดอร์ผู้ใช้
                $sql = "SELECT id FROM file_folder WHERE username = ? AND path = ?";
                $stmt = $conn->prepare($sql);
                $stmt->execute([$username, $user_dir]);
                $user_folder = $stmt->fetch();
                
                if ($user_folder) {
                    $sql = "INSERT INTO file_folder (name, path, type, username, parent_id) VALUES (?, ?, 'folder', ?, ?)";
                    $stmt = $conn->prepare($sql);
                    $stmt->execute([$folder_name, $new_folder, $username, $user_folder['id']]);
                }
            }
        }
    }
}

// Handle file upload
if (isset($_FILES['file_upload'])) {
    $parent_id = $_POST['parent_id'];
    $file_name = basename($_FILES["file_upload"]["name"]);
    
    // Get parent folder path
    if ($parent_id != 0) {
        $sql = "SELECT path FROM file_folder WHERE id = ? AND username = ?";
        $stmt = $conn->prepare($sql);
        $stmt->execute([$parent_id, $username]);
        $parent_folder = $stmt->fetch();
        
        if ($parent_folder) {
            $target_dir = $parent_folder['path'] . "/";
        } else {
            echo json_encode(['success' => false, 'message' => 'ไม่พบโฟลเดอร์หลัก']);
            exit();
        }
    } else {
        // หา ID ของโฟลเดอร์ผู้ใช้
        $sql = "SELECT id FROM file_folder WHERE username = ? AND path = ?";
        $stmt = $conn->prepare($sql);
        $stmt->execute([$username, $user_dir]);
        $user_folder = $stmt->fetch();
        
        if ($user_folder) {
            $parent_id = $user_folder['id'];
        } else {
            echo json_encode(['success' => false, 'message' => 'ไม่พบโฟลเดอร์ผู้ใช้']);
            exit();
        }
        $target_dir = $user_dir . "/";
    }
    
    $target_file = $target_dir . $file_name;

    // Create directory if it doesn't exist
    if (!file_exists($target_dir)) {
        if (!mkdir($target_dir, 0777, true)) {
            echo json_encode(['success' => false, 'message' => 'ไม่สามารถสร้างโฟลเดอร์เป้าหมายได้']);
            exit();
        }
    }

    // Set directory permissions
    chmod($target_dir, 0777);

    // ตรวจสอบว่ามีไฟล์นี้ในฐานข้อมูลหรือไม่
    $sql = "SELECT COUNT(*) FROM file_folder WHERE path = ? AND username = ?";
    $stmt = $conn->prepare($sql);
    $stmt->execute([$target_file, $username]);
    $exists = $stmt->fetchColumn() > 0;

    if (!$exists && $parent_id) {
        if (move_uploaded_file($_FILES["file_upload"]["tmp_name"], $target_file)) {
            // Set file permissions
            chmod($target_file, 0644);
            
            $sql = "INSERT INTO file_folder (name, path, type, username, parent_id) VALUES (?, ?, 'file', ?, ?)";
            $stmt = $conn->prepare($sql);
            if ($stmt->execute([$file_name, $target_file, $username, $parent_id])) {
                echo json_encode(['success' => true, 'message' => 'อัปโหลดไฟล์สำเร็จ']);
            } else {
                unlink($target_file); // ลบไฟล์หากบันทึกฐานข้อมูลล้มเหลว
                echo json_encode(['success' => false, 'message' => 'ไม่สามารถบันทึกข้อมูลไฟล์ในฐานข้อมูลได้']);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'ไม่สามารถอัปโหลดไฟล์ได้']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'ไฟล์นี้มีอยู่แล้ว']);
    }
    exit();
}

// Add new PHP handler for file saving
if (isset($_POST['save_file'])) {
    $file_path = $_POST['file_path'];
    $content = $_POST['content'];
    
    try {
        // Verify the file belongs to the user
        $sql = "SELECT * FROM file_folder WHERE path = ? AND username = ?";
        $stmt = $conn->prepare($sql);
        $stmt->execute([$file_path, $username]);
        $file = $stmt->fetch();
        
        if ($file) {
            if (file_put_contents($file_path, $content)) {
                echo json_encode(['success' => true]);
            } else {
                throw new Exception('ไม่สามารถบันทึกไฟล์ได้');
            }
        } else {
            throw new Exception('ไม่มีสิทธิ์แก้ไขไฟล์นี้');
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit();
}

// Add this after other PHP handler sections
if (isset($_POST['generate_share'])) {
    try {
        $file_id = $_POST['file_id'];
        $share_token = bin2hex(random_bytes(16));
        $password = !empty($_POST['password']) ? password_hash($_POST['password'], PASSWORD_DEFAULT) : null;
        
        // เพิ่มการตั้งค่าเขตเวลา
        date_default_timezone_set('Asia/Bangkok');
        
        // Calculate expiration time
        $expires = null;
        if (!empty($_POST['expires'])) {
            $expires = new DateTime('now', new DateTimeZone('Asia/Bangkok'));
            switch ($_POST['expires']) {
                case '5m': $expires->modify('+5 minutes'); break;
                case '10m': $expires->modify('+10 minutes'); break;
                case '1h': $expires->modify('+1 hour'); break;
                case '2h': $expires->modify('+2 hours'); break;
                case '1d': $expires->modify('+1 day'); break;
                case '2d': $expires->modify('+2 days'); break;
                case '5d': $expires->modify('+5 days'); break;
                case '1w': $expires->modify('+1 week'); break;
            }
            $expires = $expires->format('Y-m-d H:i:s');
        }
        
        $sql = "UPDATE file_folder SET share_token = ?, share_password = ?, share_expires = ?, created_at = NOW() WHERE id = ? AND username = ? AND type = 'file'";
        $stmt = $conn->prepare($sql);
        if ($stmt->execute([$share_token, $password, $expires, $file_id, $username])) {
            echo json_encode(['success' => true, 'token' => $share_token]);
        } else {
            throw new Exception('Database update failed');
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit();
}

// Add these new PHP handlers at the top with other handlers:
if (isset($_POST['get_share_details'])) {
    $file_id = $_POST['file_id'];
    
    $sql = "SELECT *, share_token, share_password, share_expires, created_at FROM file_folder WHERE id = ? AND username = ? AND type = 'file'";
    $stmt = $conn->prepare($sql);
    $stmt->execute([$file_id, $username]);
    $file = $stmt->fetch();
    
    if ($file && $file['share_token']) {
        $long_url = "https://nknz.xyz/download.php?f=" . $file['share_token'];  // Changed from token to f
        $share_url = createShortUrl($long_url) ?: $long_url; // Use short URL if available, fallback to long URL
        
        // แก้ไขการจัดการวันที่
        $expires = null;
        if ($file['share_expires']) {
            $expires_date = new DateTime($file['share_expires']);
            $now = new DateTime();
            $isExpired = $now > $expires_date;
            $expires = $expires_date->format('d/m/Y H:i');
            
            // เพิ่มข้อมูลการหมดอายุเข้าไปในผลลัพธ์
            $data['is_expired'] = $isExpired;
        }
        
        echo json_encode([
            'success' => true,
            'share_url' => $share_url,
            'expires' => $expires,
            'is_expired' => isset($data['is_expired']) ? $data['is_expired'] : false,
            'has_password' => !empty($file['share_password']),
            'created_at' => date('d/m/Y H:i', strtotime($file['created_at']))
        ]);
    } else {
        echo json_encode(['success' => false]);
    }
    exit();
}

if (isset($_POST['cancel_share'])) {
    $file_id = $_POST['file_id'];
    
    $sql = "UPDATE file_folder SET share_token = NULL, share_password = NULL, share_expires = NULL WHERE id = ? AND username = ?";
    $stmt = $conn->prepare($sql);
    $success = $stmt->execute([$file_id, $username]);
    
    echo json_encode(['success' => $success]);
    exit();
}

// Add new handler for share link regeneration
if (isset($_POST['regenerate_share'])) {
    $file_id = $_POST['file_id'];
    $password = $_POST['password'];
    $expires = $_POST['expires'];
    $share_token = bin2hex(random_bytes(16));
    
    // เพิ่มการตั้งค่าเขตเวลา
    date_default_timezone_set('Asia/Bangkok');
    
    // Calculate new expiration time
    $expires_date = null;
    if (!empty($expires)) {
        $expires_date = new DateTime('now', new DateTimeZone('Asia/Bangkok'));
        switch ($expires) {
            case '5m': $expires_date->modify('+5 minutes'); break;
            case '10m': $expires_date->modify('+10 minutes'); break;
            case '1h': $expires_date->modify('+1 hour'); break;
            case '2h': $expires_date->modify('+2 hours'); break;
            case '1d': $expires_date->modify('+1 day'); break;
            case '2d': $expires_date->modify('+2 days'); break;
            case '5d': $expires_date->modify('+5 days'); break;
            case '1w': $expires_date->modify('+1 week'); break;
        }
        $expires_date = $expires_date->format('Y-m-d H:i:s');
    }
    
    // Update share settings with explicit timezone for created_at
    $sql = "UPDATE file_folder SET 
            share_token = ?, 
            share_password = ?, 
            share_expires = ?,
            created_at = CONVERT_TZ(NOW(), 'UTC', 'Asia/Bangkok')
            WHERE id = ? AND username = ? AND type = 'file'";
    $stmt = $conn->prepare($sql);
    if ($stmt->execute([
        $share_token,
        !empty($password) ? password_hash($password, PASSWORD_DEFAULT) : null,
        $expires_date,
        $file_id,
        $username
    ])) {
        echo json_encode(['success' => true, 'token' => $share_token]);
    } else {
        echo json_encode(['success' => false]);
    }
    exit();
}

// แก้ไขการแสดงรายการไฟล์และโฟลเดอร์
$current_folder_id = isset($_GET['folder']) ? $_GET['folder'] : 0;

if ($current_folder_id == 0) {
    // แสดงโฟลเดอร์หลักทั้งหมดยกเว้นโฟลเดอร์ผู้ใช้
    $sql = "SELECT * FROM file_folder WHERE username = ? AND parent_id IS NULL AND path != ?";
    $stmt = $conn->prepare($sql);
    $stmt->execute([$username, $user_dir]);
} else {
    // แสดงไฟล์และโฟลเดอร์ในโฟลเดอร์ปัจจุบัน
    $sql = "SELECT * FROM file_folder WHERE username = ? AND parent_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->execute([$username, $current_folder_id]);
}
$items = $stmt->fetchAll(PDO::FETCH_ASSOC);

// เชื่อมต่อฐานข้อมูล settings
$conn_settings = new mysqli("localhost", "root", "", "nkn");
if ($conn_settings->connect_error) {
    die("Connection failed: " . $conn_settings->connect_error);
}
$result_settings = $conn_settings->query("SELECT * FROM settings WHERE id=1");
$settings = $result_settings->fetch_assoc();
$conn_settings->close();

// เพิ่มฟังก์ชันสำหรับแปลงขนาดไฟล์
function formatFileSize($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } else {
        return number_format($bytes) . ' bytes';
    }
}

// คำนวณขนาดรวมของไฟล์ทั้งหมด
$total_size = 0;
foreach($items as $item) {
    if($item['type'] == 'file' && file_exists($item['path'])) {
        $size = @filesize($item['path']);
        if ($size !== false) {
            $total_size += $size;
        }
    }
}

// เพิ่มฟังก์ชันสำหรับเลือกไอคอนตามนามสกุลไฟล์
function getFileIcon($filename) {
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    
    $iconMap = [
        // Database
        'sql' => 'fa-database',
        // Documents
        'doc' => 'fa-file-word',
        'docx' => 'fa-file-word',
        'pdf' => 'fa-file-pdf',
        'txt' => 'fa-file-lines',
        'rtf' => 'fa-file-word',
        // Spreadsheets
        'xls' => 'fa-file-excel',
        'xlsx' => 'fa-file-excel',
        'csv' => 'fa-file-csv',
        // Presentations
        'ppt' => 'fa-file-powerpoint',
        'pptx' => 'fa-file-powerpoint',
        // Images
        'jpg' => 'fa-file-image',
        'jpeg' => 'fa-file-image',
        'png' => 'fa-file-image',
        'gif' => 'fa-file-image',
        'bmp' => 'fa-file-image',
        // Archive
        'zip' => 'fa-file-zipper',
        'rar' => 'fa-file-zipper',
        '7z' => 'fa-file-zipper',
        // Audio
        'mp3' => 'fa-file-audio',
        'wav' => 'fa-file-audio',
        // Video
        'mp4' => 'fa-file-video',
        'avi' => 'fa-file-video',
        'mov' => 'fa-file-video',
        // Code
        'php' => 'fa-file-code',
        'html' => 'fa-file-code',
        'css' => 'fa-file-code',
        'js' => 'fa-file-code',
        // Text
        'xml' => 'fa-file-code',
        'json' => 'fa-file-code'
    ];
    
    return isset($iconMap[$extension]) ? $iconMap[$extension] : 'fa-file';
}

// Add these functions after the existing function declarations
function generateShortCode($length = 6) {
    $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $code = '';
    for ($i = 0; $i < $length; $i++) {
        $code .= $chars[rand(0, strlen($chars) - 1)];
    }
    return $code;
}

function createShortUrl($longUrl) {
    global $conn;
    try {
        // Generate unique short code
        do {
            $shortCode = generateShortCode();
            $sql = "SELECT COUNT(*) FROM short_urls WHERE short_code = ?";
            $stmt = $conn->prepare($sql);
            $stmt->execute([$shortCode]);
        } while ($stmt->fetchColumn() > 0);
        
        // Insert short URL
        $sql = "INSERT INTO short_urls (short_code, long_url) VALUES (?, ?)";
        $stmt = $conn->prepare($sql);
        if ($stmt->execute([$shortCode, $longUrl])) {
            return "https://nknz.xyz/rsd867.php?c=" . $shortCode;
        }
    } catch (PDOException $e) {
        error_log("Database Error: " . $e->getMessage());
        return false;
    }
    return false;
}

// Add this table creation check
try {
    $sql = "CREATE TABLE IF NOT EXISTS short_urls (
        id INT AUTO_INCREMENT PRIMARY KEY,
        short_code VARCHAR(10) UNIQUE NOT NULL,
        long_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )";
    $conn->exec($sql);
} catch (PDOException $e) {
    error_log("Table Creation Error: " . $e->getMessage());
}

// Add handler for short URL creation
if (isset($_POST['create_short_url'])) {
    $longUrl = $_POST['url'];
    $shortUrl = createShortUrl($longUrl);
    echo json_encode(['success' => true, 'short_url' => $shortUrl]);
    exit();
}
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $settings['site_name']; ?></title>
    <link rel="shortcut icon" href="https://i.postimg.cc/4352xQSt/nkn122.png" type="image/png" sizes="16x16">
    <link rel="stylesheet" href="<?php echo $base_url; ?>/33/system/css/second.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
    <link rel="stylesheet" href="//cdn.datatables.net/1.13.4/css/jquery.dataTables.min.css">
    <script src="//cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
    <link href="https://kit-pro.fontawesome.com/releases/v6.2.0/css/pro.min.css" rel="stylesheet">
    <script src="//cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=<?php echo str_replace(' ', '+', $settings['font_family']); ?>&display=swap">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.0/min/vs/loader.min.js"></script>
    <?php include 'css/global-background.php'; ?>
    <style>
        :root {
            --main: #ff0000;
            --sub: #000000;
            --sub-opa-50: #ff000080;
            --sub-opa-25: #ff0000;
        }
        body {
            font-family: '<?php echo $settings['font_family']; ?>', sans-serif;
            color: <?php echo $settings['text_color']; ?>;
        }
        .category-card {
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-family: '<?php echo $settings['font_family']; ?>', sans-serif;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            margin-bottom: 1.5rem;
        }
        .category-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }
        
        /* เพิ่ม CSS สำหรับ Modal */
        .modal {
            display: none;
            position: fixed;
            z-index: 1050;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.4);
        }

        .modal.show {
            display: block;
        }

        .modal-backdrop {
            position: fixed;
            top: 0;
            left: 0;
            z-index: 1040;
            width: 100vw;
            height: 100vh;
            background-color: rgba(0, 0, 0, 0.5);
        }

        .modal-dialog {
            position: relative;
            width: auto;
            margin: 1.75rem auto;
            max-width: 500px;
        }

        #monaco-editor {
            width: 100%;
            height: 500px;
            border: 1px solid #ccc;
        }

        /* Add styles for Monaco Editor container */
        .monaco-editor-container {
            width: 100%;
            height: 70vh;
            margin: 0;
            padding: 0;
            overflow: hidden;
            border-radius: 4px;
        }

        /* Custom styling for SweetAlert2 modal when viewing code */
        .swal2-popup.code-view {
            padding: 0 !important;
            width: 98vw !important;
            height: 98vh !important;
            max-height: none !important;
        }

        .code-editor-container {
            display: flex;
            flex-direction: column;
            height: calc(98vh - 120px);
            overflow: hidden;
        }

        .editor-header {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 8px 15px;
            border-bottom: 1px solid #333;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-shrink: 0;
        }

        .editor-header .file-info {
            font-size: 0.9em;
            margin: 0;
        }

        .editor-header .file-info span {
            margin-right: 15px;
            white-space: nowrap;
        }

        .editor-header .btn-danger {
            padding: 4px 8px;
            font-size: 14px;
        }

        #monaco-editor {
            flex: 1;
            width: 100%;
            min-height: 0;
            text-align: left;
        }

        .editor-footer {
            background: #1e1e1e;
            border-top: 1px solid #333;
            padding: 8px;
            display: flex;
            justify-content: flex-end;
            gap: 8px;
            flex-shrink: 0;
        }

        /* Make buttons more compact */
        .editor-footer .btn {
            padding: 4px 12px;
            font-size: 0.9em;
        }

        /* Add CSS for command palette */
        .command-palette {
            position: fixed;
            top: 20%;
            left: 50%;
            transform: translateX(-50%);
            width: 600px;
            background: #252526;
            border: 1px solid #454545;
            border-radius: 6px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.4);
            z-index: 10000;
        }
        .command-input {
            width: 100%;
            padding: 8px 12px;
            border: none;
            background: #3c3c3c;
            color: #e0e0e0;
            font-size: 14px;
            outline: none;
        }
        .command-list {
            max-height: 300px;
            overflow-y: auto;
        }
        .command-item {
            padding: 6px 12px;
            cursor: pointer;
            color: #e0e0e0;
        }
        .command-item:hover {
            background: #04395e;
        }
    </style>
    <script>
        // Add base URL for fetch requests
        const baseUrl = '<?php echo $base_url; ?>';
        
        // Add this utility function at the start of your script
        async function fetchWithRetry(url, options, retries = 3) {
            for (let i = 0; i < retries; i++) {
                try {
                    const response = await fetch(url, {
                        ...options,
                        headers: {
                            ...options.headers,
                            'Cache-Control': 'no-cache',
                            'Pragma': 'no-cache'
                        }
                    });

                    // ตรวจสอบ content-type ว่าเป็น JSON หรือไม่
                    const contentType = response.headers.get('content-type');
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    if (contentType && contentType.indexOf('application/json') !== -1) {
                        return await response.json();
                    } else {
                        // ถ้าไม่ใช่ JSON (เช่น ได้ HTML กลับมา) ให้ redirect หรือแจ้งเตือน
                        const text = await response.text();
                        if (text.includes('<!DOCTYPE html>') && text.includes('login')) {
                            window.location.href = 'index.php';
                            return;
                        }
                        throw new Error('Unexpected response from server');
                    }
                } catch (error) {
                    console.error(`Attempt ${i + 1} failed:`, error);
                    if (i === retries - 1) throw error;
                    await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1))); // Exponential backoff
                }
            }
        }

        // Update form submit handler
        document.getElementById('mainFolderForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            Swal.fire({
                title: 'กำลังสร้างแฟ้ม...',
                allowOutsideClick: false,
                didOpen: () => {
                    Swal.showLoading();
                }
            });

            const formData = new FormData(this);
            formData.append('create_main_folder', '1');

            try {
                // Use window.location.origin to get full URL
                const url = window.location.origin + window.location.pathname;
                const data = await fetchWithRetry(url, {
                    method: 'POST',
                    body: formData
                });

                if (data.success) {
                    await Swal.fire({
                        icon: 'success',
                        title: 'สำเร็จ!',
                        text: data.message,
                        showConfirmButton: false,
                        timer: 1500
                    });
                    closeMainModal();
                    // เปลี่ยนจาก window.location.reload() เป็น redirect ไปหน้าเดิมแบบ fresh
                    window.location.replace(window.location.pathname + '?folder=0&t=' + Date.now());
                } else {
                    throw new Error(data.message || 'ไม่สามารถสร้างแฟ้มได้');
                }
            } catch (error) {
                console.error('Error:', error);
                Swal.fire({
                    icon: 'error', 
                    title: 'เกิดข้อผิดพลาด!',
                    text: error.message || 'เกิดข้อผิดพลาดในการเชื่อมต่อ กรุณาลองใหม่อีกครั้ง',
                    confirmButtonText: 'ลองใหม่'
                });
            }
        });
    </script>
</head>
<body>
<?php include_once('css/bar/nav2.php'); ?>
<div class="container-fluid p-0">
    <div class="container-sm m-cent p-0 pt-4" style="border-radius: 50px;">
        <div class="container-sm">
            <div class="container-fluid">
                <div class="container-fluid bg-white p-4 pt-4" data-aos="zoom-in">
                    <div class="d-flex mb-2">
                        <img src="https://i.postimg.cc/gkmMHmrt/application.png" class="align-self-center" style="max-height: 78px;">
                        <div class="align-self-center">
                            <h2 class="text-main ms-1 mb-0">&nbsp;จัดการไฟล์</h2>
                        </div>
                    </div>

                    <?php if (!$has_folders || !$has_user_folder): ?>
                        <div class="text-center my-5">
                            <h4 class="mb-4">คุณยังไม่มีแฟ้มสำหรับเก็บไฟล์</h4>
                            <button type="button" class="btn btn-warning btn-lg" onclick="showMainFolderDialog()">
                                <i class="fas fa-folder-plus"></i> สร้างแฟ้ม
                            </button>
                        </div>
                        <div class="modal" id="mainFolderDialog" tabindex="-1" aria-hidden="true">
                            <div class="modal-dialog">
                                <div class="modal-content">
                                    <div class="modal-header">
                                        <h5 class="modal-title">สร้างแฟ้ม</h5>
                                        <button type="button" class="btn-close" onclick="closeMainModal()"></button>
                                    </div>
                                    <form id="mainFolderForm">
                                        <div class="modal-body">
                                            <div class="mb-3">
                                                <label class="form-label">ชื่อแฟ้ม</label>
                                                <input type="text" class="form-control" name="main_folder_name" required>
                                            </div>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-secondary" onclick="closeMainModal()">ปิด</button>
                                            <button type="submit" class="btn btn-warning">สร้าง</button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                    <?php else: ?>
                        <!-- Add navigation breadcrumb -->
                        <?php if ($current_folder_id != 0): 
                            // ดึงข้อมูลโฟลเดอร์ปัจจุบันและตรวจสอบการมีอยู่
                            $sql = "SELECT * FROM file_folder WHERE id = ? AND username = ?";
                            $stmt = $conn->prepare($sql);
                            $stmt->execute([$current_folder_id, $username]);
                            $current_folder = $stmt->fetch();
                            
                            if ($current_folder): ?>
                                <nav aria-label="breadcrumb" class="mb-4">
                                    <ol class="breadcrumb">
                                        <li class="breadcrumb-item">
                                            <a href="?folder=0" class="text-decoration-none">
                                                <i class="fas fa-home"></i> หน้าหลัก
                                            </a>
                                        </li>
                                        <li class="breadcrumb-item active" aria-current="page">
                                            <?php echo htmlspecialchars($current_folder['name']); ?>
                                        </li>
                                    </ol>
                                </nav>
                            <?php else: ?>
                                <script>window.location.href = '?folder=0';</script>
                            <?php endif; ?>
                        <?php endif; ?>

                        <!-- Existing folder creation and file upload buttons -->
                        <div class="row mb-4">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <?php if ($current_folder_id != 0): ?>
                                        <button type="button" class="btn btn-warning" data-bs-toggle="modal" data-bs-target="#folderModal">
                                            <i class="fas fa-folder-plus"></i> สร้างโฟลเดอร์ใหม่
                                        </button>
                                        <button type="button" class="btn btn-primary ms-2" data-bs-toggle="modal" data-bs-target="#uploadModal">
                                            <i class="fas fa-upload"></i> อัพโหลดไฟล์
                                        </button>
                                    <?php else: ?>
                                        <button type="button" class="btn btn-warning" data-bs-toggle="modal" data-bs-target="#folderModal">
                                            <i class="fas fa-folder-plus"></i> สร้างแฟ้ม
                                        </button>
                                    <?php endif; ?>
                                </div>
                                <div class="d-none d-md-block">
                                    <span class="text-muted">
                                        <i class="fas fa-hdd"></i> ขนาดไฟล์ทั้งหมด: <?php echo formatFileSize($total_size); ?>
                                    </span>
                                </div>
                            </div>
                            <!-- แสดงขนาดไฟล์สำหรับมือถือ -->
                            <div class="d-md-none mt-3">
                                <span class="text-muted">
                                    <i class="fas fa-hdd"></i> ขนาดไฟล์ทั้งหมด: <?php echo formatFileSize($total_size); ?>
                                </span>
                            </div>
                        </div>
                        <div class="row">
                            <?php if(empty($items)): ?>
                                <div class="col-12">
                                    <div class="alert alert-warning py-2" role="alert" style="width: fit-content; margin: 0 auto;">
                                        <i class="fas fa-folder-open"></i>&nbsp; ไม่มีไฟล์หรือโฟลเดอร์
                                    </div>
                                </div>
                            <?php else: ?>
                                <?php foreach($items as $item): ?>
                                    <div class="col-md-3 col-sm-6 mb-4">
                                        <div class="card category-card shadow-sm text-center p-3" style="background-color: rgba(255, 255, 255, 0.95);">
                                            <?php if($item['type'] == 'folder'): ?>
                                                <a href="?folder=<?php echo $item['id']; ?>" class="text-decoration-none">
                                                    <i class="fas fa-folder fa-3x mb-2 text-warning"></i>
                                                    <h5 class="fw-bold text-dark"><?php echo htmlspecialchars($item['name']); ?></h5>
                                                </a>
                                            <?php else: ?>
                                                <a href="javascript:void(0)" onclick="showFileDetails(
                                                    '<?php echo htmlspecialchars($item['name']); ?>', 
                                                    '<?php echo file_exists($item['path']) ? date('d/m/Y H:i', filemtime($item['path'])) : 'ไม่พบไฟล์'; ?> น.', 
                                                    '<?php echo file_exists($item['path']) ? formatFileSize(filesize($item['path'])) : '0 bytes'; ?>', 
                                                    '<?php echo htmlspecialchars($item['path']); ?>', 
                                                    '<?php echo htmlspecialchars($item['username']); ?>'
                                                )" class="text-decoration-none">
                                                    <i class="fas <?php echo getFileIcon($item['name']); ?> fa-3x mb-2 text-primary"></i>
                                                    <h5 class="fw-bold text-dark"><?php echo htmlspecialchars($item['name']); ?></h5>
                                                    <p class="text-muted mb-2">
                                                        <small>
                                                            <?php if(file_exists($item['path'])): ?>
                                                                <i class="fas fa-clock"></i> <?php echo date('d/m/Y H:i', filemtime($item['path'])); ?> น.<br>
                                                                <i class="fas fa-hdd"></i> <?php echo formatFileSize(filesize($item['path'])); ?>
                                                            <?php else: ?>
                                                                <span class="text-danger">ไม่พบไฟล์</span>
                                                            <?php endif; ?>
                                                        </small>
                                                    </p>
                                                </a>
                                                <a href="<?php echo htmlspecialchars($item['path']); ?>" class="btn btn-primary w-100 mb-2" download>
                                                    <i class="fas fa-download"></i> ดาวน์โหลด
                                                </a>
                                                <?php if(empty($item['share_token'])): ?>
                                                    <button class="btn btn-info w-100 mb-2" onclick="generateShareLink(<?php echo $item['id']; ?>)">
                                                        <i class="fas fa-share"></i> แชร์
                                                    </button>
                                                <?php else: ?>
                                                    <button class="btn btn-secondary w-100 mb-2" onclick="showShareDetails(<?php echo $item['id']; ?>)">
                                                        <i class="fas fa-info-circle"></i> รายละเอียดการแชร์
                                                    </button>
                                                <?php endif; ?>
                                            <?php endif; ?>
                                            <a href="javascript:void(0)" 
                                               class="btn btn-warning w-100"
                                               onclick="confirmDelete(<?php echo $item['id']; ?>)">
                                                <i class="fas fa-trash"></i> ลบ
                                            </a>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    <br />
    <!-- Footer -->
    <footer class="bg-white shadow pt-3">
        <div class="container">
            <div class="row">
                <hr>
                <div class="container-fluid pt-3 pb-3">
                    <center>
                        <div class="col-5 col-lg-2 text-center mb-5">
                            <h5>ช่องทางการติดต่อ</h5>
                            <a href="https://www.facebook.com/nkn.227/" class="text-black" style="text-decoration: none;"><i class="fa-brands fa-facebook"></i> Facebook</a><br>
                            <a href="" class="text-black" style="text-decoration: none;"><i class="fa-brands fa-discord"></i> Discord</a><br>
                        </div>
                        <p class="text-dark mb-1"><strong>มีอะไรให้วิ่งรอบมอก่อนค่อยมาแจ้งปัญหา  nkn.66122</strong></p>
                    </center>
                </div>
            </div>
        </div>
    </footer>
</div>

<!-- Modals -->
<div class="modal fade" id="folderModal">
    <div class="modal-dialog">
        <div class="modal-content bg-light">
            <div class="modal-header">
                <h5 class="modal-title">สร้างโฟลเดอร์ใหม่</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST">
                <div class="modal-body">
                    <input type="hidden" name="parent_id" value="<?php echo $current_folder_id; ?>">
                    <div class="mb-3">
                        <label class="form-label">ชื่อโฟลเดอร์</label>
                        <input type="text" class="form-control" name="folder_name" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">ปิด</button>
                    <button type="submit" name="create_folder" class="btn btn-warning">สร้าง</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- File Upload Modal -->
<div class="modal fade" id="uploadModal">
    <div class="modal-dialog">
        <div class="modal-content bg-light">
            <div class="modal-header">
                <h5 class="modal-title">อัพโหลดไฟล์</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" enctype="multipart/form-data">
                <div class="modal-body">
                    <input type="hidden" name="parent_id" value="<?php echo $current_folder_id; ?>">
                    <div class="mb-3">
                        <label class="form-label">เลือกไฟล์</label>
                        <input type="file" class="form-control bg-white" name="file_upload" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">ปิด</button>
                    <button type="submit" class="btn btn-primary">อัพโหลด</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
    AOS.init();

    function showMainFolderDialog() {
        const modal = document.getElementById('mainFolderDialog');
        modal.classList.add('show');
        document.body.style.overflow = 'hidden';
    }

    function closeMainModal() {
        const modal = document.getElementById('mainFolderDialog');
        modal.classList.remove('show');
        document.body.style.overflow = '';
        document.body.style.removeProperty('padding-right');
    }

    document.getElementById('mainFolderForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Show loading
        Swal.fire({
            title: 'กำลังสร้างแฟ้ม...',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });

        const formData = new FormData(this);
        formData.append('create_main_folder', '1');
        
        // ใช้ relative path แทน absolute path
        const currentPath = window.location.pathname;
        const currentDir = currentPath.substring(0, currentPath.lastIndexOf('/'));
        const url = currentDir + '/file_management.php';

        fetch(url, {
            method: 'POST',
            body: formData,
            headers: {
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if(data.success) {
                Swal.fire({
                    icon: 'success',
                    title: 'สำเร็จ!',
                    text: data.message,
                    showConfirmButton: false,
                    timer: 1500
                }).then(() => {
                    closeMainModal();
                    // เปลี่ยนจาก window.location.reload() เป็น redirect ไปหน้าเดิมแบบ fresh
                    window.location.replace(window.location.pathname + '?folder=0&t=' + Date.now());
                });
            } else {
                throw new Error(data.message || 'ไม่สามารถสร้างแฟ้มได้');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            let errorMessage = 'เกิดข้อผิดพลาดในการเชื่อมต่อ กรุณาลองใหม่อีกครั้ง';
            if (error.message) {
                errorMessage = error.message;
            }
            Swal.fire({
                icon: 'error',
                title: 'เกิดข้อผิดพลาด!',
                text: errorMessage,
                confirmButtonText: 'ลองใหม่'
            });
        });
    });

    // ปิด Modal เมื่อคลิกพื้นที่นอก Modal
    window.onclick = function(event) {
        const modal = document.getElementById('mainFolderDialog');
        if (event.target === modal) {
            closeMainModal();
        }
    }

    function confirmDelete(id) {
        Swal.fire({
            title: 'ยืนยันการลบ',
            text: "คุณต้องการลบรายการนี้ใช่หรือไม่?",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'ใช่',
            cancelButtonText: 'ยกเลิก',
            allowOutsideClick: false,
            allowEscapeKey: false
        }).then((result) => {
            if (result.isConfirmed) {
                // แสดง loading
                Swal.fire({
                    title: 'กำลังลบ...',
                    allowOutsideClick: false,
                    allowEscapeKey: false,
                    didOpen: () => {
                        Swal.showLoading();
                    }
                });

                // ส่งคำขอลบ
                fetch('file_management.php?delete=' + id, {
                    method: 'GET',
                    headers: {
                        'Cache-Control': 'no-cache'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if(data.success) {
                        Swal.fire({
                            title: 'สำเร็จ!',
                            text: data.message,
                            icon: 'success',
                            allowOutsideClick: false,
                            allowEscapeKey: false
                        }).then(() => {
                            // รีเฟรชหน้าแบบบังคับ
                            window.location.href = window.location.pathname + 
                                '?folder=' + <?php echo $current_folder_id; ?> + 
                                '&t=' + new Date().getTime();
                        });
                    } else {
                        Swal.fire({
                            title: 'ผิดพลาด!',
                            text: data.message,
                            icon: 'error'
                        });
                    }
                })
                .catch(error => {
                    Swal.fire({
                        title: 'ผิดพลาด!',
                        text: 'เกิดข้อผิดพลาดในการลบ',
                        icon: 'error'
                    });
                    console.error('Error:', error);
                });
            }
        });
    }

    function showFileDetails(name, date, size, path, username) {
        const ext = name.split('.').pop().toLowerCase();
        
        // Define file types with additional code extensions
        const fileTypes = {
            code: {
                extensions: ['php', 'html', 'css', 'js', 'jsx', 'ts', 'tsx', 'json', 'xml', 'sql', 'py', 'java', 'cpp', 'c', 'cs', 'go', 'rb', 'rust', 'swift'],
                languageMap: {
                    'php': 'php',
                    'html': 'html',
                    'css': 'css',
                    'js': 'javascript',
                    'jsx': 'javascript',
                    'ts': 'typescript',
                    'tsx': 'typescript',
                    'json': 'json',
                    'xml': 'xml',
                    'sql': 'sql',
                    'py': 'python',
                    'java': 'java',
                    'cpp': 'cpp',
                    'c': 'c',
                    'cs': 'csharp',
                    'go': 'go',
                    'rb': 'ruby',
                    'rust': 'rust',
                    'swift': 'swift'
                }
            },
            text: ['txt', 'log', 'csv', 'md'],
            image: ['jpg', 'jpeg', 'png', 'gif', 'bmp'],
            pdf: ['pdf'],
            office: ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']
        };

        let detailsHtml = `
            <div class="text-start mb-3">
                <p><i class="fas fa-user"></i> ผู้อัพโหลด: ${username}</p>
                <p><i class="fas fa-clock"></i> วันที่: ${date}</p>
                <p><i class="fas fa-hdd"></i> ขนาด: ${size}</p>
            </div>`;

        // For code files, enhance the Monaco Editor setup
        if (fileTypes.code.extensions.includes(ext)) {
            fetch(path)
                .then(response => response.text())
                .then(content => {
                    Swal.fire({
                        html: `
                            <div class="code-editor-container">
                                <div class="editor-header">
                                    <div class="file-info">
                                        <span><i class="fas fa-code"></i> ${name}</span>
                                        <span><i class="fas fa-user"></i> ${username}</span>
                                        <span><i class="fas fa-clock"></i> ${date}</span>
                                        <span><i class="fas fa-hdd"></i> ${size}</span>
                                    </div>
                                    <div>
                                        <button class="btn btn-danger btn-sm" onclick="Swal.close()">
                                            <i class="fas fa-times"></i>
                                        </button>
                                    </div>
                                </div>
                                <div id="monaco-editor"></div>
                                <div class="editor-footer">
                                    <button class="btn btn-primary" onclick="window.location.href='${path}'">ดาวน์โหลด</button>
                                    <button class="btn btn-success" onclick="saveCurrentFile('${path}')">บันทึก</button>
                                </div>
                            </div>
                        `,
                        width: '98vw',
                        padding: 0,
                        background: '#1e1e1e',
                        customClass: {
                            popup: 'code-view'
                        },
                        showConfirmButton: false,
                        showCloseButton: false,
                        didOpen: () => {
                            require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.0/min/vs' }});
                            require(['vs/editor/editor.main'], function() {
                                // Register VS Code command palette actions
                                const commandPaletteActions = [
                                    {
                                        id: 'format',
                                        label: 'Format Document',
                                        keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyF],
                                        run: (editor) => editor.getAction('editor.action.formatDocument').run()
                                    },
                                    {
                                        id: 'find',
                                        label: 'Find',
                                        keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyF],
                                        run: (editor) => editor.getAction('actions.find').run()
                                    },
                                    {
                                        id: 'replace',
                                        label: 'Replace',
                                        keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyH],
                                        run: (editor) => editor.getAction('editor.action.startFindReplaceAction').run()
                                    }
                                ];

                                const editor = monaco.editor.create(document.getElementById('monaco-editor'), {
                                    value: content,
                                    language: fileTypes.code.languageMap[ext] || 'plaintext',
                                    theme: 'vs-dark',
                                    fontSize: 14,
                                    lineHeight: 21,
                                    // VS Code-like features
                                    minimap: { 
                                        enabled: true,
                                        maxColumn: 120,
                                        renderCharacters: false,
                                        scale: 1
                                    },
                                    folding: true,
                                    foldingStrategy: 'indentation',
                                    renderIndentGuides: true,
                                    contextmenu: true,
                                    mouseWheelZoom: true,
                                    quickSuggestions: {
                                        other: true,
                                        comments: true,
                                        strings: true
                                    },
                                    parameterHints: {
                                        enabled: true,
                                        cycle: true
                                    },
                                    suggest: {
                                        localityBonus: true,
                                        snippetsPreventQuickSuggestions: false,
                                        showIcons: true,
                                        maxVisibleSuggestions: 12,
                                        showMethods: true,
                                        showFunctions: true,
                                        showConstructors: true,
                                        showFields: true,
                                        showVariables: true,
                                        showClasses: true,
                                        showStructs: true,
                                        showInterfaces: true,
                                        showModules: true,
                                        showProperties: true,
                                        showEvents: true,
                                        showOperators: true,
                                        showUnits: true,
                                        showValues: true,
                                        showConstants: true,
                                        showEnums: true,
                                        showEnumMembers: true,
                                        showKeywords: true,
                                        showWords: true,
                                        showColors: true,
                                        showFiles: true,
                                        showReferences: true,
                                        showFolders: true,
                                        showTypeParameters: true,
                                        showSnippets: true
                                    },
                                    // VS Code controls
                                    scrollbar: {
                                        verticalScrollbarSize: 14,
                                        horizontalScrollbarSize: 14,
                                        alwaysConsumeMouseWheel: false
                                    },
                                    renderLineHighlight: 'all',
                                    renderWhitespace: 'selection',
                                    occurrencesHighlight: true,
                                    cursorBlinking: 'smooth',
                                    cursorSmoothCaretAnimation: true,
                                    smoothScrolling: true,
                                    mouseWheelScrollSensitivity: 1,
                                    multiCursorModifier: 'alt',
                                    wordBasedSuggestions: true,
                                    // Keybindings like VS Code
                                    automaticLayout: true
                                });

                                // Register command palette
                                editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyP, () => {
                                    // Create command palette UI
                                    const palette = document.createElement('div');
                                    palette.className = 'command-palette';
                                    palette.innerHTML = `
                                        <input type="text" class="command-input" placeholder="Type a command...">
                                        <div class="command-list"></div>
                                    `;
                                    
                                    document.body.appendChild(palette);
                                    const input = palette.querySelector('.command-input');
                                    input.focus();

                                    // Filter and show commands
                                    input.addEventListener('input', () => {
                                        const query = input.value.toLowerCase();
                                        const filteredCommands = commandPaletteActions.filter(
                                            cmd => cmd.label.toLowerCase().includes(query)
                                        );
                                        // Show filtered commands
                                        showFilteredCommands(filteredCommands, palette.querySelector('.command-list'));
                                    });
                                });

                                // Add VS Code keyboard shortcuts
                                editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
                                    saveCurrentFile(path);
                                });

                                window.currentEditor = editor;
                                
                                // Format on load
                                setTimeout(() => {
                                    editor.getAction('editor.action.formatDocument').run();
                                    editor.focus();
                                }, 100);
                            });
                        },
                        willClose: () => {
                            if (window.currentEditor) {
                                window.currentEditor.dispose();
                            }
                        }
                    });
                });
            return;
        }

        // Handle other file types
        if (fileTypes.text.includes(ext)) {
            fetch(path)
                .then(response => response.text())
                .then(content => {
                    Swal.fire({
                        title: name,
                        html: `
                            ${detailsHtml}
                            <div class="form-group">
                                <textarea id="fileContent" class="form-control" style="height: 400px; font-family: monospace;">${content.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</textarea>
                            </div>
                        `,
                        width: '80%',
                        showCloseButton: true,
                        showDenyButton: true,
                        confirmButtonText: 'บันทึก',
                        denyButtonText: 'ดาวน์โหลด',
                        showCancelButton: true,
                        cancelButtonText: 'ปิด'
                    }).then((result) => {
                        if (result.isConfirmed) {
                            const newContent = document.getElementById('fileContent').value;
                            saveFile(path, newContent);
                        } else if (result.isDenied) {
                            window.location.href = path;
                        }
                    });
                });
            return;
        } else if (fileTypes.image.includes(ext)) {
            Swal.fire({
                title: name,
                html: `
                    ${detailsHtml}
                    <img src="${path}" class="img-fluid mb-3" alt="${name}">
                `,
                width: '80%',
                showCloseButton: true,
                showDenyButton: true,
                denyButtonText: 'ดาวน์โหลด',
                showCancelButton: true,
                cancelButtonText: 'ปิด'
            }).then((result) => {
                if (result.isDenied) {
                    window.location.href = path;
                }
            });
        } else if (fileTypes.pdf.includes(ext)) {
            Swal.fire({
                title: name,
                html: `
                    ${detailsHtml}
                    <iframe src="${path}" width="100%" height="600px" frameborder="0"></iframe>
                `,
                width: '80%',
                showCloseButton: true,
                showDenyButton: true,
                denyButtonText: 'ดาวน์โหลด',
                showCancelButton: true,
                cancelButtonText: 'ปิด'
            }).then((result) => {
                if (result.isDenied) {
                    window.location.href = path;
                }
            });
        } else if (fileTypes.office.includes(ext)) {
            const googleViewerUrl = `https://docs.google.com/viewer?embedded=true&url=${encodeURIComponent(window.location.origin + '/' + path)}`;
            Swal.fire({
                title: name,
                html: `
                    ${detailsHtml}
                    <iframe src="${googleViewerUrl}" width="100%" height="600px" frameborder="0"></iframe>
                `,
                width: '80%',
                showCloseButton: true,
                showDenyButton: true,
                denyButtonText: 'ดาวน์โหลด',
                showCancelButton: true,
                cancelButtonText: 'ปิด'
            }).then((result) => {
                if (result.isDenied) {
                    window.location.href = path;
                }
            });
        } else {
            Swal.fire({
                title: name,
                html: `
                    ${detailsHtml}
                    <p class="text-muted">ไม่สามารถแสดงตัวอย่างไฟล์นี้ได้</p>
                `,
                width: '80%',
                showCloseButton: true,
                showDenyButton: true,
                denyButtonText: 'ดาวน์โหลด',
                showCancelButton: true,
                cancelButtonText: 'ปิด'
            }).then((result) => {
                if (result.isDenied) {
                    window.location.href = path;
                }
            });
        }
    }

    function saveFile(path, content) {
        fetch('file_management.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `save_file=1&file_path=${encodeURIComponent(path)}&content=${encodeURIComponent(content)}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                Swal.fire({
                    icon: 'success',
                    title: 'บันทึกไฟล์สำเร็จ',
                    toast: true,
                    position: 'top-end',
                    showConfirmButton: false,
                    timer: 3000
                });
            } else {
                Swal.fire({
                    icon: 'error',
                    title: 'เกิดข้อผิดพลาด',
                    text: data.error
                });
            }
        });
    }

    function saveCurrentFile(path) {
        if (window.currentEditor) {
            const content = window.currentEditor.getValue();
            saveFile(path, content);
        }
    }

    function generateShareLink(fileId) {
        Swal.fire({
            title: 'ตั้งค่าการแชร์',
            html: `
                <div class="form-group mb-3">
                    <label class="form-label">รหัสผ่าน (ไม่บังคับ)</label>
                    <input type="password" class="form-control" id="sharePassword" placeholder="ไม่ต้องใส่หากไม่ต้องการตั้งรหัสผ่าน">
                </div>
                <div class="form-group mb-3">
                    <label class="form-label">ระยะเวลาการแชร์</label>
                    <select class="form-control" id="shareExpires">
                        <option value="">ไม่มีกำหนด</option>
                        <option value="5m">5 นาที</option>
                        <option value="10m">10 นาที</option>
                        <option value="1h">1 ชั่วโมง</option>
                        <option value="2h">2 ชั่วโมง</option>
                        <option value="1d">1 วัน</option>
                        <option value="2d">2 วัน</option>
                        <option value="5d">5 วัน</option>
                        <option value="1w">1 สัปดาห์</option>
                    </select>
                </div>
            `,
            showCancelButton: true,
            confirmButtonText: 'สร้างลิงก์',
            cancelButtonText: 'ยกเลิก',
            showLoaderOnConfirm: true,
            preConfirm: () => {
                const password = document.getElementById('sharePassword').value;
                const expires = document.getElementById('shareExpires').value;
                const formData = new FormData();
                formData.append('generate_share', '1');
                formData.append('file_id', fileId);
                formData.append('password', password);
                formData.append('expires', expires);
                
                return fetch('file_management.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(err => {
                            throw new Error(err.error || 'เกิดข้อผิดพลาดในการสร้างลิงก์แชร์');
                        });
                    }
                    return response.json();
                })
                .catch(error => {
                    Swal.showValidationMessage(error.message);
                });
            },
            allowOutsideClick: () => !Swal.isLoading()
        }).then((result) => {
            if (result.isConfirmed && result.value && result.value.success) {
                const longUrl = 'https://nknz.xyz/download.php?token=' + result.value.token;
                const formData = new FormData();
                formData.append('create_short_url', '1');
                formData.append('url', longUrl);
                
                return fetch('file_management.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    const shareUrl = data.short_url; // ใช้ short URL อย่างเดียว
                    Swal.fire({
                        title: 'ลิงก์สำหรับแชร์',
                        html: `
                            <div class="input-group mb-3">
                                <input type="text" class="form-control" value="${shareUrl}" id="shareUrl" readonly>
                                <button class="btn btn-outline-primary" type="button" onclick="copyShareLink()">
                                    <i class="fas fa-copy"></i> คัดลอก
                                </button>
                            </div>
                        `,
                        showCloseButton: true,
                        showConfirmButton: false
                    }).then(() => {
                        window.location.reload();
                    });
                })
                .catch(error => {
                    Swal.fire({
                        icon: 'error',
                        title: 'เกิดข้อผิดพลาด',
                        text: 'ไม่สามารถสร้างลิงก์แชร์ได้'
                    });
                });
            }
        });
    }

    function copyShareLink() {
        const shareUrl = document.getElementById('shareUrl');
        shareUrl.select();
        document.execCommand('copy');
        Swal.fire({
            toast: true,
            position: 'top-end',
            showConfirmButton: false,
            timer: 1500,
            icon: 'success',
            title: 'คัดลอกลิงก์แล้ว'
        });
    }

    function showShareDetails(fileId) {
        fetch('file_management.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'get_share_details=1&file_id=' + fileId
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                let expiresText = '';
                if (data.expires) {
                    if (data.is_expired) {
                        expiresText = `<p class="text-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            ลิ้งค์หมดอายุเมื่อเวลา: ${data.expires} น.
                        </p>`;
                    } else {
                        expiresText = `<p class="text-success">
                            <i class="fas fa-clock me-2"></i>
                            กำลังแชร์ถึงเวลา: ${data.expires} น.
                        </p>`;
                    }
                } else {
                    expiresText = '<p><i class="fas fa-infinity me-2"></i>ไม่มีวันหมดอายุ</p>';
                }
                
                let passwordText = data.has_password ? 
                    '<p><i class="fas fa-lock me-2"></i>มีการป้องกันด้วยรหัสผ่าน</p>' : 
                    '<p><i class="fas fa-lock-open me-2"></i>ไม่มีรหัสผ่าน</p>';
                
                Swal.fire({
                    title: 'รายละเอียดการแชร์',
                    html: `
                        <div class="text-start p-3" style="background: #f8f9fa; border-radius: 10px;">
                            <p><i class="fas fa-link me-2"></i>ลิงก์แชร์:</p>
                            <div class="input-group mb-3">
                                <input type="text" class="form-control" value="${data.share_url}" id="shareUrl" readonly>
                                <button class="btn btn-outline-primary" type="button" onclick="copyShareLink()">
                                    <i class="fas fa-copy"></i> คัดลอก
                                </button>
                            </div>
                            ${expiresText}
                            ${passwordText}
                            <p><i class="fas fa-calendar me-2"></i>สร้างเมื่อ: ${data.created_at} น.</p>
                        </div>
                    `,
                    showDenyButton: true,
                    showCancelButton: true,
                    confirmButtonColor: '#d33',
                    denyButtonColor: '#3085d6',
                    confirmButtonText: 'ยกเลิกการแชร์',
                    denyButtonText: 'สร้างลิงก์ใหม่',
                    cancelButtonText: 'ปิด'
                }).then((result) => {
                    if (result.isConfirmed) {
                        cancelShare(fileId);
                    } else if (result.isDenied) {
                        regenerateShareLink(fileId);
                    }
                });
            }
        });
    }

    function cancelShare(fileId) {
        Swal.fire({
            title: 'ยืนยันการยกเลิกแชร์',
            text: 'ลิงก์แชร์จะไม่สามารถใช้งานได้อีก คุณแน่ใจหรือไม่?',
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'ยืนยัน',
            cancelButtonText: 'ยกเลิก'
        }).then((result) => {
            if (result.isConfirmed) {
                fetch('file_management.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: 'cancel_share=1&file_id=' + fileId
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        Swal.fire({
                            icon: 'success',
                            title: 'ยกเลิกการแชร์แล้ว',
                            showConfirmButton: false,
                            timer: 1500
                        }).then(() => {
                            window.location.reload();
                        });
                    }
                });
            }
        });
    }

    function regenerateShareLink(fileId) {
        Swal.fire({
            title: 'สร้างลิงก์แชร์ใหม่',
            html: `
                <div class="form-group mb-3">
                    <label class="form-label">รหัสผ่าน (ไม่บังคับ)</label>
                    <input type="password" class="form-control" id="sharePassword" placeholder="ไม่ต้องใส่หากไม่ต้องการตั้งรหัสผ่าน">
                </div>
                <div class="form-group mb-3">
                    <label class="form-label">ระยะเวลาการแชร์</label>
                    <select class="form-control" id="shareExpires">
                        <option value="">ไม่มีกำหนด</option>
                        <option value="5m">5 นาที</option>
                        <option value="10m">10 นาที</option>
                        <option value="1h">1 ชั่วโมง</option>
                        <option value="2h">2 ชั่วโมง</option>
                        <option value="1d">1 วัน</option>
                        <option value="2d">2 วัน</option>
                        <option value="5d">5 วัน</option>
                        <option value="1w">1 สัปดาห์</option>
                    </select>
                </div>
            `,
            showCancelButton: true,
            confirmButtonText: 'สร้างลิงก์',
            cancelButtonText: 'ยกเลิก',
            showLoaderOnConfirm: true,
            preConfirm: () => {
                const password = document.getElementById('sharePassword').value;
                const expires = document.getElementById('shareExpires').value;
                
                return fetch('file_management.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `regenerate_share=1&file_id=${fileId}&password=${password}&expires=${expires}`
                })
                .then(response => response.json())
            }
        }).then((result) => {
            if (result.isConfirmed && result.value.success) {
                const longUrl = 'https://nknz.xyz/download.php?token=' + result.value.token;
                const formData = new FormData();
                formData.append('create_short_url', '1'); 
                formData.append('url', longUrl);
                
                fetch('file_management.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    const shareUrl = data.short_url; // ใช้ short URL อย่างเดียว
                    Swal.fire({
                        icon: 'success',
                        title: 'สร้างลิงก์ใหม่สำเร็จ',
                        html: `
                            <div class="input-group mb-3">
                                <input type="text" class="form-control" value="${shareUrl}" id="shareUrl" readonly>
                                <button class="btn btn-outline-primary" type="button" onclick="copyShareLink()">
                                    <i class="fas fa-copy"></i> คัดลอก
                                </button>
                            </div>
                        `,
                        showConfirmButton: false,
                        showCloseButton: true
                    }).then(() => {
                        window.location.reload();
                    });
                });
            }
        });
    }
</script>
</body>
</html>
