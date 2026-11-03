<?php
require_once dirname(__DIR__,2).'/app/customer.php';
if($_SERVER['REQUEST_METHOD']!=='POST') { header('Allow: POST'); abort_page(405,'지원하지 않는 요청입니다','문의 화면에서 등록해 주세요.'); }
require_once APP_ROOT.'/app/customer-photos.php';
$u=customer_user(); check_csrf(); $action=(string)($_POST['action']??'');
if($action==='create' && $u['role']==='VISITOR') {
    $photo=null; $storedPath=null;
    if (isset($_FILES['photo']) && (!is_array($_FILES['photo']) || ($_FILES['photo']['error']??null)!==UPLOAD_ERR_NO_FILE)) {
        try {
            if (!is_array($_FILES['photo'])) { throw new DomainException('malformed_upload'); }
            $photo=inspect_customer_photo($_FILES['photo']);
            if (!is_uploaded_file((string)$_FILES['photo']['tmp_name'])) { throw new DomainException('invalid_upload_source'); }
        } catch (DomainException $ex) {
            audit('ticket_photo_upload','denied',['reason'=>$ex->getMessage(),'http_status'=>422]);
            abort_page(422,'사진을 첨부할 수 없습니다','2MB 이하 JPEG 또는 PNG 사진을 선택해 주세요.');
        }
    }
    $values=ticket_form_values($_POST); $errors=ticket_form_errors($values);
    if($errors) {
        http_response_code(422);
        $ticketFormState=['values'=>$values,'errors'=>$errors];
        $_GET=['new'=>'1'];
        require APP_ROOT.'/public/customer/tickets.php'; exit;
    }
    ['category'=>$category,'title'=>$title,'body'=>$body]=$values;
    $department=ticket_categories()[$category]??null;
    $pdo=db(); $pdo->beginTransaction();
    try {
        query('INSERT INTO customer_tickets(user_id,department_id,category,title,body,is_public) VALUES(?,?,?,?,?,?)',[$u['id'],$department,$category,$title,$body,$values['visibility']==='public'?1:0]);
        $id=(int)$pdo->lastInsertId();
        if ($photo!==null) {
            $dir=customer_photo_directory();
            if (!is_dir($dir) && !mkdir($dir,0770,true) && !is_dir($dir)) { throw new RuntimeException('Cannot create photo storage'); }
            $name=bin2hex(random_bytes(24)).'.'.$photo['extension']; $storedPath=$dir.'/'.$name;
            if (!move_uploaded_file((string)$_FILES['photo']['tmp_name'],$storedPath)) { throw new RuntimeException('Cannot store photo'); }
            chmod($storedPath,0640);
            query('INSERT INTO customer_ticket_files(ticket_id,stored_filename,mime,bytes,sha256) VALUES(?,?,?,?,?)',[$id,$name,$photo['mime'],$photo['bytes'],$photo['sha256']]);
        }
        $pdo->commit();
    } catch (Throwable $ex) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        if ($storedPath!==null && is_file($storedPath)) { unlink($storedPath); }
        audit('ticket_create','failure',['reason'=>'storage_failure','http_status'=>500]);
        throw $ex;
    }
    if ($photo!==null) { audit('ticket_photo_upload','success',['object_type'=>'ticket','object_id'=>$id,'bytes'=>$photo['bytes'],'http_status'=>303]); }
    audit('ticket_create','success',['object_type'=>'ticket','object_id'=>$id,'department_id'=>$department,'to_status'=>'RECEIVED','http_status'=>303]);
    redirect_to('/customer/tickets.php?id='.$id,'문의가 접수되었습니다.');
}
if($action==='reply' && $u['role']==='STAFF') {
    $id=(int)($_POST['id']??0); $ticket=query('SELECT * FROM customer_tickets WHERE id=?',[$id])->fetch();
    if(!$ticket) { abort_page(404,'문의를 찾을 수 없습니다','문의 목록을 확인해 주세요.'); }
    require_ticket_scope($u,$ticket); $reply=limited_text($_POST['reply']??'',5000);
    if($reply==='') { abort_page(422,'답변을 작성해 주세요','빈 답변은 등록할 수 없습니다.'); }
    $changed=query("UPDATE customer_tickets SET reply=?,answered_by=?,answered_at=NOW(),status='ANSWERED' WHERE id=? AND department_id=? AND status='RECEIVED'",[$reply,$u['id'],$id,$u['department_id']])->rowCount();
    if(!$changed) { abort_page(409,'이미 처리된 문의입니다','현재 답변 상태를 확인해 주세요.'); }
    audit('ticket_reply','success',['object_type'=>'ticket','object_id'=>$id,'department_id'=>(int)$ticket['department_id'],'from_status'=>'RECEIVED','to_status'=>'ANSWERED','http_status'=>303]);
    redirect_to('/customer/tickets.php?id='.$id,'답변을 등록했습니다.');
}
audit('ticket_action','denied',['reason'=>'role_or_action','http_status'=>403]);
abort_page(403,'처리 권한이 없습니다','현재 계정에서 허용된 문의 기능을 이용해 주세요.');
