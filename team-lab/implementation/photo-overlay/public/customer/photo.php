<?php
declare(strict_types=1);
require_once dirname(__DIR__,2).'/app/customer.php';
require_once APP_ROOT.'/app/customer-photos.php';
$id=filter_var($_GET['id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
$file=$id?query('SELECT f.*,t.user_id,t.department_id,t.is_public FROM customer_ticket_files f JOIN customer_tickets t ON t.id=f.ticket_id WHERE f.id=?',[$id])->fetch():false;
if (!$file || !customer_photo_can_read(user(),$file)) {
    audit('ticket_photo_read','denied',['reason'=>'not_found_or_outside_scope','http_status'=>404]);
    abort_page(404,'사진을 찾을 수 없습니다','문의의 공개 여부와 접근 권한을 확인해 주세요.');
}
if (!preg_match('/^[a-f0-9]{48}\.(?:png|jpg)$/D',$file['stored_filename']) || !in_array($file['mime'],['image/png','image/jpeg'],true)) {
    throw new RuntimeException('Invalid photo metadata');
}
$path=customer_photo_directory().'/'.$file['stored_filename'];
if (!is_file($path) || is_link($path) || filesize($path)!==(int)$file['bytes'] || !hash_equals($file['sha256'],hash_file('sha256',$path))) {
    abort_page(404,'사진을 찾을 수 없습니다','첨부 사진의 상태를 확인해 주세요.');
}
audit('ticket_photo_read','success',['object_type'=>'ticket','object_id'=>(int)$file['ticket_id'],'bytes'=>(int)$file['bytes'],'http_status'=>200]);
header('Content-Type: '.$file['mime']);
header('Content-Disposition: inline; filename="photo.'.($file['mime']==='image/png'?'png':'jpg').'"');
header('Content-Length: '.(int)$file['bytes']);
header('X-Content-Type-Options: nosniff');
readfile($path);
