<?php
declare(strict_types=1);
require_once dirname(__DIR__).'/app/customer-photos.php';
require_once dirname(__DIR__).'/app/customer.php';
$checks=0;
function photo_check(bool $condition,string $label): void {
    global $checks;
    if (!$condition) { throw new RuntimeException($label); }
    $checks++;
}
function denied_photo(array $file,string $reason): void {
    try { inspect_customer_photo($file); } catch (DomainException $ex) { photo_check($ex->getMessage()===$reason,$reason); return; }
    throw new RuntimeException('Expected rejection: '.$reason);
}
$tmp=tempnam(sys_get_temp_dir(),'photo-test-');
try {
    $png=base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a1ioAAAAASUVORK5CYII=');
    file_put_contents($tmp,$png);
    $file=['name'=>'normal.png','tmp_name'=>$tmp,'error'=>UPLOAD_ERR_OK,'size'=>strlen($png)];
    $info=inspect_customer_photo($file);
    photo_check($info['mime']==='image/png' && $info['bytes']===strlen($png),'PNG inspection');
    denied_photo(array_replace($file,['name'=>'photo.php.png']),'executable_extension');
    denied_photo(array_replace($file,['name'=>'photo.PHTML.jpg']),'executable_extension');
    denied_photo(array_replace($file,['name'=>'photo.svg']),'executable_extension');
    denied_photo(array_replace($file,['name'=>'photo.js']),'executable_extension');
    denied_photo(array_replace($file,['name'=>"photo\0.png"]),'invalid_filename');
    denied_photo(array_replace($file,['name'=>'../photo.png']),'invalid_filename');
    denied_photo(array_replace($file,['name'=>['photo.png']]),'malformed_upload');
    denied_photo(array_replace($file,['error'=>UPLOAD_ERR_PARTIAL]),'upload_error');
    denied_photo(array_replace($file,['name'=>'photo.jpg']),'image_type_mismatch');
    file_put_contents($tmp,'plain text');
    denied_photo(array_replace($file,['size'=>10]),'image_type_mismatch');
    // Inert bytes in a temporary file: never evaluated or served.
    file_put_contents($tmp,$png.'<?php /* inert fixture */ ?>');
    denied_photo(array_replace($file,['size'=>filesize($tmp)]),'script_content');
    file_put_contents($tmp,str_repeat('x',2*1024*1024+1)); clearstatcache(true,$tmp);
    denied_photo(array_replace($file,['size'=>filesize($tmp)]),'invalid_size');
    foreach (['haneul-careers-v1.png','haneul-haru-v1.png','haneul-leadership-v1.png'] as $imageName) {
        $path=dirname(__DIR__).'/public/assets/images/'.$imageName;
        $photo=inspect_customer_photo(['name'=>$imageName,'tmp_name'=>$path,'error'=>UPLOAD_ERR_OK,'size'=>filesize($path)]);
        photo_check($photo['mime']==='image/png','Existing valid photo with ordinary compressed bytes: '.$imageName);
    }
    $ticket=['user_id'=>11,'department_id'=>2,'is_public'=>0];
    photo_check(!customer_photo_can_read(null,$ticket),'Private photo anonymous denied');
    photo_check(customer_photo_can_read(['role'=>'VISITOR','id'=>11],$ticket),'Private photo owner allowed');
    photo_check(!customer_photo_can_read(['role'=>'VISITOR','id'=>12],$ticket),'Other visitor denied');
    photo_check(customer_photo_can_read(['role'=>'STAFF','department_id'=>2],$ticket),'Department allowed');
    photo_check(!customer_photo_can_read(['role'=>'STAFF','department_id'=>1],$ticket),'Other department denied');
    photo_check(customer_photo_can_read(null,array_replace($ticket,['is_public'=>1])),'Public photo follows public ticket');
} finally { unlink($tmp); }
echo json_encode(['result'=>'passed','checks'=>$checks,'network_access'=>false,'database_access'=>false]).PHP_EOL;
