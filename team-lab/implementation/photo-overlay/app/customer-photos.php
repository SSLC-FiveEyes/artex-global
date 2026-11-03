<?php
declare(strict_types=1);

/** Validate a local temporary file. Moving HTTP uploads remains a separate boundary. */
function inspect_customer_photo(array $file): array {
    foreach (['name','tmp_name','error','size'] as $key) {
        if (!isset($file[$key]) || !is_scalar($file[$key])) { throw new DomainException('malformed_upload'); }
    }
    if ((int)$file['error'] !== UPLOAD_ERR_OK) { throw new DomainException('upload_error'); }
    $name=(string)$file['name'];
    if (strlen($name)>200 || preg_match('/[\x00-\x1f\x7f\/\\\\]/',$name)) { throw new DomainException('invalid_filename'); }
    if (preg_match('/(?:^|\.)(?:php[0-9]*|phtml|phar|cgi|pl|js|html?|svg)(?:\.|$)/i',$name)) { throw new DomainException('executable_extension'); }
    $extension=strtolower(pathinfo($name,PATHINFO_EXTENSION));
    if (!in_array($extension,['jpg','jpeg','png'],true)) { throw new DomainException('image_extension_required'); }
    $path=(string)$file['tmp_name'];
    clearstatcache(true,$path);
    $size=is_file($path)?filesize($path):false;
    if ($size===false || $size<1 || $size>2*1024*1024 || (int)$file['size']!==$size) { throw new DomainException('invalid_size'); }
    $content=file_get_contents($path);
    // A conservative policy signal, not a general malware classifier.
    if ($content===false || stripos($content,'<?php')!==false || str_contains($content,'<?=')) { throw new DomainException('script_content'); }
    $mime=(new finfo(FILEINFO_MIME_TYPE))->file($path);
    $image=@getimagesize($path);
    $expected=$extension==='png'?'image/png':'image/jpeg';
    if (!$image || $mime!==$expected || ($image['mime']??null)!==$expected) { throw new DomainException('image_type_mismatch'); }
    if ($image[0]<1 || $image[1]<1 || $image[0]>4096 || $image[1]>4096 || $image[0]*$image[1]>16000000) { throw new DomainException('image_dimensions'); }
    return ['mime'=>$mime,'bytes'=>$size,'sha256'=>hash('sha256',$content),'extension'=>$expected==='image/png'?'png':'jpg'];
}
function customer_photo_directory(): string { return APP_ROOT.'/storage/customer-ticket-files'; }
function customer_photo_can_read(?array $u,array $ticket): bool {
    return !empty($ticket['is_public']) || ($u!==null && ticket_scope($u,$ticket));
}
function render_customer_photo_links(int $ticketId): void {
    $photos=query('SELECT id FROM customer_ticket_files WHERE ticket_id=? ORDER BY id',[$ticketId])->fetchAll();
    if (!$photos) { return; }
    echo '<section class="info-box"><h3>첨부 사진</h3>';
    foreach($photos as $photo) {
        echo '<p><a href="/customer/photo.php?id='.(int)$photo['id'].'" target="_blank" rel="noopener">첨부 사진 보기</a></p>';
    }
    echo '</section>';
}
