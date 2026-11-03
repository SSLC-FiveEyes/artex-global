<?php
require_once dirname(__DIR__,2).'/app/views/layout.php';
require_once APP_ROOT.'/app/customer.php';
require_once APP_ROOT.'/app/customer-photos.php';
require_once APP_ROOT.'/app/customer-form.php';
$u=customer_user(); $id=(int)($_GET['id']??0); $ticket=null;
if($id) {
    $ticket=query('SELECT t.*,d.name department_name FROM customer_tickets t JOIN departments d ON d.id=t.department_id WHERE t.id=?',[$id])->fetch();
    if(!$ticket) { abort_page(404,'문의를 찾을 수 없습니다','문의 목록에서 다시 확인해 주세요.'); }
    require_ticket_scope($u,$ticket);
    audit('ticket_view','success',['object_type'=>'ticket','object_id'=>$id,'department_id'=>(int)$ticket['department_id'],'authz_decision'=>'scope_checked','http_status'=>200]);
}
page_header($u['role']==='STAFF'?'고객 문의 처리':'나의 고객의 소리','customer');
sub_hero($u['role']==='STAFF'?'고객 문의 처리':'나의 고객의 소리',$u['role']==='STAFF'?'현재 담당 부서에 접수된 문의를 확인하고 답변합니다.':'접수한 문의와 답변을 확인하세요.','고객참여');
?>
<link rel="stylesheet" href="/assets/css/customer-voice.css?v=20261029">
<main id="main" class="container content-section">
<nav class="section-links" aria-label="고객 서비스"><a href="<?=e(home_for($u))?>"><?=$u['role']==='STAFF'?'직원 업무 현황':'나의 이용내역'?></a><a href="/customer/board.php">고객의 소리 게시판</a><a href="/customer/tickets.php" <?=!$ticket&&!isset($_GET['new'])?'aria-current="page"':''?>><?=$u['role']==='STAFF'?'담당 문의 목록':'나의 문의 목록'?></a><a href="/customer/#faq">자주 묻는 질문</a><?php if($u['role']==='VISITOR'):?><a href="/account/reservations.php">나의 신청 내역</a><?php endif;?></nav>
<?php if($ticket):?>
<article class="notice-detail"><span class="category"><?=e($ticket['category'])?> · <?=$ticket['is_public']?'공개글':'비밀글'?></span><h2><?=e($ticket['title'])?></h2><p class="muted">접수번호 HCS-<?=sprintf('%04d',$id)?> · <?=e($ticket['department_name'])?> · <?=e($ticket['created_at'])?> · <?=e(ticket_status_label($ticket['status']))?></p><?php if($ticket['category']==='공개자료 문의'):?><p class="muted">공개자료 이용 문의로 접수되었으며 법정 정보공개청구가 아닙니다.</p><?php endif;?><div class="article-body"><?=nl2br(e($ticket['body']))?></div><?php render_customer_photo_links((int)$ticket['id']); ?>
<?php if($ticket['reply']!==null):?><section class="info-box"><h3>담당 부서 답변</h3><p><?=nl2br(e($ticket['reply']))?></p><small><?=e($ticket['answered_at'])?></small></section>
<?php elseif($u['role']==='STAFF'):?><form class="service-form" method="post" action="/customer/action.php"><input type="hidden" name="csrf" value="<?=e(csrf_token())?>"><input type="hidden" name="action" value="reply"><input type="hidden" name="id" value="<?=$id?>"><label for="reply">담당 부서 답변</label><?php if($ticket['is_public']):?><p class="muted">이 문의는 공개글입니다. 답변도 누구나 볼 수 있으므로 개인정보를 포함하지 마세요.</p><?php endif;?><textarea id="reply" name="reply" maxlength="5000" rows="6" required></textarea><button class="button">답변 등록</button></form><?php else:?><section class="info-box"><h3>담당 부서가 확인하고 있습니다</h3><p>답변이 등록되면 이 화면에서 확인할 수 있습니다. 추가 설명이 필요하면 새 문의에 접수번호를 적어 주세요.</p></section><?php endif;?>
<a class="button button-outline" href="/customer/tickets.php">문의 목록</a><?php if($u['role']==='VISITOR'):?> <a class="button button-outline" href="/customer/tickets.php?new=1">새 문의 작성</a><?php endif;?></article>
<?php elseif(isset($_GET['new']) && $u['role']==='VISITOR'):
$formValues=$ticketFormState['values']??[];
$requestedCategory=$_GET['category']??'';
if(!isset($ticketFormState['values']) && is_string($requestedCategory) && isset(ticket_categories()[$requestedCategory])) { $formValues['category']=$requestedCategory; }
render_customer_ticket_form($formValues,$ticketFormState['errors']??[]);
else:
$filters=ticket_list_filters($_GET); $listing=scoped_ticket_list($u,$filters); $rows=$listing['rows'];
$baseQuery=['q'=>$filters['q'],'status'=>$filters['status']];
?>
<div class="list-tools"><div><p><?=$u['role']==='STAFF'?'담당 부서':'나의 문의'?> 전체 <strong><?=array_sum($listing['counts'])?></strong>건 · 답변 완료 <strong><?=(int)($listing['counts']['ANSWERED']??0)?></strong>건</p><small>공개·비밀 문의 · 검색 결과 <?=number_format($listing['total'])?>건</small></div><?php if($u['role']==='VISITOR'):?><a class="button" href="?new=1">문의 작성 +</a><?php endif;?></div>
<form class="search-form" method="get"><label class="sr-only" for="ticket-status">처리 상태</label><select id="ticket-status" name="status"><option value="">전체 상태</option><?php foreach(['RECEIVED','ANSWERED'] as $status):?><option value="<?=$status?>" <?=$filters['status']===$status?'selected':''?>><?=e(ticket_status_label($status))?></option><?php endforeach;?></select><label class="sr-only" for="ticket-query">제목 또는 접수번호</label><input id="ticket-query" name="q" maxlength="100" value="<?=e($filters['q'])?>" placeholder="제목 또는 접수번호 HCS-0001"><button class="button" type="submit">검색</button><a class="button button-outline" href="/customer/tickets.php">초기화</a></form>
<div class="table-wrap"><table><caption class="sr-only"><?=$u['role']==='STAFF'?'담당 부서 문의':'본인 문의'?> 목록</caption><thead><tr><th scope="col">접수번호</th><th scope="col">분야</th><th scope="col">제목</th><th scope="col">공개 여부</th><th scope="col">접수일</th><th scope="col">처리 상태</th></tr></thead><tbody><?php foreach($rows as $row):?><tr><td class="nowrap">HCS-<?=sprintf('%04d',$row['id'])?></td><td><?=e($row['category'])?></td><td><a class="table-title" href="?id=<?=$row['id']?>"><?=e($row['title'])?></a></td><td><?=$row['is_public']?'공개':'비밀'?></td><td class="nowrap"><?=e(substr($row['created_at'],0,10))?></td><td><span class="badge"><?=e(ticket_status_label($row['status']))?></span></td></tr><?php endforeach;?><?php if(!$rows):?><tr><td colspan="6" class="empty"><?=$filters['q']!==''||$filters['status']!==''?'조건에 맞는 문의가 없습니다. 검색어·처리 상태를 바꾸거나 초기화해 주세요.':'접수된 문의가 없습니다. 궁금한 점을 문의 작성으로 남겨 주세요.'?></td></tr><?php endif;?></tbody></table></div>
<?php if($listing['pages']>1):?><nav class="pagination" aria-label="문의 목록 페이지"><?php if($listing['page']>1):?><a href="?<?=e(http_build_query($baseQuery+['page'=>$listing['page']-1]))?>" aria-label="이전 페이지">이전</a><?php endif;?><?php for($p=max(1,$listing['page']-2);$p<=min($listing['pages'],$listing['page']+2);$p++):?><a href="?<?=e(http_build_query($baseQuery+['page'=>$p]))?>" <?=$p===$listing['page']?'aria-current="page" class="selected"':''?>><?=$p?></a><?php endfor;?><?php if($listing['page']<$listing['pages']):?><a href="?<?=e(http_build_query($baseQuery+['page'=>$listing['page']+1]))?>" aria-label="다음 페이지">다음</a><?php endif;?></nav><p class="muted"><?=$listing['page']?> / <?=$listing['pages']?> 페이지 · 한 페이지 10건</p><?php endif;?>
<?php endif;?></main><?php page_footer(); ?>
