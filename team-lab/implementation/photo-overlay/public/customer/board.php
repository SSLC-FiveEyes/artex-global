<?php
declare(strict_types=1);
require_once dirname(__DIR__,2).'/app/views/layout.php';
require_once APP_ROOT.'/app/customer.php';
require_once APP_ROOT.'/app/customer-photos.php';
$id=filter_var($_GET['id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]])?:0;
$filters=ticket_list_filters($_GET);
$base=['q'=>$filters['q'],'status'=>$filters['status'],'page'=>$filters['page']];
$return='/customer/board.php?'.http_build_query($base);
// Public endpoint never selects hidden tickets, including on direct ID access.
$ticket=$id?query('SELECT t.id,t.category,t.title,t.body,t.status,t.reply,t.created_at,t.answered_at,d.name department_name FROM customer_tickets t JOIN departments d ON d.id=t.department_id WHERE t.id=? AND t.is_public=1',[$id])->fetch():null;
if($id && !$ticket) { abort_page(404,'문의가 없습니다','공개 문의 목록에서 다시 확인해 주세요.'); }
page_header('고객의 소리','customer');sub_hero('고객의 소리','공항 이용에 관한 의견과 답변을 살펴보세요.','고객참여');
?>
<link rel="stylesheet" href="/assets/css/customer-voice.css?v=20261029">
<main id="main" class="container content-section">
<nav class="section-links" aria-label="고객 서비스"><a href="/customer/">고객참여 안내</a><a href="/customer/board.php" aria-current="page">고객의 소리 게시판</a><a href="/customer/tickets.php">나의 문의·답변</a><a href="/customer/#faq">자주 묻는 질문</a></nav>
<?php if($ticket): ?>
<article class="notice-detail"><span class="category"><?=e($ticket['category'])?> · 공개글</span><h2><?=e($ticket['title'])?></h2><p class="muted">접수번호 HCS-<?=sprintf('%04d',(int)$ticket['id'])?> · <?=e($ticket['department_name'])?> · <?=e(substr($ticket['created_at'],0,10))?> · <?=e(ticket_status_label($ticket['status']))?></p><div class="article-body"><?=nl2br(e($ticket['body']))?></div><?php render_customer_photo_links((int)$ticket['id']); ?><?php if($ticket['reply']!==null):?><section class="info-box"><h3>담당 부서 답변</h3><p><?=nl2br(e($ticket['reply']))?></p><small><?=e($ticket['answered_at'])?></small></section><?php else:?><section class="info-box"><h3>담당 부서가 확인하고 있습니다</h3><p>답변이 등록되면 이곳에서 확인할 수 있습니다.</p></section><?php endif;?><a class="button button-outline" href="<?=e($return)?>">목록으로</a> <a class="button" href="/customer/tickets.php?new=1">문의 작성</a></article>
<?php else:
$where='is_public=1';$args=[];
if($filters['status']!=='') { $where.=' AND status=?';$args[]=$filters['status']; }
if($filters['q']!=='') {
 $escaped=strtr($filters['q'],['='=>'==','%'=>'=%','_'=>'=_']);
 if(preg_match('/^(?:HCS-)?0*([0-9]+)$/i',$filters['q'],$match)) { $where.=" AND (title LIKE ? ESCAPE '=' OR body LIKE ? ESCAPE '=' OR id=?)";$args[]='%'.$escaped.'%';$args[]='%'.$escaped.'%';$args[]=(int)$match[1]; }
 else { $where.=" AND (title LIKE ? ESCAPE '=' OR body LIKE ? ESCAPE '=')";$args[]='%'.$escaped.'%';$args[]='%'.$escaped.'%'; }
}
$total=(int)query('SELECT COUNT(*) FROM customer_tickets WHERE '.$where,$args)->fetchColumn();
$pages=max(1,(int)ceil($total/10));$page=min($filters['page'],$pages);$offset=($page-1)*10;
$rows=query('SELECT id,category,title,status,created_at FROM customer_tickets WHERE '.$where.' ORDER BY created_at DESC,id DESC LIMIT 10 OFFSET '.$offset,$args)->fetchAll();
$base['page']=$page;
?>
<section class="info-box"><h2>고객의 소리 이용안내</h2><p>공항 이용 중 궁금한 점이나 개선 의견을 남겨 주세요. 일반 회원으로 로그인한 뒤 문의를 작성할 수 있습니다.</p><p>이 게시판에는 작성자가 공개를 선택한 문의와 답변만 표시합니다. 비밀글은 작성자와 담당 부서만 확인하며, <a href="/customer/tickets.php">나의 문의</a>에서 확인할 수 있습니다. 실제 개인정보는 입력하지 마세요.</p></section>
<div class="list-tools"><p>공개 문의 <strong><?=number_format($total)?></strong>건</p><a class="button" href="/customer/tickets.php?new=1">문의 작성 +</a></div>
<form class="search-form" method="get" action="/customer/board.php"><label class="sr-only" for="board-status">처리 상태</label><select id="board-status" name="status"><option value="">전체 상태</option><?php foreach(['RECEIVED','ANSWERED'] as $status):?><option value="<?=$status?>" <?=$filters['status']===$status?'selected':''?>><?=e(ticket_status_label($status))?></option><?php endforeach;?></select><label class="sr-only" for="board-q">제목, 내용 또는 접수번호 검색</label><input id="board-q" name="q" maxlength="100" value="<?=e($filters['q'])?>" placeholder="제목, 내용 또는 접수번호 검색"><button class="button" type="submit">검색</button><a class="button button-outline" href="/customer/board.php">초기화</a></form>
<div class="table-wrap voice-board"><table><caption class="sr-only">공개 고객의 소리 게시판</caption><thead><tr><th scope="col">접수번호</th><th scope="col">분야</th><th scope="col">제목</th><th scope="col">접수일</th><th scope="col">처리 상태</th></tr></thead><tbody><?php foreach($rows as $row):?><tr><td class="nowrap">HCS-<?=sprintf('%04d',(int)$row['id'])?></td><td><?=e($row['category'])?></td><td><a class="table-title" href="<?=e('/customer/board.php?'.http_build_query($base+['id'=>(int)$row['id']]))?>"><?=e($row['title'])?></a></td><td class="nowrap"><?=e(substr($row['created_at'],0,10))?></td><td><span class="badge"><?=e(ticket_status_label($row['status']))?></span></td></tr><?php endforeach;?><?php if(!$rows):?><tr><td colspan="5" class="empty">등록된 공개 문의가 없거나 검색 결과가 없습니다.</td></tr><?php endif;?></tbody></table></div>
<?php if($pages>1):?><nav class="pagination" aria-label="공개 문의 목록 페이지"><?php for($p=max(1,$page-2);$p<=min($pages,$page+2);$p++):?><a href="<?=e('/customer/board.php?'.http_build_query(['q'=>$filters['q'],'status'=>$filters['status'],'page'=>$p]))?>" <?=$p===$page?'aria-current="page" class="selected"':''?>><?=$p?></a><?php endfor;?></nav><?php endif;?>
<?php endif;?></main><?php page_footer(); ?>
