<?php
require_once dirname(__DIR__).'/app/views/layout.php';
require_once APP_ROOT.'/app/auth/mfa.php';
start_app_session();
$current=user();
if (isset($_GET['next']) && ($next=safe_login_return($_GET['next']))) { $_SESSION['login_return_to']=$next; }
if($current) { $next=safe_login_return($_SESSION['login_return_to']??null); unset($_SESSION['login_return_to']); redirect_to($next??home_for($current)); }
$error='';
if($_SERVER['REQUEST_METHOD']==='POST') {
    check_csrf();
    $username=limited_text($_POST['username']??'',50); $password=(string)($_POST['password']??'');
    $stmt=query('SELECT u.*,c.contract_status FROM users u LEFT JOIN companies c ON c.id=u.company_id WHERE u.username=? LIMIT 1',[$username]); $u=$stmt->fetch();
    $allowed=$u && $u['account_status']!=='DISABLED' && ($u['role']!=='CONTRACTOR'||$u['contract_status']==='ACTIVE');
    if($allowed && password_verify($password,$u['password_hash'])) {
        if(mfa_enabled()) {
            try { mfa_secret_for((int)$u['id']); }
            catch(Throwable $ex) {
                audit('mfa_challenge','denied',['object_type'=>'user','object_id'=>(int)$u['id'],'reason'=>'configuration_unavailable','http_status'=>503]);
                abort_page(503,'추가 인증을 시작할 수 없습니다','잠시 후 다시 시도하거나 관리자에게 문의해 주세요.');
            }
            session_regenerate_id(true); $_SESSION['csrf']=bin2hex(random_bytes(24));
            mfa_begin($_SESSION,$u,time(),session_id()); unset($GLOBALS['app_user']);
            audit('mfa_challenge','issued',['object_type'=>'user','object_id'=>(int)$u['id'],'reason'=>'password_verified','http_status'=>303]);
            redirect_to('/mfa.php');
        }
        session_regenerate_id(true); mfa_password_only_session($_SESSION,$u); unset($GLOBALS['app_user']); user();
        $next=safe_login_return($_SESSION['login_return_to']??null); unset($_SESSION['login_return_to']);
        audit('login','success',['http_status'=>303]); redirect_to($next??home_for($u));
    }
    audit('login','failure',['username'=>$username,'reason'=>'invalid_credentials_or_account_state','http_status'=>401]);
    http_response_code(401); $error='아이디 또는 비밀번호를 확인해 주세요.';
}
page_header('통합 로그인');
?>
<main id="main" class="login-section container"><section class="login-intro"><span class="eyebrow">WELCOME TO HANEUL</span><h1>여행과 일상,<br>하나로 이어지는 하늘.</h1><p>일반 이용자·협력업체·공사 담당자를 위한<br>나에게 맞는 서비스를 시작하세요.</p><div class="login-benefit"><?=icon('file',28)?><div><strong>문의부터 업무까지 한 곳에서</strong><p>고객 문의 · 작업 보고 · 처리 결과 확인</p></div></div><div class="login-benefit"><?=icon('shield',28)?><div><strong>소속에 맞는 안전한 업무공간</strong><p>이용자·업체·담당 부서별 정보 보호</p></div></div><a class="inline-link" href="/section.php?id=guide">처음 이용하시나요? 이용안내 <?=icon('arrow',18)?></a></section><section class="login-card"><div class="login-card-title"><?=icon('user',30)?><h2>통합 로그인</h2><p>일반 회원 또는 발급받은 업무 계정으로 로그인해 주세요.</p></div><?php if($error):?><div class="form-error" role="alert"><?=e($error)?></div><?php endif;?><form method="post"><input type="hidden" name="csrf" value="<?=e(csrf_token())?>"><label for="username">아이디</label><input id="username" name="username" maxlength="50" placeholder="아이디를 입력해 주세요" autocomplete="username" required value="<?=e($_POST['username']??'')?>"><label for="password">비밀번호</label><input id="password" type="password" name="password" placeholder="비밀번호를 입력해 주세요" autocomplete="current-password" required><button class="button full-width" type="submit">로그인 <?=icon('arrow',19)?></button></form><p><a class="inline-link" href="/recover.php">비밀번호를 잊으셨나요?</a></p><section class="signup-invitation" aria-labelledby="signup-invitation-title"><h3 id="signup-invitation-title">처음 이용하시나요?</h3><p>일반 회원으로 가입하고 신청 내역과 고객 문의를 이용하세요.</p><a class="button button-outline full-width" href="/register.php">일반 이용자 회원가입 <?=icon('arrow',18)?></a></section><div class="login-help"><strong>업무 계정 안내</strong><p>일반 이용자는 문의·신청 내역으로, 직원·협력업체는 소속 업무공간으로 이동합니다.</p><p>회원가입은 일반 이용자 전용입니다. 직원·협력업체의 업무 계정은 별도로 발급받아 사용해 주세요.</p></div></section></main><?php page_footer(); ?>
