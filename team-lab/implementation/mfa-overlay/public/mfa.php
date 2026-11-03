<?php
declare(strict_types=1);
require_once dirname(__DIR__).'/app/views/layout.php';
require_once APP_ROOT.'/app/auth/mfa.php';
start_app_session();
if(!mfa_enabled()) { redirect_to('/login.php'); }
$method=$_SERVER['REQUEST_METHOD']??'GET';
if(!in_array($method,['GET','POST'],true)) { header('Allow: GET, POST'); abort_page(405,'지원하지 않는 요청입니다','로그인 화면에서 다시 시작해 주세요.'); }
$current=user();
if($method==='GET' && $current) { redirect_to(home_for($current)); }
$error='';
if($method==='POST') {
    if(!is_string($_POST['csrf']??null) || !hash_equals(csrf_token(),$_POST['csrf'])) {
        audit('mfa_verify','denied',['reason'=>'csrf_rejected','http_status'=>403]);
        abort_page(403,'요청을 확인할 수 없습니다','추가 인증 화면을 다시 열어 주세요.');
    }
    $pending=$_SESSION['mfa_pending']??null;
    $account=is_array($pending)?query('SELECT u.*,c.contract_status FROM users u LEFT JOIN companies c ON c.id=u.company_id WHERE u.id=? LIMIT 1',[(int)$pending['user_id']])->fetch():false;
    $subjectId=is_array($pending)?(int)$pending['user_id']:null;
    try {
        $secret=$account?mfa_secret_for((int)$account['id']):'';
        $result=mfa_verify_attempt($_SESSION,$account?:null,$_POST['challenge_token']??null,$_POST['otp']??null,$secret,mfa_replay_directory(),time(),session_id());
    } catch(Throwable $ex) {
        // Fail closed on missing enrollment, corrupt replay state or storage failure.
        unset($_SESSION['mfa_pending']);
        audit('mfa_verify','denied',['object_type'=>'user','object_id'=>$subjectId,'reason'=>'configuration_unavailable','http_status'=>503]);
        abort_page(503,'추가 인증을 완료할 수 없습니다','로그인을 다시 시작하거나 관리자에게 문의해 주세요.');
    }
    if($result['ok']) {
        session_regenerate_id(true); $_SESSION['csrf']=bin2hex(random_bytes(24));
        mfa_mark_verified($_SESSION,$account,time()); unset($GLOBALS['app_user']); user();
        audit('mfa_verify','success',['reason'=>'verified','http_status'=>303]);
        audit('login','success',['http_status'=>303]);
        $next=safe_login_return($_SESSION['login_return_to']??null); unset($_SESSION['login_return_to']);
        redirect_to($next??home_for($account));
    }
    http_response_code(403);
    audit('mfa_verify','denied',['object_type'=>'user','object_id'=>$subjectId,'reason'=>$result['reason'],'http_status'=>403]);
    $error='인증을 완료하지 못했습니다. 인증 앱의 현재 코드를 확인하거나 로그인을 다시 시작해 주세요.';
}
$pending=$_SESSION['mfa_pending']??null;
page_header('추가 인증');
?>
<main id="main" class="container content-section"><section class="panel service-form-panel"><h1>추가 인증</h1><p>등록한 인증 앱에서 표시되는 6자리 코드를 입력해 주세요.</p>
<?php if($error):?><div class="form-error" role="alert"><?=e($error)?></div><?php endif;?>
<?php if(is_array($pending) && time()<$pending['expires_at']):?>
<form class="service-form" method="post" action="/mfa.php">
<input type="hidden" name="csrf" value="<?=e(csrf_token())?>"><input type="hidden" name="challenge_token" value="<?=e($pending['token'])?>">
<label for="otp">인증 코드</label><input id="otp" name="otp" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" autocomplete="one-time-code" required>
<button class="button" type="submit">인증 완료</button></form>
<?php else:?><p>진행 중인 인증이 없거나 만료되었습니다. 로그인부터 다시 시작해 주세요.</p><?php endif;?>
<p><a href="/login.php">로그인 다시 시작</a></p></section></main>
<?php page_footer(); ?>
