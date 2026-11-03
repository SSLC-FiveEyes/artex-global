<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli') { exit(1); }
require_once dirname(__DIR__).'/app/auth/mfa.php';
$checks=0;
function check_mfa(bool $condition,string $label): void { global $checks; if(!$condition) { throw new RuntimeException($label); } $checks++; }
function reject_mfa(callable $action,string $label): void { try { $action(); } catch(Throwable $ex) { check_mfa(true,$label); return; } check_mfa(false,$label); }
// Public RFC 6238 SHA-1 test fixture, not an enrollment credential.
$secret='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
foreach([59=>'94287082',1111111109=>'07081804',1111111111=>'14050471',1234567890=>'89005924',2000000000=>'69279037',20000000000=>'65353130'] as $time=>$expected) {
    check_mfa(mfa_totp($secret,intdiv($time,30),8)===$expected,'RFC 6238 SHA-1 vector');
}
reject_mfa(fn()=>mfa_decode_base32('not-a-secret'),'Invalid base32 fails closed');
reject_mfa(fn()=>mfa_decode_base32('AAAA'),'Short secret fails closed');
putenv('AIRPORT_MFA_ENABLED=0'); check_mfa(!mfa_enabled(),'MFA default-off configuration');
putenv('AIRPORT_MFA_ENABLED=1'); check_mfa(mfa_enabled(),'MFA opt-in configuration');
putenv('AIRPORT_MFA_ENABLED=unexpected'); reject_mfa(fn()=>mfa_enabled(),'Unknown mode fails closed');
putenv('AIRPORT_MFA_ENABLED=0');
$now=1700000000; $account=['id'=>71,'password_hash'=>'test-credential-hash','account_status'=>'ACTIVE','role'=>'VISITOR'];
$passwordSession=['mfa_pending'=>['previous'=>'challenge'],'mfa_verified'=>['old'=>'proof']];
mfa_password_only_session($passwordSession,$account);
check_mfa(isset($passwordSession['user_id'],$passwordSession['credential_stamp']) && !isset($passwordSession['mfa_pending']) && !isset($passwordSession['mfa_verified']),'Returning to password-only mode clears pending challenge');
putenv('AIRPORT_MFA_ENABLED=1');
reject_mfa(function() use (&$passwordSession,$account) { mfa_password_only_session($passwordSession,$account); },'Password-only helper cannot authenticate in MFA mode');
putenv('AIRPORT_MFA_ENABLED=0');
$directory=sys_get_temp_dir().'/hac-mfa-test-'.bin2hex(random_bytes(8));
try {
    $session=['user_id'=>71,'credential_stamp'=>'old','mfa_verified'=>[]];
    $token=mfa_begin($session,$account,$now,'session-a');
    check_mfa(!isset($session['user_id'],$session['credential_stamp'],$session['mfa_verified']),'Password success does not create authenticated session');
    check_mfa(strlen($token)===64 && isset($session['mfa_pending']),'Challenge created');
    check_mfa(!mfa_session_verified($session,$account,$now),'Pending challenge cannot satisfy completed MFA');
    $otp=mfa_totp($secret,intdiv($now,30));
    $result=mfa_verify_attempt($session,$account,$token,$otp,$secret,$directory,$now,'session-a');
    check_mfa($result===['ok'=>true,'reason'=>'verified'] && !isset($session['mfa_pending']),'Valid bound challenge consumed');
    check_mfa(!isset($session['user_id']),'Verification result alone does not silently log in');
    mfa_mark_verified($session,$account,$now);
    check_mfa(mfa_session_verified($session,$account,$now),'Completion proof accepted');
    check_mfa(!mfa_session_verified($session,$account,$now+43200),'Completion proof expires');
    check_mfa(!mfa_session_verified($session,$account,$now-1),'Future completion proof rejected');
    check_mfa(mfa_verify_attempt($session,$account,$token,$otp,$secret,$directory,$now,'session-a')['reason']==='invalid_or_used','Consumed challenge rejected');
    $other=[]; $otherToken=mfa_begin($other,$account,$now,'session-b');
    check_mfa(mfa_verify_attempt($other,$account,$otherToken,$otp,strtolower($secret),$directory,$now,'session-b')['reason']==='otp_reused','Same TOTP denied across sessions and Base32 case changes');
    $malformed=['mfa_pending'=>['user_id'=>['bad']]];
    check_mfa(mfa_verify_attempt($malformed,$account,null,null,$secret,$directory,$now,'session-a')['reason']==='invalid_or_used' && !isset($malformed['mfa_pending']),'Malformed pending session rejected without warning');
    $conflicting=$session; $conflicting['mfa_pending']=['unexpected'=>true];
    check_mfa(!mfa_session_verified($conflicting,$account,$now),'Pending session cannot reuse completed proof');
    $missingUser=$session; unset($missingUser['user_id']);
    check_mfa(!mfa_session_verified($missingUser,$account,$now),'Completed proof requires matching authenticated user');
    $other=[]; $otherToken=mfa_begin($other,$account,$now,'session-b');
    check_mfa(mfa_verify_attempt($other,$account,$otherToken,$otp,$secret,$directory,$now,'session-c')['reason']==='session_mismatch','Session binding enforced');
    $other=[]; $otherToken=mfa_begin($other,$account,$now,'session-b');
    check_mfa(mfa_verify_attempt($other,$account,$otherToken,$otp,$secret,$directory,$now+300,'session-b')['reason']==='expired','TTL enforced');
    $other=[]; $otherToken=mfa_begin($other,$account,$now,'session-b');
    $changed=$account; $changed['password_hash']='changed';
    check_mfa(mfa_verify_attempt($other,$changed,$otherToken,$otp,$secret,$directory,$now,'session-b')['reason']==='account_changed','Credential change invalidates pending challenge');
    check_mfa(!mfa_session_verified($session,$changed,$now),'Credential change invalidates completion proof');
    $other=[]; $otherToken=mfa_begin($other,$account,$now,'session-b');
    $disabled=$account; $disabled['account_status']='DISABLED';
    check_mfa(mfa_verify_attempt($other,$disabled,$otherToken,$otp,$secret,$directory,$now,'session-b')['reason']==='account_changed','Disabled account rejected');
    $other=[]; $otherToken=mfa_begin($other,$account,$now,'session-b');
    check_mfa(mfa_verify_attempt($other,$account,null,$otp,$secret,$directory,$now,'session-b')['reason']==='invalid_or_used','Missing token rejected');
    check_mfa(mfa_verify_attempt($other,$account,[$otherToken],$otp,$secret,$directory,$now,'session-b')['reason']==='invalid_or_used','Array token rejected safely');
    check_mfa(mfa_verify_attempt($other,$account,$token,$otp,$secret,$directory,$now,'session-b')['reason']==='invalid_or_used','Other challenge token rejected');
    check_mfa(mfa_verify_attempt($other,$account,$otherToken,['123456'],$secret,$directory,$now,'session-b')['reason']==='invalid_otp','Array OTP rejected safely');
    check_mfa(mfa_verify_attempt($other,$account,$otherToken,'invalid',$secret,$directory,$now,'session-b')['reason']==='invalid_otp','Malformed OTP rejected');
    check_mfa(mfa_verify_attempt($other,$account,$otherToken,$otp,$secret,$directory,$now,'session-b')['reason']==='attempt_limit','Attempt limit enforced');
    $broken=$directory.'/'.hash('sha256',$account['id'].':'.$secret).'.json';
    file_put_contents($broken,'broken');
    reject_mfa(fn()=>mfa_claim_step($account['id'],$secret,intdiv($now,30)+1,$directory),'Corrupt replay state fails closed');
} finally {
    foreach(glob($directory.'/*')?:[] as $path) { unlink($path); }
    if(is_dir($directory)) { rmdir($directory); }
}
echo json_encode(['result'=>'passed','checks'=>$checks,'database_access'=>false,'http_requests'=>0],JSON_UNESCAPED_UNICODE).PHP_EOL;
