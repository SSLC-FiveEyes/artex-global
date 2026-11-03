<?php
declare(strict_types=1);

// Secrets and OTPs must never be passed to audit(), exception text or response headers.
function mfa_enabled(): bool {
    $value=strtolower(trim((string)(getenv('AIRPORT_MFA_ENABLED') ?: '0')));
    if(in_array($value,['0','false','off'],true)) { return false; }
    if(in_array($value,['1','true','on'],true)) { return true; }
    throw new RuntimeException('Invalid MFA configuration');
}
function mfa_decode_base32(string $encoded): string {
    $encoded=strtoupper($encoded);
    if(!preg_match('/^[A-Z2-7]+$/D',$encoded)) { throw new InvalidArgumentException('Invalid MFA secret format'); }
    $buffer=0; $bits=0; $decoded='';
    foreach(str_split($encoded) as $char) {
        $buffer=($buffer<<5)|strpos('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',$char); $bits+=5;
        if($bits>=8) { $bits-=8; $decoded.=chr(($buffer>>$bits)&255); $buffer&=(1<<$bits)-1; }
    }
    if($bits && $buffer!==0) { throw new InvalidArgumentException('Invalid MFA secret padding'); }
    if(strlen($decoded)<16) { throw new InvalidArgumentException('MFA secret too short'); }
    return $decoded;
}
function mfa_totp(string $base32, int $step, int $digits=6): string {
    if($step<0 || !in_array($digits,[6,8],true)) { throw new InvalidArgumentException('Invalid TOTP parameters'); }
    $counter=pack('N2',intdiv($step,4294967296),$step%4294967296);
    $digest=hash_hmac('sha1',$counter,mfa_decode_base32($base32),true);
    $offset=ord($digest[19])&15;
    $value=unpack('N',substr($digest,$offset,4))[1]&0x7fffffff;
    return str_pad((string)($value%(10**$digits)),$digits,'0',STR_PAD_LEFT);
}
function mfa_secret_for(int $userId): string {
    $path=getenv('AIRPORT_MFA_SECRET_FILE');
    $real=is_string($path)&&$path!==''?realpath($path):false;
    $public=realpath(dirname(__DIR__,2).'/public');
    if(!$real || !is_file($real) || !is_readable($real) || ($public && ($real===$public || str_starts_with($real,$public.DIRECTORY_SEPARATOR)))) {
        throw new RuntimeException('MFA secret file unavailable');
    }
    $size=filesize($real);
    if($size===false || $size>1024*1024) { throw new RuntimeException('MFA secret file unavailable'); }
    $raw=file_get_contents($real);
    try { $secrets=json_decode($raw===false?'':$raw,true,32,JSON_THROW_ON_ERROR); }
    catch(Throwable $ex) { throw new RuntimeException('Invalid MFA secret configuration'); }
    $secret=is_array($secrets)?($secrets[(string)$userId]??null):null;
    if(!is_string($secret)) { throw new RuntimeException('MFA account enrollment required'); }
    mfa_decode_base32($secret);
    return $secret;
}
function mfa_replay_directory(): string {
    return dirname(__DIR__,2).'/storage/mfa-replay';
}
/** Atomically accept a time step once per account+secret across PHP sessions/workers. */
function mfa_claim_step(int $userId,string $secret,int $step,string $directory): bool {
    if(!is_dir($directory) && !mkdir($directory,0700,true) && !is_dir($directory)) { throw new RuntimeException('MFA replay store unavailable'); }
    $real=realpath($directory); $public=realpath(dirname(__DIR__,2).'/public');
    if(!$real || ($public && ($real===$public || str_starts_with($real,$public.DIRECTORY_SEPARATOR)))) { throw new RuntimeException('Invalid MFA replay store'); }
    // Base32 case changes must not create a fresh replay namespace.
    mfa_decode_base32($secret);
    $path=$real.'/'.hash('sha256',$userId.':'.strtoupper($secret)).'.json';
    if(is_link($path)) { throw new RuntimeException('Invalid MFA replay record'); }
    $lockPath=$path.'.lock';
    if(is_link($lockPath)) { throw new RuntimeException('Invalid MFA replay lock'); }
    $handle=fopen($lockPath,'c+');
    if(!$handle) { throw new RuntimeException('MFA replay store unavailable'); }
    $temporary=null;
    try {
        if(!chmod($lockPath,0600) || !flock($handle,LOCK_EX)) { throw new RuntimeException('MFA replay lock unavailable'); }
        $previous=-1;
        if(file_exists($path)) {
            $raw=file_get_contents($path);
            if($raw===false || $raw==='') { throw new RuntimeException('Invalid MFA replay record'); }
            try { $record=json_decode($raw,true,8,JSON_THROW_ON_ERROR); }
            catch(Throwable $ex) { throw new RuntimeException('Invalid MFA replay record'); }
            if(!is_array($record) || !isset($record['step']) || !is_int($record['step']) || $record['step']<0) { throw new RuntimeException('Invalid MFA replay record'); }
            $previous=$record['step'];
        }
        if($step<=$previous) { return false; }
        $value=json_encode(['step'=>$step],JSON_THROW_ON_ERROR);
        $temporary=tempnam($real,'.mfa-');
        if(!$temporary || !chmod($temporary,0600) || file_put_contents($temporary,$value)!==strlen($value) || !rename($temporary,$path)) { throw new RuntimeException('MFA replay write failed'); }
        $temporary=null;
        return true;
    } finally {
        if($temporary!==null && is_file($temporary)) { unlink($temporary); }
        flock($handle,LOCK_UN); fclose($handle);
    }
}
function mfa_account_allowed(?array $account): bool {
    return $account && ($account['account_status']??'DISABLED')!=='DISABLED' && (($account['role']??'')!=='CONTRACTOR' || ($account['contract_status']??'')==='ACTIVE');
}
/** Clear pending MFA when an operator deliberately returns to password-only mode. */
function mfa_password_only_session(array &$session,array $account): void {
    if(mfa_enabled()) { throw new RuntimeException('Password-only authentication is disabled'); }
    if(!mfa_account_allowed($account)) { throw new RuntimeException('Account is not available'); }
    unset($session['mfa_pending'],$session['mfa_verified']);
    $session['user_id']=(int)$account['id'];
    $session['credential_stamp']=hash('sha256',$account['password_hash']);
}
function mfa_pending_valid(mixed $pending): bool {
    return is_array($pending) && is_int($pending['user_id']??null) && $pending['user_id']>0
        && is_string($pending['credential_stamp']??null) && (bool)preg_match('/^[a-f0-9]{64}$/D',$pending['credential_stamp'])
        && is_string($pending['token']??null) && (bool)preg_match('/^[a-f0-9]{64}$/D',$pending['token'])
        && is_string($pending['session_binding']??null) && (bool)preg_match('/^[a-f0-9]{64}$/D',$pending['session_binding'])
        && is_int($pending['issued_at']??null) && is_int($pending['expires_at']??null)
        && $pending['expires_at']>$pending['issued_at'] && $pending['expires_at']-$pending['issued_at']<=300
        && is_int($pending['attempts']??null) && $pending['attempts']>=0 && $pending['attempts']<=5;
}
function mfa_begin(array &$session,array $account,int $now,string $sessionId): string {
    unset($session['user_id'],$session['credential_stamp'],$session['mfa_verified']);
    $token=bin2hex(random_bytes(32));
    $session['mfa_pending']=['user_id'=>(int)$account['id'],'credential_stamp'=>hash('sha256',$account['password_hash']),'token'=>$token,'session_binding'=>hash('sha256',$sessionId),'issued_at'=>$now,'expires_at'=>$now+300,'attempts'=>0];
    return $token;
}
/** Fixed reason values are safe for audit; no submitted values are returned. */
function mfa_verify_attempt(array &$session,?array $account,mixed $token,mixed $otp,string $secret,string $replayDirectory,int $now,string $sessionId): array {
    $pending=$session['mfa_pending']??null;
    if(!mfa_pending_valid($pending)) { unset($session['mfa_pending']); return ['ok'=>false,'reason'=>'invalid_or_used']; }
    if($now<($pending['issued_at']??PHP_INT_MAX) || $now>=($pending['expires_at']??0)) { unset($session['mfa_pending']); return ['ok'=>false,'reason'=>'expired']; }
    if(!hash_equals($pending['session_binding']??'',hash('sha256',$sessionId))) { unset($session['mfa_pending']); return ['ok'=>false,'reason'=>'session_mismatch']; }
    if(!mfa_account_allowed($account) || (int)$account['id']!==(int)$pending['user_id'] || !hash_equals($pending['credential_stamp'],hash('sha256',$account['password_hash']))) { unset($session['mfa_pending']); return ['ok'=>false,'reason'=>'account_changed']; }
    if(($pending['attempts']??0)>=5) { unset($session['mfa_pending']); return ['ok'=>false,'reason'=>'attempt_limit']; }
    $session['mfa_pending']['attempts']++;
    if(!is_string($token) || !hash_equals($pending['token'],$token)) { return ['ok'=>false,'reason'=>'invalid_or_used']; }
    if(!is_string($otp) || !preg_match('/^[0-9]{6}$/D',$otp)) { return ['ok'=>false,'reason'=>'invalid_otp']; }
    $step=intdiv($now,30); $matched=null;
    foreach([$step,$step-1,$step+1] as $candidate) {
        if($candidate>=0 && hash_equals(mfa_totp($secret,$candidate),$otp)) { $matched=$candidate; break; }
    }
    if($matched===null) { return ['ok'=>false,'reason'=>'invalid_otp']; }
    if(!mfa_claim_step((int)$account['id'],$secret,$matched,$replayDirectory)) { return ['ok'=>false,'reason'=>'otp_reused']; }
    unset($session['mfa_pending']);
    return ['ok'=>true,'reason'=>'verified'];
}
function mfa_mark_verified(array &$session,array $account,int $now): void {
    $session['user_id']=(int)$account['id'];
    $session['credential_stamp']=hash('sha256',$account['password_hash']);
    $session['mfa_verified']=['user_id'=>(int)$account['id'],'credential_stamp'=>$session['credential_stamp'],'verified_at'=>$now,'method'=>'totp'];
}
/** Called from user() before treating an old password-only session as authenticated. */
function mfa_session_verified(array $session,array $account,int $now): bool {
    $proof=$session['mfa_verified']??null;
    return !isset($session['mfa_pending']) && (int)($session['user_id']??0)===(int)$account['id']
        && mfa_account_allowed($account) && is_array($proof) && ($proof['method']??'')==='totp' && (int)($proof['user_id']??0)===(int)$account['id']
        && is_string($proof['credential_stamp']??null) && hash_equals(hash('sha256',$account['password_hash']),$proof['credential_stamp'])
        && is_int($proof['verified_at']??null) && $proof['verified_at']<=$now && $proof['verified_at']>$now-43200;
}
