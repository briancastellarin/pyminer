"""
#
#
#
#
#
#
#
#
#
#
#
#
#
#
"""

""" IMPORTS """
import binascii, struct, random, time, hashlib, json, socket, threading 
from datetime import datetime 
from codecs import decode 

""" BINASCII SIMPLIFICATION """
hexlify = binascii.hexlify
unhexlify = binascii.unhexlify

""" LOG THE PROCESS """
LOG_FILE = 'logs/miner.txt'
 
LEVEL_PROTOCOL  = 'protocol'
LEVEL_INFO      = 'info'
LEVEL_DEBUG     = 'debug'
LEVEL_ERROR     = 'error'

def Log(message, level = LEVEL_INFO, ponly = False):
    # MESSAGE FORMAT
    message = '[%s] %s' % (level.upper(), message)
    
    # RELEASE OUTPUT
    output = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), message)
    
    # DISPLAY IN CONSOLE
    if level != LEVEL_PROTOCOL and level != LEVEL_DEBUG:
        print(output)
    
    # SAVE IN FILE
    if not ponly:
        with open(LOG_FILE, 'a+') as file:
            file.write(output)
            file.write('\n')

""" SHA256 DOUBLE ENCRYPT """
def sha256d(value):
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()


'''Returns a human readable representation of hashrate.'''
def human_readable_hashrate(hashrate): 
  if hashrate < 1000:
    return '%2f hashes/s' % hashrate
  if hashrate < 10000000:
    return '%2f khashes/s' % (hashrate / 1000)
  if hashrate < 10000000000:
    return '%2f Mhashes/s' % (hashrate / 1000000)
  return '%2f Ghashes/s' % (hashrate / 1000000000)

''' JOB CLASS '''
class Job(object):
    ''' CONSTRUCTOR '''
    def __init__(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, bits, time, target, extranonce1, extranonce2_size):
        
        # Job parts from the mining.notify command
        self._jobid = job_id
        self._prevhash = prevhash
        self._coinb1 = coinb1
        self._coinb2 = coinb2
        self._merklebranches = [ b for b in merkle_branches ] 
        self._version = version
        self.merk = merkle_branches
        self._bits = bits
        self._time = time 
        
        # Job information needed to mine from mining.subsribe
        self._target = target
        self._extranonce1 = extranonce1
        self._extranonce2_size = extranonce2_size
        
        # Flag to stop this job's mine coroutine
        self.finish = False
        self.sopt = False
        
        # Hash metrics (start time, delta time, total hashes)
        self.deltatime = 0.0
        self.hash_done = 0
        self.passaway = 0
    
    # Accessors
    id = property(lambda s: s._jobid)
    prevhash = property(lambda s: s._prevhash)
    coinb1 = property(lambda s: s._coinb1)
    coinb2 = property(lambda s: s._coinb2)
    merkle_branches = property(lambda s: [ b for b in s._merklebranches ])
    version = property(lambda s: s._version)
    bits = property(lambda s: s._bits)
    time = property(lambda s: s._time)

    target = property(lambda s: s._target)
    extranonce1 = property(lambda s: s._extranonce1)
    extranonce2_size = property(lambda s: s._extranonce2_size)
  
    @property
    def hashrate(self):
        if self.deltatime == 0: return 0.0
        return self.hash_done / self.deltatime
    
    def merkle_root_bin(self, extranonce2):
        merkle_root = None
        if self.coinb1 == -1:
            merkle_root = decode(self.merk, 'hex')
        else:
            merkle_root = sha256d( decode(self.coinb1, 'hex') + decode(self.extranonce1, 'hex') + extranonce2  + decode(self.coinb2, 'hex') ) 
            for branch in self.merkle_branches:
                        merkle_root = sha256d( merkle_root + decode(branch , 'hex'))
        return merkle_root
    
    def stop(self):
        self.sopt = True
        self.finish = True 
        
    def mine(self, nonce_start = 0,  nonce_ends = 0x7fffffff,  nonce_step = 1):
        ''' TIMER START '''
        timer_start = time.time()
        
        ''' MINE '''
        while not self.sopt:
            #0xffffffff
            for extranonce2 in range( 0, 0x7fffffff):
                 
                ''' GENERATE EXTRANONCE2 BY SIZE '''
                extranonce2_bin = extranonce2.to_bytes(self.extranonce2_size, 'big')
                 
                ''' GENERATE HEADER '''
                header = struct.pack('<L', int(self.version)) + decode(self.prevhash[::-1], 'hex')[::-1] + self.merkle_root_bin(extranonce2_bin)[::-1] + struct.pack('<LL', int(self.time, 16), int(self.bits, 16))
                 
                ''' NONCE SEARCH '''
                for nonce in range(nonce_start, nonce_ends, nonce_step):
                    
                    ''' EXIT LOOP '''
                    if self.finish:
                            #print('number of rounds before a new job: {}'.format(self.passaway))
                            #print('extranonce2: ', extranonce2)
                            self.deltatime += (time.time() - timer_start)
                            raise StopIteration()
                
                    ''' NONCE BIN '''
                    nonce_bin : bytes = struct.pack('<L', nonce)
                    
                    # + unhexlify('000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000') padding ?
                    ''' FINISH HASH '''
                    hash = hexlify(sha256d(header  + nonce_bin + struct.pack('<LL',0x80000000,0x00000280))[::-1]).decode()
                     
                    ''' FALSE POSITIVE '''
                    if hash.startswith('0'*6):
                        print('false positive hash: {}, at extranonce2: {}'.format(hash, extranonce2))
                         
                    if hash <= self.target:
                        result = dict(
                            jobid = self.id,
                            extranonce2 = hexlify(extranonce2_bin),
                            ntime = str(self.time),                   
                            nonce = hexlify(nonce_bin[::-1])
                        )
                        
                        self.deltatime += (time.time() - timer_start)
                        
                        yield result
                        
                        self.sopt = True 
                        timer_start = time.time()
                     
                    self.hash_done += 1   
            self.passaway += 1
            
    def __str__(self):
        return '<Job id=%s prevhash=%s coinb1=%s coinb2=%s merkle_branches=%s version=%s nbits=%s ntime=%s target=%s extranounce1=%s extranounce2_size=%d>' % (self.id, self.prevhash, self.coinb1, self.coinb2, self.merkle_branches, self.version, self.bits, self.time, self.target, self.extranonce1, self.extranonce2_size)


""" MINER CLASS """
class Miner:
    """ CONSTRUCTOR """
    def __init__(self, hostname, port, username, password):
        ''' SERVER '''
        self.server = None
        self.handle_server = None
        self.job = None
        self.requests = {}
        self.message_id = 1
        self.lock = threading.RLock()
        self.worker_name = None
        self.username = username
        self.password = password
        self.subscription_id = None
        
        ''' '''
        self.extranonce1 = None
        self.extranonce2_size = None
        self.target = None
        self.difficulty = None
        self.accepted = 0
         
        
        ''' TRY TO CONNECT '''
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try: 
            print('#'*20, ' PYTHON MINER v1.0 ', '#'*20 )
        
            ''' CONNECT '''
            self.server.connect((hostname, port)) 
                
            Log('starting server on {}:{}'.format(hostname, port))
        except:
            raise Log('fail to connect to {}:{}'.format(hostname, port))
            
    def handle_server_data(self):
        ''' RETRIVE DATA FROM SERVER '''
        response = ''
        line = ''
        reply = ''
        while True:
            
            ''' CHECK IF HAVE NEW LINE, IF NOT RETRIVE A DATA FROM SERVER '''
            if '\n' in response:
                (line, response) = response.split('\n', 1)
            else:
                response += self.server.recv(1024).decode()
                continue
            
            ''' SERVERS RETRIVE DATA '''
            Log("servers says: {}".format(line), LEVEL_PROTOCOL)
            
            ''' TRY TO PARSE THE DATA '''
            try:
                reply = json.loads(line)
            except:
                Log("fail to parse json data from server, {} (skipping)".format(line), LEVEL_PROTOCOL)
                continue
            
            ''' HANDLE REPLY FROM THE SERVER '''
            try:
                r = None
                if 'id' in reply and reply['id'] in self.requests:
                    r = self.requests[reply['id']]
                self.handle_response(r, reply)
            except:
                #Log('something happend trying to handle the reply', LEVEL_ERROR)
                continue
            
    def handle_response(self, request, reply):
        
        ''' '''
        if reply.get('method') == 'mining.notify':
            if 'params' not in reply or len(reply['params']) != 9:
                raise Log('Malformed mining.notify message\n{}'.format(reply), LEVEL_ERROR)
            
            ''' GET INFO FROM SERVER '''
            job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs = reply['params'] 
              
            ''' GENERATE THE JOB '''
            self.spawn_job(job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime)
            
            Log('new job: {}'.format(job_id), LEVEL_DEBUG)
            
        elif reply.get('method') == 'mining.set_difficulty':
            if 'params' not in reply or len(reply['params']) != 1:
                raise Log('malformed mining.set_difficulty message\n{}'.format(reply), LEVEL_ERROR)
            ''' '''
            difficulty = reply['params'][0]
            
            ''' '''
            self.set_difficulty(difficulty)
            
            ''' '''
            Log('change difficulty: {}'.format(difficulty), LEVEL_DEBUG)
        elif request:
            if request.get('method') == 'mining.subscribe':
                if 'result' not in reply or len(reply['result']) != 3:
                    raise Log('Reply to mining.subscribe is malformed\n{}\n{}'.format(reply, request), LEVEL_ERROR)
                
                ''' '''
                details, self.extranonce1, self.extranonce2_size = reply['result']
                
                ''' '''
                self.subscription_id = details[0][1]
                Log('subscribed: subscription_id={}'.format(details), LEVEL_DEBUG)

                ''' REQUEST AUTHENTICATION '''
                self.send(method = 'mining.authorize', params = [ self.username, self.password ])
                
            elif request.get('method') == 'mining.authorize':
                if 'result' not in reply or not reply['result']:
                    raise Log('failed to authenticate worker\n{}\n{}'.format(reply, request), LEVEL_ERROR)
                
                ''' '''
                self.worker_name =  request['params'][0]
                
                Log('authorized: worker_name={}'.format(self.worker_name), LEVEL_DEBUG)
                
            elif request.get('method') == 'mining.submit':
                if 'result' not in reply or not reply['result']: 
                    raise Log('failed to accept submit'.format(reply, request), LEVEL_ERROR)
                
                self.accepted += 1
                Log('\033[0;32;40maccepted shares: {}'.format(self.accepted))
            else:
                raise Log('unhandled message\n{}\n{}'.format(reply, request), LEVEL_ERROR)
        else:
            raise Log('bad message state\n{}'.format(reply), LEVEL_ERROR)
        
    def send(self, method, params):
        
        ''' CHECK IF CONNECTED '''
        if not self.server:
            raise Log('not connected to the server', LEVEL_ERROR)

        ''''''
        request =  dict(id = self.message_id, method = method, params = params)
        message = json.dumps(request)
        
        with self.lock:
            self.requests[self.message_id] = request
            self.message_id += 1
            self.server.sendall((message + '\n').encode())
        
        Log('request sended to the server:\n{}'.format(message), LEVEL_PROTOCOL)
        return request
        
    def set_target(self, target):
        self.target = '%064x' % target
        Log('difficulty target: {}'.format(self.target), LEVEL_DEBUG)
    
    def set_difficulty(self, difficulty):
        if difficulty < 0: Log('difficulty must be non-negative', LEVEL_ERROR)

        # Compute target
        if difficulty == 0:
            target : int = 2 ** 256 - 1
        else:
            target = min(int((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1 + 0.5), 2 ** 256 - 1)

        self.difficulty = difficulty
        self.set_target(target)
   
    def spawn_job(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime):
        
        if self.subscription_id is None:
            raise Log('not subscribed', LEVEL_DEBUG)
 
        if self.job: self.job.stop()
        
        self.job = Job(
                job_id = job_id,
                prevhash = prevhash,
                coinb1 = coinb1,
                coinb2 = coinb2,
                merkle_branches = merkle_branches,
                version = version,
                bits = nbits,
                time = ntime,
                target = self.target,
                extranonce1 = self.extranonce1,
                extranonce2_size = self.extranonce2_size,
            )
        
        def work(job):
            try:
                Log('working now... standby', LEVEL_DEBUG)
                for result in job.mine(0, 0x7fffffff):
                    params = [ self.worker_name ] + [ result[k] for k in ('job_id', 'extranonce2', 'ntime', 'nonce') ]
                    self.send(method = 'mining.submit', params = params)
                    Log("\033[0;32;40mfound share: " + str(params))
                    break
                #print("hashrate: %s" % human_readable_hashrate(job.hashrate))
            except Exception as e:
                Log("error: %s" % e, LEVEL_DEBUG)
        
        thread = threading.Thread(target = work, args = (self.job, ))
        thread.daemon = True
        thread.start()
         
    def run(self):
        ''' SUBSCRIBE TO THE SERVER '''
        self.send(method = 'mining.subscribe', params = ['PYMINER/1.0V'])
         
        
        ''' PARSE DATA FROM SERVER '''
        if not self.handle_server:
                self.handle_server = threading.Thread(target=self.handle_server_data)
                self.handle_server.daemon = True
                self.handle_server.start()
                
        while True:
            time.sleep(10)


        
if __name__ == '__main__':
    
    miner = Miner('solo.ckpool.org', 3333, '1Bc1iqcXKswgXoiZK7AiGuRL4DZBPi3MHQ', 'x')
    miner.run()
    
