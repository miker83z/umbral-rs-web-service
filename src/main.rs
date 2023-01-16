use actix_web::{error, get, post, web, App, HttpResponse, HttpServer, Responder, Result};
use derive_more::{Display, Error};
use openssl::ec::{EcGroup, EcPoint};
use openssl::nid::Nid;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use umbral_rs::internal::curve::*;
use umbral_rs::internal::keyredistrib::*;
use umbral_rs::internal::keys::*;
use umbral_rs::pre::*;

use openssl::bn::{BigNum, BigNumContext};

// util functions

// fn params_rc_to_arc(params: &Rc<Params>) -> Arc<Params> {
//     Arc::new(params.clone())
// }

pub struct ParamsArc {
    group: EcGroup,
    g_point: EcPoint,
    order: BigNum,
    u_point: EcPoint,
    field_order_size_in_bytes: usize,
    group_order_size_in_bytes: usize,
    ctx: Arc<RefCell<BigNumContext>>,
}
#[derive(Debug, Display, Error)]
#[display(fmt = "Error: {}", info)]
struct GenericError {
    info: &'static str,
}

impl error::ResponseError for GenericError {}
// create a hashtable whose key is a string and value is a struct KeyState
// #[derive(Clone)]
struct KeyState {
    n: usize,
    threshold: usize,
    private_key_vec: Vec<Vec<u8>>,
}

impl Clone for KeyState {
    fn clone(&self) -> Self {
        KeyState {
            n: self.n,
            threshold: self.threshold,
            private_key_vec: self.private_key_vec.clone(),
        }
    }
}

impl KeyState {
    fn new(n: usize, threshold: usize) -> KeyState {
        let private_key_vec: Vec<Vec<u8>> = Vec::new();

        KeyState {
            n,
            threshold,
            private_key_vec,
        }
    }

    fn Copy(&self) -> KeyState {
        KeyState {
            n: self.n,
            threshold: self.threshold,
            private_key_vec: self.private_key_vec.clone(),
        }
    }

    fn clone(&self) -> KeyState {
        KeyState {
            n: self.n,
            threshold: self.threshold,
            private_key_vec: self.private_key_vec.clone(),
        }
    }

    fn get_threshold(&self) -> usize {
        self.threshold
    }

    fn get_n(&self) -> usize {
        self.n
    }

    fn add_private_key(&mut self, private_key: Vec<u8>) -> Self {
        self.private_key_vec.push(private_key);

        let n = self.n;
        let threshold = self.threshold;
        let private_key_vec = self.private_key_vec.clone();

        KeyState {
            n,
            threshold,
            private_key_vec,
        }
    }

    fn has_private_key(&self, sk: &Vec<u8>) -> bool {
        let mut priv_vec_iter = self.private_key_vec.iter();
        // O(n) search
        let mut flag = false;
        for _ in 0..self.private_key_vec.len() {
            if priv_vec_iter.next() == Some(&sk) {
                flag = true;
                break;
            }
        }
        flag
    }

    fn delete_keystate(&mut self) -> Self {
        let n = 0;
        let threshold = 0;

        KeyState {
            n,
            threshold,
            private_key_vec: Vec::new(),
        }
    }

    fn get_private_keys_number(&self) -> usize {
        self.private_key_vec.len()
    }
}

#[derive(Deserialize)]
struct KeyRefreash {
    sid: usize,
    parties: usize,
    threshold: usize,
    keypair: KeyPairJson,
}

// struct AppState {
//     params: Arc<Params>,
//     keystate: Mutex<HashMap<usize, KeyState>>,
// }

struct AppState {
    keystate: Mutex<HashMap<usize, KeyState>>,
}

impl AppState {
    fn new() -> AppState {
        AppState {
            // params,
            keystate: Mutex::new(HashMap::new()),
        }
    }

    // fn clone(&self) -> AppState {
    //     AppState {
    //         // params: self.params.clone(),
    //         keystate: self.keystate,
    //     }
    // }
}

impl Clone for AppState {
    fn clone(&self) -> AppState {
        AppState {
            // params: self.params.clone(),
            keystate: Mutex::new(self.keystate.lock().unwrap().clone()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct KeyPairJson {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[derive(Deserialize)]
struct SignReqJson {
    signer: KeyPairJson,
    data: String,
}

#[derive(Serialize, Deserialize)]
struct SignRespJson {
    signature: Vec<u8>,
}

#[derive(Deserialize)]
struct VerifyReqJson {
    signature: Vec<u8>,
    data: String,
    pk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct VerifyRespJson {
    verified: bool,
}

#[derive(Deserialize)]
struct EncryptReqJson {
    plaintext: String,
    pk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct EncryptRespJson {
    ciphertext: Vec<u8>,
    capsule: Vec<u8>,
}

#[derive(Deserialize)]
struct KfragsReqJson {
    sender: KeyPairJson,
    signer: KeyPairJson,
    receiver: Vec<u8>,
    threshold: usize,
    nodes_number: usize,
}

#[derive(Serialize, Deserialize)]
struct KfragsRespJson {
    kfrags: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct KeyRefreshRespJson {
    resp: String,
}

#[derive(Deserialize)]
struct ReencryptReqJson {
    sender: Vec<u8>,
    signer: Vec<u8>,
    receiver: Vec<u8>,
    capsule: Vec<u8>,
    kfrag: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ReencryptRespJson {
    cfrag: Vec<u8>,
}

#[derive(Deserialize)]
struct DecryptReqJson {
    sender: Vec<u8>,
    signer: Vec<u8>,
    receiver: KeyPairJson,
    capsule: Vec<u8>,
    ciphertext: Vec<u8>,
    cfrags: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
struct SimpleDecryptReqJson {
    keypair: KeyPairJson,
    capsule: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct DecryptRespJson {
    plaintext: String,
}

#[get("/stateless/keypair")]
async fn keypair(data: web::Data<AppState>) -> Result<impl Responder, GenericError> {
    let params = new_standard_params();
    let kp = KeyPair::new(&params);
    let (pk, sk) = kp.to_bytes();
    let resp = KeyPairJson { pk, sk };
    match serde_json::to_string(&resp) {
        Ok(j) => Ok(HttpResponse::Ok().body(j)),
        Err(_) => Err(GenericError {
            info: "Keypair serialization error",
        }),
    }
}

#[get("/stateless/signer")]
async fn signer(data: web::Data<AppState>) -> Result<impl Responder, GenericError> {
    let params = new_standard_params();
    let kp = Signer::new(&params);
    let (pk, sk) = kp.to_bytes();
    let resp = KeyPairJson { pk, sk };
    match serde_json::to_string(&resp) {
        Ok(j) => Ok(HttpResponse::Ok().body(j)),
        Err(_) => Err(GenericError {
            info: "Keypair serialization error",
        }),
    }
}

#[post("/stateless/sign")]
async fn sign_stlss(
    data: web::Data<AppState>,
    request_payload: web::Json<SignReqJson>,
) -> Result<impl Responder, GenericError> {
    let params = new_standard_params();
    let signr = match Signer::from_bytes(
        &request_payload.signer.pk,
        &request_payload.signer.sk,
        &params,
    ) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Keypair serialization Error",
            });
        }
    };
    let data = request_payload.data.as_bytes().to_vec();

    let signature = signr.sign_sha2(&data);

    let resp = SignRespJson {
        signature: signature.to_bytes(),
    };
    match serde_json::to_string(&resp) {
        Ok(j) => Ok(HttpResponse::Ok().body(j)),
        Err(_) => Err(GenericError {
            info: "Signature serialization error",
        }),
    }
}

#[post("/stateless/verify")]
async fn verify_stlss(
    data: web::Data<AppState>,
    request_payload: web::Json<VerifyReqJson>,
) -> Result<impl Responder, GenericError> {
    let params = new_standard_params();
    let signatr = match Signature::from_bytes(&request_payload.signature, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Signature serialization Error",
            });
        }
    };
    let pk = match CurvePoint::from_bytes(&request_payload.pk, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization error",
            });
        }
    };
    let data = request_payload.data.as_bytes().to_vec();

    let verified = signatr.verify_sha2(&data, &pk);

    let resp = VerifyRespJson { verified };
    match serde_json::to_string(&resp) {
        Ok(j) => Ok(HttpResponse::Ok().body(j)),
        Err(_) => Err(GenericError {
            info: "Signature serialization error",
        }),
    }
}

#[post("/stateless/encrypt")]
async fn encrypt_stlss(
    data: web::Data<AppState>,
    request_payload: web::Json<EncryptReqJson>,
) -> Result<impl Responder, GenericError> {
    let params = new_standard_params();
    let plain = request_payload.plaintext.as_bytes().to_vec();
    let pk = match CurvePoint::from_bytes(&request_payload.pk, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization error",
            });
        }
    };
    let (cipert, cap) = match encrypt(&pk, &plain) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Encryption Error",
            });
        }
    };
    let resp = EncryptRespJson {
        ciphertext: cipert,
        capsule: cap.to_bytes(),
    };
    match serde_json::to_string(&resp) {
        Ok(j) => Ok(HttpResponse::Ok().body(j)),
        Err(_) => Err(GenericError {
            info: "Capsule serialization error",
        }),
    }
}

#[post("/stateless/kfrags")]
async fn kfrags_stlss(
    data: web::Data<AppState>,
    request_payload: web::Json<KfragsReqJson>,
) -> Result<impl Responder, GenericError> {
    let params = new_standard_params();
    let alice = match KeyPair::from_bytes(
        &request_payload.sender.pk,
        &request_payload.sender.sk,
        &params,
    ) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Keypair serialization Error",
            });
        }
    };
    let signr = match Signer::from_bytes(
        &request_payload.signer.pk,
        &request_payload.signer.sk,
        &params,
    ) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Keypair serialization Error",
            });
        }
    };
    let bob = match CurvePoint::from_bytes(&request_payload.receiver, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization Error",
            });
        }
    };
    let kfrags = match generate_kfrags(
        &alice,
        &bob,
        request_payload.threshold,
        request_payload.nodes_number,
        &signr,
        KFragMode::DelegatingAndReceiving,
    ) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "KFrag Error",
            });
        }
    };

    let mut v: Vec<Vec<u8>> = Vec::new();
    for kfrag in kfrags {
        v.push(kfrag.to_bytes())
    }

    let resp = KfragsRespJson { kfrags: v };
    match serde_json::to_string(&resp) {
        Ok(j) => Ok(HttpResponse::Ok().body(j)),
        Err(_) => Err(GenericError {
            info: "KFrags serialization error",
        }),
    }
}

#[post("/stateless/reencrypt")]
async fn reencrypt_stlss(
    data: web::Data<AppState>,
    request_payload: web::Json<ReencryptReqJson>,
) -> Result<impl Responder, GenericError> {
    let params = new_standard_params();
    let alice = match CurvePoint::from_bytes(&request_payload.sender, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization Error",
            });
        }
    };
    let signr = match CurvePoint::from_bytes(&request_payload.signer, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization Error",
            });
        }
    };
    let bob = match CurvePoint::from_bytes(&request_payload.receiver, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization Error",
            });
        }
    };
    let mut cap = match Capsule::from_bytes(&request_payload.capsule, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Capsule serialization Error",
            });
        }
    };
    let kf = match KFrag::from_bytes(&request_payload.kfrag, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "KFrag serialization Error",
            });
        }
    };
    cap.set_correctness_keys(&alice, &bob, &signr);
    let cfrag = match reencrypt(&kf, &cap, true, None, true) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Re-encryption Error",
            });
        }
    };
    let resp = ReencryptRespJson {
        cfrag: cfrag.to_bytes(),
    };
    match serde_json::to_string(&resp) {
        Ok(j) => Ok(HttpResponse::Ok().body(j)),
        Err(_) => Err(GenericError {
            info: "CFrag serialization error",
        }),
    }
}

#[post("/stateless/decrypt")]
async fn decrypt_stlss(
    data: web::Data<AppState>,
    request_payload: web::Json<DecryptReqJson>,
) -> Result<impl Responder, GenericError> {
    let params = new_standard_params();
    let alice = match CurvePoint::from_bytes(&request_payload.sender, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization Error",
            });
        }
    };
    let signr = match CurvePoint::from_bytes(&request_payload.signer, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization Error",
            });
        }
    };
    let bob = match KeyPair::from_bytes(
        &request_payload.receiver.pk,
        &request_payload.receiver.sk,
        &params,
    ) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Keypair serialization Error",
            });
        }
    };
    let mut cap = match Capsule::from_bytes(&request_payload.capsule, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Capsule serialization Error",
            });
        }
    };
    cap.set_correctness_keys(&alice, &bob.public_key(), &signr);
    for cfrag in request_payload.cfrags.to_owned() {
        let cfr = match CFrag::from_bytes(&cfrag, &params) {
            Ok(x) => x,
            Err(_) => {
                return Err(GenericError {
                    info: "Cfrag serialization Error",
                });
            }
        };
        match cap.attach_cfrag(&cfr) {
            Ok(_) => (),
            Err(_) => {
                return Err(GenericError {
                    info: "Capsule fragments attach Error",
                });
            }
        };
    }
    let plaintext = match decrypt(request_payload.ciphertext.to_owned(), &cap, &bob, true) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Decryption Error",
            });
        }
    };

    let resp = DecryptRespJson {
        plaintext: match String::from_utf8(plaintext.to_owned()) {
            Ok(x) => x,
            Err(_) => {
                return Err(GenericError {
                    info: "Plaintext serialization Error",
                });
            }
        },
    };
    match serde_json::to_string(&resp) {
        Ok(j) => Ok(HttpResponse::Ok().body(j)),
        Err(_) => Err(GenericError {
            info: "Plaintext serialization error",
        }),
    }
}

#[post("/stateless/simple_decrypt")]
async fn decrypt_simple_stlss(
    data: web::Data<AppState>,
    request_payload: web::Json<SimpleDecryptReqJson>,
) -> Result<impl Responder, GenericError> {
    let params = new_standard_params();
    let alice = match KeyPair::from_bytes(
        &request_payload.keypair.pk,
        &request_payload.keypair.sk,
        &params,
    ) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Keypair serialization Error",
            });
        }
    };
    let cap = match Capsule::from_bytes(&request_payload.capsule, &params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Capsule serialization Error",
            });
        }
    };
    let plaintext = match decrypt(request_payload.ciphertext.to_owned(), &cap, &alice, true) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Decryption Error",
            });
        }
    };

    let resp = DecryptRespJson {
        plaintext: match String::from_utf8(plaintext.to_owned()) {
            Ok(x) => x,
            Err(_) => {
                return Err(GenericError {
                    info: "Plaintext serialization Error",
                });
            }
        },
    };
    match serde_json::to_string(&resp) {
        Ok(j) => Ok(HttpResponse::Ok().body(j)),
        Err(_) => Err(GenericError {
            info: "Plaintext serialization error",
        }),
    }
}

#[post("/stateful/keyrefresh")]
async fn keyrefresh_stfl(
    data: web::Data<AppState>,
    request_payload: web::Json<KeyRefreash>,
) -> Result<impl Responder, GenericError> {
    let params = new_standard_params();
    // 1. get data
    // 2. parse it
    // let params = &data.params;
    let N = request_payload.parties;
    let t = request_payload.threshold;
    let pk = &request_payload.keypair.pk;
    let sk_bytes = request_payload.keypair.sk.clone();
    let sk = CurveBN::from_bytes(&sk_bytes, &params).unwrap();

    // 2.1. if exists already, stop
    // 3. store it
    // 3.1 if number of stored data is equal to N, start key refresh
    // 4. return response
    let sid = request_payload.sid;

    // None => {
    //     return Err(GenericError {
    //         info: "No sid found",
    //     });
    // }
    // get the key state from the keystate map
    let mut keystateMap = data.keystate.lock().unwrap();
    // let mut keystate = data.keystate[&sid];
    let mut resp0: String;

    // if sid is not in the keystate map, create a new one
    // check if key sid is in the keystate map
    // if it is, check if the key is already refreshed
    if keystateMap.contains_key(&sid) {
        resp0 = format!("Key state already exists for sid: {}", sid);
        // let curr_keystate = keystate.get(&sid).unwrap();
        // check if private key is already in the current keystate
        if keystateMap[&sid].has_private_key(&sk_bytes) {
            resp0 = format!("{}. Key already in there", resp0);
            return Err(GenericError {
                info: "Key already in there",
            });
        }
        let mut ks = keystateMap[&sid].clone();
        ks.add_private_key(sk_bytes);
        *keystateMap.get_mut(&sid).unwrap() = ks;
    } else {
        resp0 = format!("Key state does not exist for sid: {}", sid);
        let mut ks = KeyState::new(N, t);
        // let mut ks = keystateMap[&sid].clone();
        ks.add_private_key(sk_bytes);
        // *keystateMap.get_mut(&sid).unwrap() = ks;
        keystateMap.insert(sid, ks);
    }

    let curr_key_length = keystateMap[&sid].get_private_keys_number();
    let resp_raw;
    let resp: KeyRefreshRespJson;

    if curr_key_length < N {
        resp_raw= format!(
                    "{}. There are currently {} keys in the keystate for sid {}. We expect to have {} keys in total",
                    resp0, curr_key_length, sid, N
                );
        resp = KeyRefreshRespJson { resp: resp_raw };
    } else {
        let keys_vector = keystateMap[&sid].private_key_vec.clone();
        let key_vector_iter = keys_vector.iter();
        let key_vector_curveBN = key_vector_iter
            .map(|x| CurveBN::from_bytes(x, &params).unwrap())
            .collect();
        let res = key_refresh(&key_vector_curveBN, t as u32, &params);
        // print the result
        resp_raw = format!("Result: {:?}", res);
        resp = KeyRefreshRespJson { resp: resp_raw };

        let mut ks = keystateMap[&sid].clone();
        ks.delete_keystate();
        *keystateMap.get_mut(&sid).unwrap() = ks;
    }

    match serde_json::to_string(&resp) {
        Ok(j) => Ok(HttpResponse::Ok().body(j)),
        Err(_) => Err(GenericError {
            info: "Plaintext serialization error",
        }),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port = "8080";
    // let old_params = new_standard_params();
    // let mut params = Params::new(Nid::SECP256K1);
    // let group = params.group();
    // let g_point = params.g_point();
    // let order = params.order();
    // let u_point = params.u_point();
    // let field_order_size_in_bytes = params.field_order_size_in_bytes();
    // let group_order_size_in_bytes = params.group_order_size_in_bytes();
    // let ctx = params.ctx();

    // let param2 = ParamsArc {
    //     group: group,
    //     g_point: g_point,
    //     order: order,
    //     u_point: u_point,
    //     field_order_size_in_bytes: field_order_size_in_bytes,
    //     group_order_size_in_bytes: group_order_size_in_bytes,
    //     ctx: Arc::new(RefCell::new(ctx)),
    // };
    // let arc_params = Arc::new(new_params);

    println!("Running at 0.0.0.0:{}", port);
    let keystate = web::Data::new(AppState {
        // params: arc_params,
        keystate: Mutex::new(HashMap::new()),
    });
    HttpServer::new(move || {
        App::new()
            .app_data(keystate.clone())
            .service(keypair)
            .service(signer)
            .service(sign_stlss)
            .service(verify_stlss)
            .service(encrypt_stlss)
            .service(kfrags_stlss)
            .service(reencrypt_stlss)
            .service(decrypt_stlss)
            .service(decrypt_simple_stlss)
            .service(keyrefresh_stfl)
    })
    .bind(format!("{}{}", "0.0.0.0:".to_string(), port))?
    .run()
    .await
}
