use actix_web::{error, get, post, web, App, HttpResponse, HttpServer, Responder, Result};
use derive_more::{Display, Error};
use serde::{Deserialize, Serialize};
use umbral_rs::internal::curve::*;
use umbral_rs::internal::keys::*;
use umbral_rs::pre::*;

#[derive(Debug, Display, Error)]
#[display(fmt = "Error: {}", info)]
struct GenericError {
    info: &'static str,
}

impl error::ResponseError for GenericError {}

struct AppState {
    params: Rc<Params>,
}

#[derive(Serialize, Deserialize)]
struct KeyPairJson {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[derive(Deserialize)]
struct EncryptReqJson {
    plaintext: String,
    pk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct EncryptRespJson {
    cipertext: Vec<u8>,
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
    cipertext: Vec<u8>,
    cfrags: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
struct SimpleDecryptReqJson {
    keypair: KeyPairJson,
    capsule: Vec<u8>,
    cipertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct DecryptRespJson {
    plaintext: String,
}

#[get("/stateless/keypair")]
async fn keypair(data: web::Data<AppState>) -> Result<impl Responder, GenericError> {
    let kp = KeyPair::new(&data.params);
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
    let kp = Signer::new(&data.params);
    let (pk, sk) = kp.to_bytes();
    let resp = KeyPairJson { pk, sk };
    match serde_json::to_string(&resp) {
        Ok(j) => Ok(HttpResponse::Ok().body(j)),
        Err(_) => Err(GenericError {
            info: "Keypair serialization error",
        }),
    }
}

#[post("/stateless/encrypt")]
async fn encrypt_stlss(
    data: web::Data<AppState>,
    request_payload: web::Json<EncryptReqJson>,
) -> Result<impl Responder, GenericError> {
    let plain = request_payload.plaintext.as_bytes().to_vec();
    let pk = match CurvePoint::from_bytes(&request_payload.pk, &data.params) {
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
        cipertext: cipert,
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
    let alice = match KeyPair::from_bytes(
        &request_payload.sender.pk,
        &request_payload.sender.sk,
        &data.params,
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
        &data.params,
    ) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Keypair serialization Error",
            });
        }
    };
    let bob = match CurvePoint::from_bytes(&request_payload.receiver, &data.params) {
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
    let alice = match CurvePoint::from_bytes(&request_payload.sender, &data.params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization Error",
            });
        }
    };
    let signr = match CurvePoint::from_bytes(&request_payload.signer, &data.params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization Error",
            });
        }
    };
    let bob = match CurvePoint::from_bytes(&request_payload.receiver, &data.params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization Error",
            });
        }
    };
    let mut cap = match Capsule::from_bytes(&request_payload.capsule, &data.params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Capsule serialization Error",
            });
        }
    };
    let kf = match KFrag::from_bytes(&request_payload.kfrag, &data.params) {
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
    let alice = match CurvePoint::from_bytes(&request_payload.sender, &data.params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "PubKey serialization Error",
            });
        }
    };
    let signr = match CurvePoint::from_bytes(&request_payload.signer, &data.params) {
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
        &data.params,
    ) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Keypair serialization Error",
            });
        }
    };
    let mut cap = match Capsule::from_bytes(&request_payload.capsule, &data.params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Capsule serialization Error",
            });
        }
    };
    cap.set_correctness_keys(&alice, &bob.public_key(), &signr);
    for cfrag in request_payload.cfrags.to_owned() {
        let cfr = match CFrag::from_bytes(&cfrag, &data.params) {
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
    let plaintext = match decrypt(request_payload.cipertext.to_owned(), &cap, &bob, true) {
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
    let alice = match KeyPair::from_bytes(
        &request_payload.keypair.pk,
        &request_payload.keypair.sk,
        &data.params,
    ) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Keypair serialization Error",
            });
        }
    };
    let cap = match Capsule::from_bytes(&request_payload.capsule, &data.params) {
        Ok(x) => x,
        Err(_) => {
            return Err(GenericError {
                info: "Capsule serialization Error",
            });
        }
    };
    let plaintext = match decrypt(request_payload.cipertext.to_owned(), &cap, &alice, true) {
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Running at 0.0.0.0:8022");
    HttpServer::new(|| {
        App::new()
            .data(AppState {
                params: new_standard_params(),
            })
            .service(keypair)
            .service(signer)
            .service(encrypt_stlss)
            .service(kfrags_stlss)
            .service(reencrypt_stlss)
            .service(decrypt_stlss)
            .service(decrypt_simple_stlss)
    })
    .bind("0.0.0.0:8022")?
    .run()
    .await
}
