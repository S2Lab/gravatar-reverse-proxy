//!                             The Unlicense
//! This is free and unencumbered software released into the public domain.
//!
//! Anyone is free to copy, modify, publish, use, compile, sell, or
//! distribute this software, either in source code form or as a compiled
//! binary, for any purpose, commercial or non-commercial, and by any
//! means.
//!
//! In jurisdictions that recognize copyright laws, the author or authors
//! of this software dedicate any and all copyright interest in the
//! software to the public domain. We make this dedication for the benefit
//! of the public at large and to the detriment of our heirs and
//! successors. We intend this dedication to be an overt act of
//! relinquishment in perpetuity of all present and future rights to this
//! software under copyright law.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//! EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//! MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//! IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
//! OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
//! ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
//! OTHER DEALINGS IN THE SOFTWARE.
//!
//! For more information, please refer to <http://unlicense.org>
//!


extern crate iron;
extern crate router;
extern crate hyper;
#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate hyper_rustls;
extern crate urlencoded;
extern crate persistent;
extern crate lru_cache;
extern crate time;
extern crate crypto_hash;

use std::vec::Vec;
use hyper::Client as HyperClient;
use hyper::client::Response as HyperResponse;
use hyper::net::HttpsConnector;
use router::{Router, NoRoute};
use iron::prelude::*;
use iron::status;
use iron::AfterMiddleware;
use regex::Regex;
use std::io::Read;
use hyper_rustls::TlsClient as RustlsClient;
use urlencoded::{UrlEncodedQuery, UrlDecodingError};
use std::collections::HashMap;
use std::option::Option;
use iron::headers::{ContentType, ContentDisposition, CacheControl, ContentLength, LastModified,
                    EntityTag, HttpDate, CacheDirective};
use lru_cache::LruCache;
use persistent::Write;
use iron::typemap::Key;
use std::result::Result;
use crypto_hash::{Algorithm as HashAlgorithm, hex_digest};
use std::ops::Deref;


fn verify_md5(md5: &str) -> bool {
    lazy_static! {
        static ref MD5_RE: Regex = Regex::new("^[0-9a-f]{32}$").unwrap();
    }

    MD5_RE.is_match(md5)
}


#[derive(Clone, Eq, PartialEq, Hash)]
struct CacheControlKey {
    email_md5: String,
    size: Option<i64>,
    default: Option<String>,
}


impl CacheControlKey {
    fn from_request(req: &mut Request) -> Result<CacheControlKey, Response> {
        let email_md5 = req.extensions
            .get::<Router>()
            .unwrap()
            .find("email_md5")
            .unwrap_or("")
            .to_lowercase();

        if !verify_md5(email_md5.as_str()) {
            return Err(Response::with((status::NotFound)));
        }

        let maybe_query = req.get::<UrlEncodedQuery>()
            .map(|val| Some(val))
            .unwrap_or_else(|err: UrlDecodingError| {
                match err {
                    UrlDecodingError::EmptyQuery => Some(HashMap::new()),
                    _ => None,
                }
            });

        let query = match maybe_query {
            Some(m) => m,
            None => return Err(Response::with((status::BadRequest))),
        };

        let size_str = query.get("s")
            .map(|s_vec| s_vec.clone())
            .map(|s_vec| { if s_vec.len() > 0 { Some(s_vec) } else { None } })
            .unwrap_or(None)
            .map(|s_vec| s_vec[0].clone());

        let default = query.get("d")
            .map(|d_vec| d_vec.clone())
            .map(|d_vec| { if d_vec.len() > 0 { Some(d_vec) } else { None } })
            .unwrap_or(None)
            .map(|d_vec| d_vec[0].clone());

        let size: Option<i64> = match size_str {
            Some(m) => {
                match m.parse::<i64>() {
                    Ok(m) => Some(m),
                    Err(_) => return Err(Response::with((status::BadRequest))),
                }
            }
            None => None,
        };

        Ok(CacheControlKey {
            email_md5: email_md5,
            size: size,
            default: default,
        })
    }
}


struct CacheControlData {
    pub etag: EntityTag,
    pub last_modified: HttpDate,
    pub content_type: ContentType,
    pub content_length: u64,
    pub content_disposition: Option<ContentDisposition>,
    pub cache_control: CacheControl,
    pub expires: HttpDate,
}


impl CacheControlData {
    fn from_response(res: &HyperResponse, res_body: &[u8]) -> AvatarResult<CacheControlData> {
        let etag = EntityTag::strong(hex_digest(HashAlgorithm::SHA256, res_body.to_vec()));
        let last_modified = res.headers
            .get::<LastModified>()
            .map(|m| m.deref().clone())
            .unwrap_or_else(|| HttpDate(time::now()));

        let content_type = try!(res.headers
            .get::<ContentType>()
            .map(|m| m.clone())
            .ok_or_else(|| Response::with((status::BadGateway))));

        let content_length = try!(res.headers
            .get::<ContentLength>()
            .map(|m| m.deref().clone() as u64)
            .ok_or_else(|| Response::with((status::BadGateway))));

        let content_disposition = res.headers.get::<ContentDisposition>().map(|m| m.clone());
        let cache_control = res.headers
            .get::<CacheControl>()
            .map(|m| m.clone())
            .unwrap_or_else(|| CacheControl(vec![CacheDirective::MaxAge(600 as u32)]));
        let expires = HttpDate(time::now() + time::Duration::minutes(10));

        Ok(CacheControlData {
            etag: etag,
            last_modified: last_modified,
            content_type: content_type,
            content_length: content_length,
            content_disposition: content_disposition,
            cache_control: cache_control,
            expires: expires,
        })
    }
}


#[derive(Copy, Clone)]
struct Cache;
impl Key for Cache {
    type Value = LruCache<CacheControlKey, CacheControlData>;
}


struct Avatar {
    pub buf: Vec<u8>,
    pub cc_key: CacheControlKey,
    pub cc_data: CacheControlData,
}


type AvatarResult<T> = Result<T, Response>;

impl Avatar {
    fn make_origin_url(cc_key: &CacheControlKey) -> String {
        let mut origin_url = format!("https://secure.gravatar.com/avatar/{}", cc_key.email_md5);

        let mut params: Vec<String> = Vec::new();

        if let Some(ref m) = cc_key.size {
            params.push(format!("s={}", m));
        }

        if let Some(ref m) = cc_key.default {
            params.push(format!("d={}", m));
        }

        if params.len() > 0 {
            origin_url.push_str("?");
            origin_url.push_str(params.join("&").as_str());
        }

        origin_url
    }

    pub fn from_response(res: &mut HyperResponse, cc_key: CacheControlKey) -> AvatarResult<Avatar> {
        if res.status != hyper::Ok {
            return Err(Response::with((status::BadGateway)));
        }

        let mut avatar_body: Vec<u8> = Vec::new();

        try!(res.read_to_end(&mut avatar_body)
            .map_err(|_| Response::with((status::BadGateway))));

        let cc_data = try!(CacheControlData::from_response(res, avatar_body.as_slice()));

        Ok(Avatar {
            buf: avatar_body,
            cc_key: cc_key,
            cc_data: cc_data,
        })

    }

    pub fn fetch(cc_key: CacheControlKey) -> AvatarResult<Avatar> {
        lazy_static! {
            static ref HYPER_CLIENT: HyperClient = HyperClient::with_connector(HttpsConnector::new(RustlsClient::new()));
        }

        let origin_url = Avatar::make_origin_url(&cc_key);

        let mut origin_res = try!(HYPER_CLIENT.get(origin_url.as_str())
            .send()
            .map_err(|_| Response::with((status::BadGateway))));

        Avatar::from_response(&mut origin_res, cc_key)
    }
}


fn handler(mut req: &mut Request) -> IronResult<Response> {
    let cache_mutex = req.get::<Write<Cache>>().unwrap();

    let cc_key = match CacheControlKey::from_request(&mut req) {
        Ok(v) => v,
        Err(res) => return Ok(res),
    };

    {
        let mut cache = cache_mutex.lock().unwrap();

        if cache.contains_key(&cc_key) {
            panic!();
        }
    }

    let avatar = match Avatar::fetch(cc_key) {
        Ok(v) => v,
        Err(_) => return Ok(Response::with((status::BadGateway))),
    };

    Ok(Response::with(((*avatar.cc_data.content_type).clone(), status::Ok, avatar.buf.clone())))
}


struct CustomErrorMsg;


impl CustomErrorMsg {
    fn alter_response(&self, res: Response) -> Response {
        if res.status == Some(status::NotFound) {
            Response::with((status::NotFound, "HTTP 404: Not Found."))

        } else if res.status == Some(status::BadRequest) {
            Response::with((status::BadRequest, "HTTP 400: Bad Request."))

        } else if res.status == Some(status::BadGateway) {
            Response::with((status::BadGateway, "HTTP 502: Bad Gateway."))

        } else {
            res

        }
    }
}


impl AfterMiddleware for CustomErrorMsg {
    fn after(&self, _: &mut Request, res: Response) -> IronResult<Response> {
        Ok(self.alter_response(res))
    }

    fn catch(&self, _: &mut Request, err: IronError) -> IronResult<Response> {
        let res = err.response;
        let res = self.alter_response(res);

        if let Some(_) = err.error.downcast::<NoRoute>() {
            return Ok(res);
        }

        Err(IronError {
            error: err.error,
            response: res,
        })
    }
}


struct XPoweredBy;


impl XPoweredBy {
    fn add_header(&self, res: &mut Response) {
        res.headers.set_raw("X-Powered-By", vec![b"Rust".to_vec()]);
    }
}


impl AfterMiddleware for XPoweredBy {
    fn after(&self, _: &mut Request, mut res: Response) -> IronResult<Response> {
        self.add_header(&mut res);

        Ok(res)
    }

    fn catch(&self, _: &mut Request, err: IronError) -> IronResult<Response> {
        let mut res = err.response;
        let inner_err = err.error;
        self.add_header(&mut res);

        Err(IronError {
            error: inner_err,
            response: res,
        })
    }
}


fn main() {
    let mut router = Router::new();

    router.get("/avatar/:email_md5", handler, "email_md5");

    let mut chain = Chain::new(router);
    chain.link_after(CustomErrorMsg);
    chain.link_after(XPoweredBy);

    chain.link(Write::<Cache>::both(LruCache::new(102400)));

    Iron::new(chain).http("localhost:3000").unwrap();
}
