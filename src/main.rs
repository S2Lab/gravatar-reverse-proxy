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
#[macro_use]
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
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::io::Read;
use std::collections::HashMap;
use std::option::Option;
use std::result::Result;

use hyper::client::{Client as HyperClient, Response as HyperResponse};
use hyper::net::HttpsConnector as HyperHttpsConnector;
use hyper::status::StatusCode as HyperStatusCode;
use hyper::header as hyper_header;
use hyper_rustls::TlsClient as HyperRustlsClient;

use iron::{IronResult, IronError, Iron};
use iron::{Request as IronRequest, Response as IronResponse, Chain as IronChain,
           Plugin as IronPlugin};
use iron::{AfterMiddleware, Handler};
use iron::typemap::Key;

use router::{Router, NoRoute};
use urlencoded::{UrlEncodedQuery, UrlDecodingError};
use persistent::Write;

use regex::Regex;
use lru_cache::LruCache;
use crypto_hash::{Algorithm as HashAlgorithm, hex_digest};

header! { (XPoweredBy, "X-Powered-By") => [String] }


fn verify_md5(md5: &str) -> bool {
    lazy_static! {
        static ref MD5_RE: Regex = Regex::new("^[0-9a-f]{32}$").unwrap();
    }

    MD5_RE.is_match(md5)
}


#[derive(Clone, Eq, PartialEq, Hash, Debug)]
struct CacheControlKey {
    email_md5: String,
    size: Option<i64>,
    default: Option<String>,
}


impl CacheControlKey {
    fn from_request(req: &mut IronRequest) -> Result<CacheControlKey, IronResponse> {
        let email_md5 = req.extensions
            .get::<Router>()
            .unwrap()
            .find("email_md5")
            .unwrap_or("")
            .to_lowercase();

        if !verify_md5(email_md5.as_str()) {
            return Err(IronResponse::with((HyperStatusCode::NotFound)));
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
            None => return Err(IronResponse::with((HyperStatusCode::BadRequest))),
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
                    Err(_) => return Err(IronResponse::with((HyperStatusCode::BadRequest))),
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


#[derive(Clone)]
struct CacheControlData {
    pub etag: hyper_header::EntityTag,
    pub last_modified: hyper_header::HttpDate,
    pub content_type: hyper_header::ContentType,
    pub content_disposition: Option<hyper_header::ContentDisposition>,
    pub cache_control: hyper_header::CacheControl,
    pub expires: hyper_header::HttpDate,
}


impl CacheControlData {
    fn from_response(res: &HyperResponse, res_body: &[u8]) -> AvatarResult<CacheControlData> {
        let etag = hyper_header::EntityTag::strong(hex_digest(HashAlgorithm::SHA256,
                                                              res_body.to_vec()));
        let last_modified = res.headers
            .get::<hyper_header::LastModified>()
            .map(|m| m.deref().clone())
            .unwrap_or_else(|| hyper_header::HttpDate(time::now()));

        let content_type = try!(res.headers
            .get::<hyper_header::ContentType>()
            .map(|m| m.clone())
            .ok_or_else(|| IronResponse::with((HyperStatusCode::BadGateway))));

        let content_disposition =
            res.headers.get::<hyper_header::ContentDisposition>().map(|m| m.clone());
        let cache_control =
            hyper_header::CacheControl(vec![hyper_header::CacheDirective::MaxAge(600 as u32)]);
        let expires = hyper_header::HttpDate(time::now() + time::Duration::minutes(10));

        Ok(CacheControlData {
            etag: etag,
            last_modified: last_modified,
            content_type: content_type,
            content_disposition: content_disposition,
            cache_control: cache_control,
            expires: expires,
        })
    }

    fn set_cache_headers(&self, mut res: &mut IronResponse) {
        res.headers.set(hyper_header::ETag(self.etag.clone()));
        res.headers.set(hyper_header::LastModified(self.last_modified.clone()));
        if let Some(m) = self.content_disposition.clone() {
            res.headers.set(m);
        }
        res.headers.set(self.cache_control.clone());
        res.headers.set(hyper_header::Expires(self.expires.clone()));

    }
}


#[derive(Clone)]
struct Cache;
impl Key for Cache {
    type Value = LruCache<CacheControlKey, CacheControlData>;
}


struct Avatar {
    pub buf: Vec<u8>,
    pub cc_key: CacheControlKey,
    pub cc_data: CacheControlData,
}


type AvatarResult<T> = Result<T, IronResponse>;

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
            return Err(IronResponse::with((HyperStatusCode::BadGateway)));
        }

        let mut avatar_body: Vec<u8> = Vec::new();

        try!(res.read_to_end(&mut avatar_body)
            .map_err(|_| IronResponse::with((HyperStatusCode::BadGateway))));

        let cc_data = try!(CacheControlData::from_response(res, avatar_body.as_slice()));

        Ok(Avatar {
            buf: avatar_body,
            cc_key: cc_key,
            cc_data: cc_data,
        })

    }

    pub fn fetch(cc_key: CacheControlKey) -> AvatarResult<Avatar> {
        lazy_static! {
            static ref HYPER_CLIENT: HyperClient = HyperClient::with_connector(HyperHttpsConnector::new(HyperRustlsClient::new()));
        }

        let origin_url = Avatar::make_origin_url(&cc_key);

        let mut origin_res = try!(HYPER_CLIENT.get(origin_url.as_str())
            .send()
            .map_err(|_| IronResponse::with((HyperStatusCode::BadGateway))));

        Avatar::from_response(&mut origin_res, cc_key)
    }
}


struct MainHandler;


impl MainHandler {
    fn read_from_cache(&self,
                       cc_key: &CacheControlKey,
                       cache_mutex: &Arc<Mutex<LruCache<CacheControlKey, CacheControlData>>>)
                       -> Option<CacheControlData> {
        let mut cache = cache_mutex.lock().unwrap();

        let cc_data = match cache.get_mut(cc_key).map(|m| m.clone()) {
            Some(m) => m,
            None => return None,
        };

        if cc_data.expires > hyper_header::HttpDate(time::now()) {
            Some(cc_data)
        } else {
            cache.remove(cc_key);
            None
        }
    }

    fn response_with_200(&self, avatar: &Avatar) -> IronResult<IronResponse> {
        let mut res = IronResponse::with((avatar.cc_data.content_type.deref().clone(),
                                          HyperStatusCode::Ok,
                                          avatar.buf.clone()));

        avatar.cc_data.set_cache_headers(&mut res);
        Ok(res)

    }

    fn response_with_304(&self, cc_data: &CacheControlData) -> IronResult<IronResponse> {
        let mut res = IronResponse::with((cc_data.content_type.deref().clone(),
                                          HyperStatusCode::NotModified));

        cc_data.set_cache_headers(&mut res);

        Ok(res)
    }
}


impl Handler for MainHandler {
    fn handle(&self, mut req: &mut IronRequest) -> IronResult<IronResponse> {
        let cache_mutex = req.get::<Write<Cache>>().unwrap();

        let cc_key = match CacheControlKey::from_request(&mut req) {
            Ok(v) => v,
            Err(res) => return Ok(res),
        };



        let maybe_if_modified_since = req.headers.get::<hyper_header::IfModifiedSince>();
        let maybe_if_none_match = req.headers.get::<hyper_header::IfNoneMatch>();

        if let Some(if_none_match) = maybe_if_none_match {
            // Prefer ETag.
            if let Some(cc_data) = self.read_from_cache(&cc_key, &cache_mutex) {
                if let &hyper_header::IfNoneMatch::Items(ref items) = if_none_match {
                    if items.as_slice().contains(&cc_data.etag) {
                        return self.response_with_304(&cc_data);
                    }
                }
            }
        } else if let Some(if_modified_since) = maybe_if_modified_since {
            if let Some(cc_data) = self.read_from_cache(&cc_key, &cache_mutex) {
                if if_modified_since.deref() == &cc_data.last_modified {
                    return self.response_with_304(&cc_data);
                }
            }
        }

        let avatar = match Avatar::fetch(cc_key) {
            Ok(v) => v,
            Err(res) => return Ok(res),
        };


        let res_result = self.response_with_200(&avatar);
        {
            let mut cache = cache_mutex.lock().unwrap();

            cache.insert(avatar.cc_key, avatar.cc_data);
        }
        res_result
    }
}

struct CustomErrorMsg;


impl CustomErrorMsg {
    fn alter_response(&self, res: IronResponse) -> IronResponse {
        if res.status == Some(HyperStatusCode::NotFound) {
            IronResponse::with((HyperStatusCode::NotFound, "HTTP 404: Not Found."))

        } else if res.status == Some(HyperStatusCode::BadRequest) {
            IronResponse::with((HyperStatusCode::BadRequest, "HTTP 400: Bad Request."))

        } else if res.status == Some(HyperStatusCode::BadGateway) {
            IronResponse::with((HyperStatusCode::BadGateway, "HTTP 502: Bad Gateway."))

        } else {
            res

        }
    }
}


impl AfterMiddleware for CustomErrorMsg {
    fn after(&self, _: &mut IronRequest, res: IronResponse) -> IronResult<IronResponse> {
        Ok(self.alter_response(res))
    }

    fn catch(&self, _: &mut IronRequest, err: IronError) -> IronResult<IronResponse> {
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


struct AddXPoweredBy;


impl AddXPoweredBy {
    fn add_header(&self, res: &mut IronResponse) {
        res.headers.set(XPoweredBy("Rust".to_owned()));
    }
}


impl AfterMiddleware for AddXPoweredBy {
    fn after(&self, _: &mut IronRequest, mut res: IronResponse) -> IronResult<IronResponse> {
        self.add_header(&mut res);

        Ok(res)
    }

    fn catch(&self, _: &mut IronRequest, err: IronError) -> IronResult<IronResponse> {
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

    router.get("/avatar/:email_md5", MainHandler, "email_md5");

    let mut chain = IronChain::new(router);
    chain.link_after(CustomErrorMsg);
    chain.link_after(AddXPoweredBy);

    chain.link(Write::<Cache>::both(LruCache::new(102400)));

    Iron::new(chain).http("localhost:3000").unwrap();
}
