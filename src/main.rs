extern crate iron;
extern crate router;
extern crate hyper;
#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate hyper_rustls;
extern crate urlencoded;

use std::vec::Vec;
use hyper::Client as HyperClient;
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
use std::error::Error;
use std::fmt;
use iron::headers::ContentType;
use std::ops::Deref;


fn verify_md5(md5: &str) -> bool {
    lazy_static! {
        static ref MD5_RE: Regex = Regex::new("^[0-9a-f]{32}$").unwrap();
    }

    MD5_RE.is_match(md5)
}


struct AvatarError {
    pub status: Option<status::Status>,
}


struct Avatar {
    pub email_md5: String,
    pub size: Option<i64>,
    pub content_type: ContentType,
    pub buf: Vec<u8>,
}


type AvatarResult = Result<Avatar, AvatarError>;

impl Avatar {
    fn make_origin_url(email_md5: &str, size: Option<i64>, default: Option<String>) -> String {
        let mut origin_url = format!("https://secure.gravatar.com/avatar/{}", email_md5);

        let mut params: Vec<String> = Vec::new();

        if let Some(m) = size {
            params.push(format!("s={}", m));
        }

        if let Some(m) = default {
            params.push(format!("d={}", m));
        }

        if params.len() > 0 {
            origin_url.push_str("?");
            origin_url.push_str(params.join("&").as_str());
        }

        origin_url
    }

    pub fn fetch(email_md5: &str, size: Option<i64>, default: Option<String>) -> AvatarResult {

        lazy_static! {
            static ref HYPER_CLIENT: HyperClient = HyperClient::with_connector(HttpsConnector::new(RustlsClient::new()));
        }

        let origin_url = Avatar::make_origin_url(email_md5, size.clone(), default.clone());

        let mut origin_res = try!(HYPER_CLIENT.get(origin_url.as_str())
            .send()
            .map_err(|_| AvatarError { status: None }));

        if origin_res.status != hyper::Ok {
            return Err(AvatarError { status: Some(origin_res.status) });
        }

        let mut avatar_body: Vec<u8> = Vec::new();

        try!(origin_res.read_to_end(&mut avatar_body)
            .map_err(|_| AvatarError { status: Some(status::BadGateway) }));

        let content_type = try!(origin_res.headers
                .get::<ContentType>()
                .ok_or(AvatarError { status: Some(status::BadGateway) }))
            .clone();

        Ok(Avatar {
            email_md5: email_md5.to_string(),
            size: size.clone(),
            content_type: content_type,
            buf: avatar_body,
        })
    }
}


fn handler(req: &mut Request) -> IronResult<Response> {
    let email_md5 = req.extensions
        .get::<Router>()
        .unwrap()
        .find("email_md5")
        .unwrap_or("")
        .to_lowercase();

    if !verify_md5(email_md5.as_str()) {
        return Ok(Response::with((status::NotFound)));
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
        None => return Ok(Response::with((status::BadRequest))),
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
                Err(_) => return Ok(Response::with((status::BadRequest))),
            }
        }
        None => None,
    };

    let avatar = match Avatar::fetch(email_md5.as_str(), size, default) {
        Ok(v) => v,
        Err(_) => return Ok(Response::with((status::BadGateway))),
    };

    Ok(Response::with((avatar.content_type.deref().clone(), status::Ok, avatar.buf.clone())))
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

    Iron::new(chain).http("localhost:3000").unwrap();
}
