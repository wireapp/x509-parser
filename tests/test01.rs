use nom::bytes::complete::take;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[wasm_bindgen_test]
fn test01() {
    let data = b"0\x88\xff\xff\xff\xff\xff\xff\xff\xff00\x0f\x02\x000\x00\x00\x00\x00\x00\x0000\x0f\x00\xff\x0a\xbb\xff";
    let _ = x509_parser::parse_x509_certificate(data);
}

fn parser02(input: &[u8]) -> nom::IResult<&[u8], ()> {
    let (_hdr, input) = take(1_usize)(input)?;
    let (_data, input) = take(usize::MAX)(input)?;
    Ok((input, ()))
}

#[test]
#[wasm_bindgen_test]
fn test02() {
    let data = b"0\x88\xff\xff\xff\xff\xff\xff\xff\xff00\x0f\x02\x000\x00\x00\x00\x00\x00\x0000\x0f\x00\xff\x0a\xbb\xff";
    let _ = parser02(data);
}
