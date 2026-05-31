/*
 * @name: Snow / Epik AI Premium Unlock
 * @desc: Hỗ trợ cả 2 app: Snow (ảnh chụp AI) & Epik-AI (chỉnh sửa ảnh/video)
 * @author: Nguyễn Ngọc Anh Tú (z3rokaze)
 * @homepage: https://github.com/z3rokaze/NguyenNgocAnhTu
 * @date: 2026-05-09
 */

var objc = JSON.parse($response.body);
const ua = $request.headers["User-Agent"] || $request.headers["user-agent"];
const times = Date.now();

const list = {
    "iphoneapp.epik": { id: "com.snowcorp.epik.subscribe.plan.oneyear" },   // Epik-AI Chỉnh sửa ảnh và video
    "iphoneapp.snow": { id: "com.campmobile.snow.subscribe.oneyear" }       // SNOW-AI ảnh chụp
};

for (const key of Object.keys(list)) {
    if (new RegExp(`^${key}`, "i").test(ua)) {
        objc.result = {
            "products": [
                {
                    "managed": true,
                    "status": "ACTIVE",
                    "startDate": times,
                    "productId": list[key].id,
                    "expireDate": 32662137600000
                }
            ],
            "tickets": [
                {
                    "managed": true,
                    "status": "ACTIVE",
                    "startDate": times,
                    "productId": list[key].id,
                    "expireDate": 32662137600000
                }
            ],
            "activated": true
        };
        console.log("✅ Unlock thành công — z3rokaze");
        break;
    }
}

$done({ body: JSON.stringify(objc) });
