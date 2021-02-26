package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/guonaihong/gout"
	"log"
	"time"

	"github.com/tencentyun/scf-go-lib/cloudfunction"
	"github.com/wumansgy/goEncrypt"
)

const (
	Skey    = "SCT6259Toc8zUBfz9DHpE27zBjUGLzlT" //酷推 skey
	Cookie  = "sajssdk_2015_cross_new_user=1; udata_account_300011972819=JaPyEobBrwwaGy0R4PMqZ73YoezyES0KyjHVXGuj5sA%3D; userid_300011972819=1614331615398298410; udata_s_300011972819=1614331616067519760; CAIYUN-TOKEN=u6iq78dGC+9QuQkdaMRIT4fHKPrLV32qMUM8LpTqMS2rBt27OX+rcB45sdjZrce2C5xcHh9qL/GOadoaJ2JiPkjv9ULmrpBNHyi7nD3hIvwpTFoCfZUjYk7HKD22av433XyoM6x2z0p/7+UraFNAHr5RauhTAg99Jnb8nSiQK+6/I7kwwGQLLGZjRNN2Fw/0Kgu9CYQL0A0gMPaH5wOJ4Dwaac+3oFp63shNn7vnSfTQuxaEXl6nkvEzhJSAXXl4cgLBM7aDyiMgnJUJItM4Sw==; CAIYUN-ACCOUNT=7hN6CpkfY8TE9qvyLzcZvg==; CAIYUN-ENCRYPT-ACCOUNT=MTUwMDM0NDg5NjA=; CAIYUN-SIMPLIFY-ACCOUNT=150****8960; sensorsdata2015jssdkcross=%7B%22distinct_id%22%3A%22177dda992af20b-0232b334a7ff42-1760647e-230400-177dda992b0271%22%2C%22first_id%22%3A%22%22%2C%22props%22%3A%7B%22%24latest_traffic_source_type%22%3A%22%E7%9B%B4%E6%8E%A5%E6%B5%81%E9%87%8F%22%2C%22%24latest_search_keyword%22%3A%22%E6%9C%AA%E5%8F%96%E5%88%B0%E5%80%BC_%E7%9B%B4%E6%8E%A5%E6%89%93%E5%BC%80%22%2C%22%24latest_referrer%22%3A%22%22%2C%22phoneNumber%22%3A%2215003448960%22%7D%2C%22%24device_id%22%3A%22177dda992af20b-0232b334a7ff42-1760647e-230400-177dda992b0271%22%7D; sensors_stay_url=https%3A%2F%2Fyun.139.com%2Fm%2F%23%2Fmain; sensors_stay_time=1614331846874" //抓包Cookie
	Referer = "https://yun.139.com/m/" //抓包referer
	UA      = "Mozilla/5.0 (Linux; Android 10; M2007J3SC Build/QKQ1.191222.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.106 Mobile Safari/537.36 MCloudApp/7.6.0"
)

func push(content string) error {
	var resp SendResult
	err := gout.POST(fmt.Sprintf("https://sctapi.ftqq.com/SCT6259Toc8zUBfz9DHpE27zBjUGLzlT.send?title=messagetitle", Skey)).
		SetBody(content).Debug(true).BindJSON(&resp).Do()

	if err != nil {
		log.Printf("push err: %v", err)
		return err
	}

	if resp.Code != 200 {
		return errors.New(resp.Message)
	}

	return nil
}

func getEncryptTime() (int64, error) {
	var resp GetEncryptTime
	err := gout.POST("http://caiyun.feixin.10086.cn:7070/portal/ajax/tools/opRequest.action").
		SetHeader(gout.H{
			"Host":             "caiyun.feixin.10086.cn:7070",
			"Accept":           "*/*",
			"X-Requested-With": "XMLHttpRequest",
			"User-Agent":       UA,
			"Content-Type":     "application/x-www-form-urlencoded",
			"Origin":           "http://caiyun.feixin.10086.cn:7070",
			"Referer":          Referer,
			"Accept-Encoding":  "gzip, deflate",
			"Accept-Language":  "zh-CN,zh;q=0.9,en;q=0.8",
			"Cookie":           Cookie,
		}).Debug(true).SetWWWForm(gout.H{
		"op": "currentTimeMillis",
	}).BindJSON(&resp).Do()
	if err != nil {
		log.Printf("err: %v\n", err)
		return 0, errors.New(err.Error())
	}

	if resp.Code != 10000 {
		log.Printf("err: %v\n", resp.Msg)
		return 0, errors.New(resp.Msg)
	}

	return resp.Result, nil
}

func encryptForm() string {
	t, err := getEncryptTime()
	if err != nil {
		panic(err)
	}

	ef, err := json.Marshal(&EncryptForm{
		SourceId:    1003,
		Type:        1,
		EncryptTime: t,
	})
	if err != nil {
		panic(err)
	}

	var encode = RSAEncrypt(ef)

	return base64.StdEncoding.EncodeToString(encode)
}

func signIn() (*SignInResponse, error) {
	var resp SignInResponse
	err := gout.POST("http://caiyun.feixin.10086.cn:7070/portal/ajax/common/caiYunSignIn.action").
		SetHeader(gout.H{
			"Host":             "caiyun.feixin.10086.cn:7070",
			"Accept":           "*/*",
			"X-Requested-With": "XMLHttpRequest",
			"User-Agent":       UA,
			"Content-Type":     "application/x-www-form-urlencoded",
			"Origin":           "http://caiyun.feixin.10086.cn:7070",
			"Referer":          Referer,
			"Accept-Encoding":  "gzip, deflate",
			"Accept-Language":  "zh-CN,zh;q=0.9,en;q=0.8",
			"Cookie":           Cookie,
		}).Debug(true).SetWWWForm(gout.H{
		"op":   "receive",
		"data": encryptForm(),
	}).BindJSON(&resp).Do()
	if err != nil {
		log.Printf("err: %v\n", err)
		return nil, errors.New(err.Error())
	}

	if resp.Code != 10000 {
		log.Printf("err: %v\n", resp.Msg)
		return nil, errors.New(resp.Msg)
	}

	return &resp, err
}

func RSAEncrypt(plainText []byte) []byte {
	var publicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCJ6kiv4v8ZcbDiMmyTKvGzxoPR3fTLj/uRuu6dUypy6zDW+EerThAYON172YigluzKslU1PD9+PzPPHLU/cv81q6KYdT+B5w29hlKkk5tNR0PcCAM/aRUQZu9abnl2aAFQow576BRvIS460urnju+Bu1ZtV+oFM+yQu04OSnmOpwIDAQAB
-----END PUBLIC KEY-----`)
	//对明文进行加密
	cipherText, err := goEncrypt.RsaEncrypt(plainText, publicKey)
	if err != nil {
		panic(err)
	}
	//返回密文
	return cipherText
}

func run() (string, error) {
	fmt.Println(time.Now().String(), " 任务执行开始!")

	var content string
	resp, err := signIn()

	if err != nil {
		log.Printf("签到失败: %v", err)
		content = "今日和彩云签到情况: " + err.Error()
		goto Push
	}

	if resp.Result.TodaySignIn {
		content = fmt.Sprintf("和彩云签到情况: 成功\n月签到天数: %d\n总积分: %d",
			resp.Result.MonthDays, resp.Result.TotalPoints)
	}

Push:
	if err = push(content); err != nil {
		log.Println("签到结果: ", content)
	} else {
		log.Println("ok")
	}

	return time.Now().String() + "任务处理完毕！", nil
}

func main() {
	cloudfunction.Start(run)
}
