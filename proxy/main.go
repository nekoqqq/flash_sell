package main

import (
	"flash_sell"
	"flash_sell/proxy/controller"
	"github.com/astaxie/beego"
	"log"
	"net/http"
)
import _ "net/http/pprof"

func main() {
	err := flash_sell.InitConfig()
	if err != nil {
		panic(err)
	}
	go func() { // profile
		log.Println(http.ListenAndServe(":6060", nil))
	}()
	beego.Router("/flash_sell", &controller.FlashSellController{}, "*:FlashSell") // *表示GET和POST等都支持
	// 秒杀查询
	beego.Router("/info", &controller.FlashSellController{}, "*:FlashSellInfo")
	beego.Run()
}
